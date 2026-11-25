"""Workflow engine: validate definitions, match triggers, gate on approval, run allow-listed steps.

Safety rules (enforced here, tested in tests/test_automation.py):

* Only the triggers and steps in :mod:`app.automation.catalog` exist; definitions are validated on save.
* A workflow with a ``medium`` step always waits for approval by a member with ``responses:approve``.
  The requester of a manual run cannot approve it, unless they are the only approver (recorded).
  Pending approvals expire after APPROVAL_TTL_HOURS.
* Runs act as the workflow owner (or the person who pressed Run). Each step re-checks that member's
  permissions at run time; a removed owner stops the workflow instead of running with stale rights.
* Automation never starts automation: events caused by a running workflow do not trigger workflows,
  so two workflows (or SENTINEL and n8n) cannot loop.
* The SOC emergency stop also stops automation: new runs are skipped, approvals refused and webhook
  deliveries held until it is released.
* Steps run one by one, each in its own savepoint; a failed step is recorded and the next one runs.
* Trigger failures never break the code that raised the event (ingestion, incidents, sweeper).
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta
from typing import Any

from fastapi import Request, status
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.automation import catalog
from app.automation.catalog import EVENTS, SCHEDULES, STEPS, TRIGGER_TYPES
from app.core.config import get_settings
from app.core.errors import AppError, not_found
from app.models import (
    Alert,
    AutomationRun,
    AutomationWorkflow,
    Device,
    Incident,
    Integration,
    Organization,
    OrganizationMember,
    ResponseAction,
    SecurityEvent,
    User,
)
from app.services import audit, realtime
from app.soc.common import aware, members_with, notify, now

log = logging.getLogger("sentinel.automation")
_IN_RUN: ContextVar[bool] = ContextVar("automation_in_run", default=False)
TEMPLATE_RE = re.compile(r"\{\{\s*([a-z_][a-z0-9_]*(?:\.[a-z0-9_]+)*)\s*\}\}", re.IGNORECASE)
MAX_STEPS = 10


class AutomationError(AppError):
    def __init__(self, code: str, message: str, http: int = status.HTTP_422_UNPROCESSABLE_CONTENT):
        super().__init__(http, code, message)


class StepFailed(Exception):
    pass


# ---------------------------------------------------------------------------------- templates
def _lookup(context: dict[str, Any], path: str) -> Any:
    value: Any = context
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def render(template: str, context: dict[str, Any], limit: int = 500) -> str:
    """Replace {{dotted.path}} with values from the trigger context. Unknown fields become empty."""

    def _sub(match: re.Match[str]) -> str:
        value = _lookup(context, match.group(1))
        if value is None or isinstance(value, dict | list):
            return ""
        return " ".join(str(value).split())

    return TEMPLATE_RE.sub(_sub, template).strip()[:limit]


@contextmanager
def _running() -> Iterator[None]:
    token = _IN_RUN.set(True)
    try:
        yield
    finally:
        _IN_RUN.reset(token)


def in_run() -> bool:
    return _IN_RUN.get()


# --------------------------------------------------------------------------------- validation
def _text(value: Any, name: str, *, max_len: int, required: bool = True) -> str | None:
    text = " ".join(str(value or "").split())
    if not text:
        if required:
            raise AutomationError("invalid_step", f"{name} is required")
        return None
    if len(text) > max_len:
        raise AutomationError("invalid_step", f"{name} must be at most {max_len} characters")
    return text


def validate_trigger(trigger_type: str, config: dict[str, Any]) -> dict[str, Any]:
    if trigger_type not in TRIGGER_TYPES:
        raise AutomationError("invalid_trigger", "Unknown trigger type")
    if trigger_type == "event":
        spec = EVENTS.get(str(config.get("event")))
        if spec is None:
            raise AutomationError("invalid_trigger", "Choose what should start the workflow")
        clean: dict[str, Any] = {"event": spec.key}
        if "min_severity" in spec.filters:
            sev = config.get("min_severity") or ("high" if spec.key == "alert.created" else "low")
            if sev not in catalog.SEVERITY_ORDER:
                raise AutomationError("invalid_trigger", "Unknown severity")
            clean["min_severity"] = sev
        if "include_simulated" in spec.filters:
            clean["include_simulated"] = bool(config.get("include_simulated", False))
        return clean
    if trigger_type == "schedule":
        try:
            every = int(config.get("every_minutes") or 0)
        except (TypeError, ValueError):
            every = 0
        if every not in SCHEDULES:
            raise AutomationError("invalid_trigger", "Choose one of the offered schedules")
        return {"every_minutes": every}
    return {}


def validate_steps(
    db: Session, org_id: uuid.UUID, trigger_type: str, trigger: dict[str, Any], steps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not steps:
        raise AutomationError("invalid_step", "Add at least one step")
    if len(steps) > MAX_STEPS:
        raise AutomationError("invalid_step", f"A workflow can have at most {MAX_STEPS} steps")
    event = trigger.get("event")
    clean: list[dict[str, Any]] = []
    for raw in steps:
        spec = STEPS.get(str(raw.get("type")))
        if spec is None:
            raise AutomationError("invalid_step", "This step type is not on the allow-list")
        if spec.triggers and trigger_type not in spec.triggers:
            raise AutomationError("invalid_step", f"“{spec.title}” cannot be used with this trigger")
        if trigger_type == "event" and spec.events and event not in spec.events:
            raise AutomationError("invalid_step", f"“{spec.title}” cannot be used with this event")
        step: dict[str, Any] = {"type": spec.key}
        if spec.key == "notify":
            audience = raw.get("audience") or "responders"
            if audience not in spec.extra["audiences"]:
                raise AutomationError("invalid_step", "Choose who should be notified")
            step["audience"] = audience
            step["message"] = _text(raw.get("message"), "Message", max_len=300)
        elif spec.key == "send_webhook":
            try:
                hook_id = uuid.UUID(str(raw.get("webhook_id")))
            except ValueError:
                raise AutomationError("invalid_step", "Choose a webhook") from None
            hook = db.scalar(
                select(Integration).where(Integration.organization_id == org_id, Integration.id == hook_id)
            )
            if hook is None:
                raise AutomationError("invalid_step", "Choose a webhook")
            step["webhook_id"] = str(hook.id)
        elif spec.key == "create_incident":
            default = "{{alert.title}}" if trigger_type == "event" else "{{payload.title}}"
            step["title"] = _text(raw.get("title") or default, "Incident title", max_len=200)
        elif spec.key == "propose_response":
            action_type = raw.get("action_type")
            if action_type not in spec.extra["action_types"]:
                raise AutomationError(
                    "invalid_step", "Automation may only propose a block or heightened monitoring"
                )
            step["action_type"] = action_type
            if action_type == "block_indicator":
                if trigger_type not in ("webhook", "manual"):
                    raise AutomationError(
                        "invalid_step", "Blocks can be proposed from an incoming webhook or a manual run"
                    )
                if raw.get("indicator_type") not in catalog.INDICATOR_TYPES:
                    raise AutomationError("invalid_step", "Choose what kind of indicator to block")
                step["indicator_type"] = raw["indicator_type"]
                step["value"] = _text(raw.get("value"), "Value to block", max_len=300)
            elif trigger_type != "event":
                raise AutomationError(
                    "invalid_step", "Heightened monitoring needs a device from an alert or offline event"
                )
        clean.append(step)
    return clean


def needs_approval(requires_approval: bool, steps: list[dict[str, Any]]) -> bool:
    return requires_approval or any(STEPS[s["type"]].risk != "low" for s in steps if s.get("type") in STEPS)


def _next_slot(every_minutes: int, after: datetime) -> datetime:
    return after + timedelta(minutes=every_minutes)


def apply_definition(
    db: Session,
    wf: AutomationWorkflow,
    *,
    trigger_type: str,
    trigger_config: dict[str, Any],
    steps: list[dict[str, Any]],
    requires_approval: bool,
) -> None:
    trigger = validate_trigger(trigger_type, trigger_config)
    clean = validate_steps(db, wf.organization_id, trigger_type, trigger, steps)
    schedule_changed = trigger_type == "schedule" and (
        wf.trigger_type != "schedule"
        or (wf.trigger_config or {}).get("every_minutes") != trigger["every_minutes"]
    )
    wf.trigger_type = trigger_type
    wf.trigger_config = trigger
    wf.steps = clean
    wf.requires_approval = needs_approval(requires_approval, clean)
    if trigger_type != "schedule":
        wf.next_run_at = None
    elif schedule_changed or wf.next_run_at is None:
        wf.next_run_at = _next_slot(trigger["every_minutes"], now())


def trigger_label(wf: AutomationWorkflow) -> str:
    cfg = wf.trigger_config or {}
    if wf.trigger_type == "event":
        spec = EVENTS.get(cfg.get("event", ""))
        label = spec.title if spec else "Unknown event"
        if cfg.get("min_severity") and cfg["min_severity"] not in ("info", "low"):
            label += f" ({cfg['min_severity']} or above)"
        return label
    if wf.trigger_type == "schedule":
        return SCHEDULES.get(cfg.get("every_minutes", 0), "On a schedule")
    return TRIGGER_TYPES.get(wf.trigger_type, wf.trigger_type)


def step_title(step: dict[str, Any], hooks: dict[str, str] | None = None) -> str:
    spec = STEPS.get(step.get("type", ""))
    if spec is None:
        return "Unknown step"
    if step["type"] == "notify":
        return f"Notify {step.get('audience', 'responders')}"
    if step["type"] == "send_webhook":
        name = (hooks or {}).get(step.get("webhook_id", ""))
        return f"Send to {name}" if name else "Send to a webhook"
    if step["type"] == "propose_response":
        return (
            "Propose a block"
            if step.get("action_type") == "block_indicator"
            else "Propose heightened monitoring"
        )
    return spec.title


# ----------------------------------------------------------------------------------- contexts
def _link(path: str) -> str:
    return path


def alert_context(db: Session, alert: Alert) -> dict[str, Any]:
    event = db.get(SecurityEvent, alert.event_id) if alert.event_id else None
    device = db.get(Device, event.device_id) if event is not None and event.device_id else None
    return {
        "alert": {
            "id": str(alert.id),
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "rule": alert.detection_rule,
            "created_at": aware(alert.created_at).isoformat() if alert.created_at else None,
            "link": _link("/events"),
        },
        "device": {"id": str(device.id), "name": device.name, "device_type": device.device_type}
        if device
        else None,
        "event": {"category": event.category, "event_type": event.event_type} if event else None,
    }


def incident_context(incident: Incident) -> dict[str, Any]:
    return {
        "incident": {
            "id": str(incident.id),
            "reference": incident.reference,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "link": _link(f"/incidents/{incident.id}"),
        }
    }


def device_context(device: Device) -> dict[str, Any]:
    return {
        "device": {
            "id": str(device.id),
            "name": device.name,
            "device_type": device.device_type,
            "status": device.status,
            "last_seen_at": aware(device.last_seen_at).isoformat() if device.last_seen_at else None,
            "link": _link(f"/devices/{device.id}"),
        }
    }


def action_context(action: ResponseAction) -> dict[str, Any]:
    return {
        "action": {
            "id": str(action.id),
            "title": action.title,
            "impact": action.impact,
            "action_type": action.action_type,
            "status": action.status,
            "link": _link(f"/incidents/{action.incident_id}" if action.incident_id else "/incidents"),
        }
    }


def summary_context(db: Session, org_id: uuid.UUID) -> dict[str, Any]:
    """Real counts (simulator data excluded) for scheduled and manual runs."""
    alerts = dict(
        db.execute(
            select(Alert.severity, func.count())
            .where(
                Alert.organization_id == org_id,
                Alert.status.in_(("open", "acknowledged")),
                Alert.is_simulated.is_(False),
            )
            .group_by(Alert.severity)
        ).all()
    )
    devices = dict(
        db.execute(
            select(Device.status, func.count())
            .where(
                Device.organization_id == org_id,
                Device.enrollment_status == "enrolled",
                Device.is_simulated.is_(False),
            )
            .group_by(Device.status)
        ).all()
    )
    open_incidents = db.scalar(
        select(func.count()).where(
            Incident.organization_id == org_id, Incident.status != "closed", Incident.is_simulated.is_(False)
        )
    )
    pending = db.scalar(
        select(func.count()).where(
            ResponseAction.organization_id == org_id, ResponseAction.status == "pending_approval"
        )
    )
    return {
        "summary": {
            "open_alerts": {s: int(alerts.get(s, 0)) for s in ("critical", "high", "medium", "low", "info")},
            "open_incidents": int(open_incidents or 0),
            "devices": {s: int(devices.get(s, 0)) for s in ("online", "degraded", "offline", "unknown")},
            "pending_approvals": int(pending or 0),
            "simulated_data_excluded": True,
            "generated_at": now().isoformat(),
        }
    }


# ---------------------------------------------------------------------------------------- runs
def _org(db: Session, org_id: uuid.UUID) -> Organization:
    org = db.scalar(select(Organization).where(Organization.id == org_id))
    if org is None:
        raise not_found("Organization")
    return org


def _stopped(org: Organization) -> bool:
    from app.soc.actions import emergency_stop  # local import: soc.actions emits automation events

    return bool(emergency_stop(org)["engaged"])


def run_summary(run: AutomationRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "workflow_id": str(run.workflow_id),
        "workflow_name": run.workflow_name,
        "status": run.status,
        "trigger_label": run.trigger_label,
    }


def _planned(wf: AutomationWorkflow, hooks: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "type": s["type"],
            "title": step_title(s, hooks),
            "risk": STEPS[s["type"]].risk if s["type"] in STEPS else "unknown",
            "status": "waiting",
            "detail": None,
            "link": None,
        }
        for s in wf.steps or []
    ]


def _hook_names(db: Session, org_id: uuid.UUID) -> dict[str, str]:
    return {
        str(i): n
        for i, n in db.execute(
            select(Integration.id, Integration.name).where(Integration.organization_id == org_id)
        ).all()
    }


def start_run(
    db: Session,
    wf: AutomationWorkflow,
    *,
    kind: str,
    label: str,
    context: dict[str, Any],
    requested_by: User | None = None,
    dedupe_key: str | None = None,
    simulated: bool = False,
) -> AutomationRun:
    org = _org(db, wf.organization_id)
    run = AutomationRun(
        id=uuid.uuid4(),
        organization_id=wf.organization_id,
        workflow_id=wf.id,
        workflow_name=wf.name,
        status="awaiting_approval",
        trigger_kind=kind,
        trigger_label=label[:255],
        context={
            **context,
            "organization": {"id": str(org.id), "name": org.name},
            "workflow": {"id": str(wf.id), "name": wf.name},
        },
        steps=_planned(wf, _hook_names(db, wf.organization_id)),
        requested_by=requested_by.id if requested_by else None,
        dedupe_key=dedupe_key,
        is_simulated=simulated,
        created_at=now(),
    )
    db.add(run)
    db.flush()
    wf.last_run_at = run.created_at
    if _stopped(org):
        run.status = "skipped"
        run.error = "Emergency stop is engaged: automation is paused"
        run.finished_at = now()
        for s in run.steps:
            s["status"] = "skipped"
        run.steps = list(run.steps)
    elif needs_approval(wf.requires_approval, wf.steps or []):
        run.expires_at = now() + timedelta(hours=get_settings().approval_ttl_hours)
        notify(
            db,
            wf.organization_id,
            members_with(db, wf.organization_id, "responses:approve"),
            kind="approval",
            title=f"Workflow waiting for approval: {wf.name}",
            body=label,
            link="/automation?tab=activity",
            severity="medium",
            exclude=requested_by.id if requested_by else None,
        )
    else:
        execute(db, run, wf)
    wf.last_status = run.status
    realtime.queue_broadcast(db, wf.organization_id, "automation.run", run_summary(run))
    return run


def _actor(
    db: Session, run: AutomationRun, wf: AutomationWorkflow
) -> tuple[User | None, frozenset[str], str]:
    from app.api.deps import load_permissions  # local import: keeps the engine free of API wiring

    user_id = run.requested_by or wf.created_by
    if user_id is None:
        return None, frozenset(), "the workflow has no owner — open it and save it to take it over"
    member = db.scalar(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == wf.organization_id,
            OrganizationMember.user_id == user_id,
            OrganizationMember.status == "active",
        )
    )
    user = db.get(User, user_id)
    if member is None or user is None or not user.is_active:
        return (
            None,
            frozenset(),
            "the workflow owner is no longer an active member — open and save it to take it over",
        )
    return user, load_permissions(db, member.role_id), user.full_name or user.email


def execute(db: Session, run: AutomationRun, wf: AutomationWorkflow) -> AutomationRun:
    actor, perms, actor_note = _actor(db, run, wf)
    results: list[dict[str, Any]] = []
    with _running():
        for index, step in enumerate(wf.steps or []):
            planned = (run.steps or [])[index] if index < len(run.steps or []) else {}
            result = {
                **planned,
                "type": step.get("type"),
                "status": "succeeded",
                "detail": None,
                "link": None,
            }
            spec = STEPS.get(step.get("type", ""))
            try:
                if spec is None:
                    raise StepFailed("This step type is no longer allowed")
                if spec.permission and (actor is None or spec.permission not in perms):
                    raise StepFailed(
                        f"Cannot run: {actor_note}"
                        if actor is None
                        else f"{actor_note} no longer has the “{spec.permission}” permission"
                    )
                with db.begin_nested():
                    detail, link = _EXECUTORS[spec.key](db, run, wf, step, actor)
                result["detail"], result["link"] = detail, link
            except StepFailed as exc:
                result["status"], result["detail"] = "failed", str(exc)[:500]
            except AppError as exc:
                result["status"], result["detail"] = "failed", exc.message[:500]
            except Exception:
                log.exception("automation step %s failed in run %s", step.get("type"), run.id)
                result["status"], result["detail"] = "failed", "Internal error while running this step"
            results.append(result)
    run.steps = results
    run.status = "succeeded" if all(r["status"] == "succeeded" for r in results) else "failed"
    failed = [r for r in results if r["status"] == "failed"]
    run.error = f"{len(failed)} of {len(results)} step(s) failed" if failed else None
    run.finished_at = now()
    wf.last_status = run.status
    return run


# ------------------------------------------------------------------------------------ executors
def _x_notify(
    db: Session, run: AutomationRun, wf: AutomationWorkflow, step: dict[str, Any], actor: User | None
):
    permission = STEPS["notify"].extra["audiences"][step["audience"]]
    users = members_with(db, run.organization_id, permission)
    message = render(step["message"], run.context, 200) or wf.name
    severity = _lookup(run.context, "alert.severity") or _lookup(run.context, "incident.severity") or "info"
    sent = notify(
        db,
        run.organization_id,
        users,
        kind="automation",
        title=message,
        body=f"Workflow: {wf.name}",
        link=_lookup(run.context, "alert.link")
        or _lookup(run.context, "incident.link")
        or _lookup(run.context, "action.link")
        or "/automation?tab=activity",
        severity=severity if severity in catalog.SEVERITY_ORDER else "info",
    )
    return f"Notified {sent} member(s)", None


def _x_webhook(
    db: Session, run: AutomationRun, wf: AutomationWorkflow, step: dict[str, Any], actor: User | None
):
    from app.automation import delivery

    hook = db.scalar(
        select(Integration).where(
            Integration.organization_id == run.organization_id,
            Integration.id == uuid.UUID(step["webhook_id"]),
        )
    )
    if hook is None:
        raise StepFailed("The webhook was deleted")
    if hook.status != "active":
        raise StepFailed(f"The webhook “{hook.name}” is disabled")
    data = {k: v for k, v in run.context.items() if k not in ("organization", "workflow")}
    item = delivery.enqueue(
        db,
        hook,
        event_type=_lookup(run.context, "trigger.event") or f"workflow.{run.trigger_kind}",
        data=data,
        run=run,
        workflow=wf,
        simulated=run.is_simulated,
    )
    return f"Queued for {hook.name} (delivery {str(item.id)[:8]})", None


def _x_incident(
    db: Session, run: AutomationRun, wf: AutomationWorkflow, step: dict[str, Any], actor: User | None
):
    from app.soc import incidents as incident_service

    assert actor is not None
    title = render(step.get("title") or "", run.context, 200) or f"Opened by workflow {wf.name}"
    alert_ids: list[uuid.UUID] = []
    alert_id = _lookup(run.context, "alert.id")
    if alert_id:
        alert = db.scalar(
            select(Alert).where(Alert.organization_id == run.organization_id, Alert.id == uuid.UUID(alert_id))
        )
        if alert is not None and alert.incident_id is not None:
            existing = db.get(Incident, alert.incident_id)
            ref = existing.reference if existing else "an incident"
            return f"Alert is already part of {ref}", f"/incidents/{alert.incident_id}"
        if alert is not None:
            alert_ids.append(alert.id)
    severity = _lookup(run.context, "payload.severity")
    incident = incident_service.create(
        db,
        None,  # type: ignore[arg-type]
        org_id=run.organization_id,
        user=actor,
        title=title,
        severity=severity if severity in ("low", "medium", "high", "critical") and not alert_ids else None,
        summary_text=f"Opened by the workflow “{wf.name}” (run {str(run.id)[:8]}).",
        alert_ids=alert_ids,
    )
    return f"Opened {incident.reference}", f"/incidents/{incident.id}"


def _x_propose(
    db: Session, run: AutomationRun, wf: AutomationWorkflow, step: dict[str, Any], actor: User | None
):
    from app.soc import actions as action_service

    assert actor is not None
    if step["action_type"] == "block_indicator":
        value = render(step["value"], run.context, 300)
        if not value:
            raise StepFailed("Nothing to block: the value is empty")
        target = {"indicator_type": step["indicator_type"], "value": value}
    else:
        device_id = _lookup(run.context, "device.id")
        if not device_id:
            raise StepFailed("This alert is not linked to a device")
        target = {"device_id": device_id}
    action = action_service.propose(
        db,
        None,  # type: ignore[arg-type]
        org_id=run.organization_id,
        user=actor,
        action_type=step["action_type"],
        target=target,
        reason=f"Proposed by the workflow “{wf.name}” (run {str(run.id)[:8]}).",
        incident_id=None,
        run_id=None,
    )
    state = "waiting for approval" if action.status == "pending_approval" else action.status.replace("_", " ")
    return f"Proposed “{action.title}” — {state}", "/incidents?tab=actions"


def _x_event(
    db: Session, run: AutomationRun, wf: AutomationWorkflow, step: dict[str, Any], actor: User | None
):
    from app.schemas.events import EventIn
    from app.services import events as event_service

    payload = run.context.get("payload") or {}
    try:
        item = EventIn.model_validate(
            {
                "event_type": payload.get("event_type") or "external.alert",
                "category": payload.get("category") or "other",
                "severity": payload.get("severity") or "medium",
                "title": payload.get("title"),
                "description": payload.get("description"),
                "dedup_key": payload.get("id"),
                "raw": {"source_workflow": wf.name},
            }
        )
    except ValidationError as exc:
        first = exc.errors()[0]
        field = ".".join(str(p) for p in first.get("loc", ())) or "body"
        raise StepFailed(f"The webhook body is not a valid event: {field} — {first.get('msg')}") from None
    outcome = event_service.ingest(db, run.organization_id, [item], source="integration")
    if not outcome.event_ids:
        reason = outcome.rejected[0]["reason"] if outcome.rejected else "rejected"
        raise StepFailed(f"Event not recorded: {reason}")
    alerts = len(outcome.alerts)
    return (
        "Recorded the event" + (f" and raised {alerts} alert(s)" if alerts else "")
        if outcome.accepted
        else "Duplicate of a recent event (counted)"
    ), "/events"


_EXECUTORS = {
    "notify": _x_notify,
    "send_webhook": _x_webhook,
    "create_incident": _x_incident,
    "propose_response": _x_propose,
    "create_event": _x_event,
}


# ------------------------------------------------------------------------------------ approvals
def expire_stale(db: Session, org_id: uuid.UUID) -> int:
    stale = db.scalars(
        select(AutomationRun).where(
            AutomationRun.organization_id == org_id,
            AutomationRun.status == "awaiting_approval",
            AutomationRun.expires_at < now(),
        )
    ).all()
    for run in stale:
        run.status = "expired"
        run.finished_at = now()
        run.steps = [{**s, "status": "skipped"} for s in run.steps or []]
        realtime.queue_broadcast(db, org_id, "automation.run", run_summary(run))
    return len(stale)


def decide(
    db: Session,
    request: Request,
    run: AutomationRun,
    *,
    user: User,
    approve: bool,
    comment: str | None,
) -> AutomationRun:
    expire_stale(db, run.organization_id)
    if run.status != "awaiting_approval":
        raise AutomationError(
            "not_pending",
            f"The run is {run.status.replace('_', ' ')}, not waiting for approval",
            status.HTTP_409_CONFLICT,
        )
    wf = db.get(AutomationWorkflow, run.workflow_id)
    if wf is None:
        raise not_found("Workflow")
    org = _org(db, run.organization_id)
    if approve and _stopped(org):
        raise AutomationError(
            "emergency_stop",
            "Emergency stop is engaged — release it before approving automation",
            status.HTTP_409_CONFLICT,
        )
    self_approval = run.requested_by == user.id
    sole = len(members_with(db, run.organization_id, "responses:approve")) <= 1
    if approve and self_approval and not sole:
        raise AutomationError(
            "separation_of_duties", "Someone else must approve a run you started", status.HTTP_403_FORBIDDEN
        )
    run.decided_by = user.id
    run.decided_at = now()
    note = (comment or "").strip()
    if approve and self_approval:
        note = (note + " [self-approved: only approver in this organization]").strip()
    run.decision_comment = note or None
    audit.record(
        db,
        "automation.run_approve" if approve else "automation.run_reject",
        request=request,
        actor_id=user.id,
        org_id=run.organization_id,
        target_type="automation_run",
        target_id=run.id,
        details={"workflow": wf.name, "self_approved": approve and self_approval, "comment": comment},
    )
    if approve:
        execute(db, run, wf)
    else:
        run.status = "rejected"
        run.finished_at = now()
        run.steps = [{**s, "status": "skipped"} for s in run.steps or []]
        wf.last_status = "rejected"
    realtime.queue_broadcast(db, run.organization_id, "automation.run", run_summary(run))
    return run


# ------------------------------------------------------------------------------------- triggers
def emit(
    db: Session,
    org_id: uuid.UUID,
    event: str,
    context: dict[str, Any],
    *,
    severity: str | None = None,
    simulated: bool = False,
    label: str | None = None,
) -> int:
    """Start every enabled workflow listening for ``event``. Never raises into the caller."""
    if in_run():
        return 0
    started = 0
    try:
        workflows = db.scalars(
            select(AutomationWorkflow).where(
                AutomationWorkflow.organization_id == org_id,
                AutomationWorkflow.enabled.is_(True),
                AutomationWorkflow.trigger_type == "event",
            )
        ).all()
        for wf in workflows:
            cfg = wf.trigger_config or {}
            if cfg.get("event") != event:
                continue
            if severity is not None and not catalog.severity_at_least(severity, cfg.get("min_severity")):
                continue
            if simulated and not cfg.get("include_simulated", False):
                continue
            try:
                with db.begin_nested():
                    start_run(
                        db,
                        wf,
                        kind="event",
                        label=label or EVENTS[event].title,
                        context={**context, "trigger": {"event": event}},
                        simulated=simulated,
                    )
                started += 1
            except Exception:
                log.exception("automation trigger failed for workflow %s", wf.id)
    except Exception:  # pragma: no cover - defensive
        log.exception("automation emit failed for %s", event)
    return started


def on_alerts(db: Session, org_id: uuid.UUID, alerts: list[Alert]) -> None:
    for alert in alerts:
        emit(
            db,
            org_id,
            "alert.created",
            alert_context(db, alert),
            severity=alert.severity,
            simulated=alert.is_simulated,
            label=f"{alert.severity.capitalize()} alert: {alert.title}",
        )


def on_incident(db: Session, incident: Incident) -> None:
    emit(
        db,
        incident.organization_id,
        "incident.created",
        incident_context(incident),
        severity=incident.severity,
        simulated=incident.is_simulated,
        label=f"Incident {incident.reference}: {incident.title}",
    )


def on_device_offline(db: Session, device: Device) -> None:
    emit(
        db,
        device.organization_id,
        "device.offline",
        device_context(device),
        simulated=device.is_simulated,
        label=f"{device.name} stopped reporting",
    )


def on_pending_approval(db: Session, action: ResponseAction) -> None:
    emit(
        db,
        action.organization_id,
        "action.pending_approval",
        action_context(action),
        label=f"Approval needed: {action.title}",
    )


def run_manual(db: Session, wf: AutomationWorkflow, user: User) -> AutomationRun:
    if wf.trigger_type not in ("manual", "schedule"):
        raise AutomationError(
            "not_manual",
            "Only manual and scheduled workflows can be started with Run",
            status.HTTP_409_CONFLICT,
        )
    if wf.trigger_type == "manual" and not wf.enabled:
        raise AutomationError("disabled", "Turn the workflow on first", status.HTTP_409_CONFLICT)
    return start_run(
        db,
        wf,
        kind="manual",
        label=f"Run by {user.full_name or user.email}",
        context={**summary_context(db, wf.organization_id), "trigger": {"event": "workflow.manual"}},
        requested_by=user,
    )


def run_due_schedules(db: Session, org_id: uuid.UUID, at: datetime | None = None) -> int:
    at = at or now()
    q = select(AutomationWorkflow).where(
        AutomationWorkflow.organization_id == org_id,
        AutomationWorkflow.enabled.is_(True),
        AutomationWorkflow.trigger_type == "schedule",
        AutomationWorkflow.next_run_at <= at,
    )
    if db.get_bind().dialect.name == "postgresql":
        q = q.with_for_update(skip_locked=True)
    started = 0
    for wf in db.scalars(q).all():
        every = int((wf.trigger_config or {}).get("every_minutes") or 1440)
        slot = aware(wf.next_run_at) or at
        # Catch up at most once after downtime, then continue on the regular rhythm.
        nxt = slot + timedelta(minutes=every)
        while nxt <= at:
            nxt += timedelta(minutes=every)
        wf.next_run_at = nxt
        try:
            with db.begin_nested():
                start_run(
                    db,
                    wf,
                    kind="schedule",
                    label=SCHEDULES.get(every, "Scheduled run"),
                    context={**summary_context(db, org_id), "trigger": {"event": "workflow.schedule"}},
                    dedupe_key=f"schedule:{slot.isoformat()}",
                )
            started += 1
        except IntegrityError:
            pass  # another instance already ran this slot
    return started


def receive_hook(
    db: Session, wf: AutomationWorkflow, payload: dict[str, Any], *, dedupe_key: str
) -> AutomationRun:
    try:
        with db.begin_nested():
            return start_run(
                db,
                wf,
                kind="webhook",
                label="Incoming webhook",
                context={"payload": payload, "trigger": {"event": "workflow.webhook"}},
                dedupe_key=dedupe_key,
            )
    except IntegrityError:
        raise AutomationError(
            "replayed", "This signed request was already received", status.HTTP_409_CONFLICT
        ) from None
