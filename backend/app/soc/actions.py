"""Controlled response actions: allow-listed, approval-gated, audited, reversible where possible.

Rules (enforced here, tested in tests/test_soc.py):

* Only the action types in :data:`ACTIONS` exist. Each has a fixed impact level and an executor
  that changes nothing outside this platform: no shell, no network calls, no third-party systems.
* ``low`` impact runs when proposed. ``medium`` and ``high`` wait for an explicit approval by a
  member with ``responses:approve``; pending approvals expire.
* ``high`` impact needs a *different* approver than the requester (separation of duties). The only
  exception is an organization with a single approver; that approval is recorded as self-approved.
* The organization-wide **emergency stop** holds every execution until it is released.
* Every proposal, decision, execution and rollback is audited and added to the incident timeline.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, not_found
from app.intel.addresses import classify
from app.models import (
    Approval,
    Device,
    Incident,
    Organization,
    OrganizationMember,
    ResponseAction,
    Role,
    ThreatIndicator,
    User,
)
from app.schemas.devices import AgentConfig
from app.services import audit, realtime
from app.services import devices as device_service
from app.soc import incidents as incident_service
from app.soc.common import actor, aware, members_with, notify, now


class ActionError(AppError):
    def __init__(self, code: str, message: str, http: int = status.HTTP_422_UNPROCESSABLE_CONTENT):
        super().__init__(http, code, message)


@dataclass(frozen=True)
class ActionSpec:
    key: str
    title: str
    impact: str  # low | medium | high
    reversible: bool
    description: str
    target_fields: tuple[str, ...]
    validate: Callable[[Session, uuid.UUID, dict[str, Any], User], tuple[dict[str, Any], str]]
    execute: Callable[[Session, Request | None, ResponseAction, User], tuple[dict[str, Any], dict[str, Any]]]
    rollback: Callable[[Session, Request | None, ResponseAction, User], dict[str, Any]] | None = None


# ----------------------------------------------------------------------------------- targets
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}


def _device(db: Session, org_id: uuid.UUID, target: dict[str, Any]) -> Device:
    try:
        device_id = uuid.UUID(str(target.get("device_id")))
    except ValueError:
        raise ActionError("invalid_target", "device_id must be a device of this organization") from None
    device = db.scalar(select(Device).where(Device.id == device_id, Device.organization_id == org_id))
    if device is None:
        raise not_found("Device")
    if device.enrollment_status != "enrolled":
        raise ActionError("invalid_target", f"{device.name} is not enrolled")
    return device


def _indicator(target: dict[str, Any]) -> tuple[str, str]:
    kind = str(target.get("indicator_type", "")).lower()
    value = str(target.get("value", "")).strip().lower()
    ok = False
    if kind in ("ipv4", "ipv6"):
        try:
            ip = ipaddress.ip_address(value)
            # Your own private, loopback or link-local ranges are never blocked by mistake.
            ok = (
                (ip.version == 4) == (kind == "ipv4")
                and not ip.is_unspecified
                and classify(ip) in ("public", "reserved")
            )
        except ValueError:
            ok = False
    elif kind == "domain":
        ok = bool(DOMAIN_RE.match(value))
    elif kind == "url":
        ok = value.startswith(("http://", "https://")) and 8 < len(value) <= 2048
    elif kind == "email":
        ok = bool(re.fullmatch(r"[^@\s]{1,64}@[^@\s]{3,253}", value))
    elif kind in HASH_LEN:
        ok = bool(re.fullmatch(rf"[0-9a-f]{{{HASH_LEN[kind]}}}", value))
    if not ok:
        raise ActionError(
            "invalid_target", "Give a valid public IP, domain, URL, email address or file hash to block"
        )
    return kind, value


def _member(db: Session, org_id: uuid.UUID, target: dict[str, Any]) -> tuple[OrganizationMember, Role, User]:
    try:
        user_id = uuid.UUID(str(target.get("user_id")))
    except ValueError:
        raise ActionError("invalid_target", "user_id must be a member of this organization") from None
    row = db.execute(
        select(OrganizationMember, Role, User)
        .join(Role, Role.id == OrganizationMember.role_id)
        .join(User, User.id == OrganizationMember.user_id)
        .where(OrganizationMember.organization_id == org_id, OrganizationMember.user_id == user_id)
    ).first()
    if row is None:
        raise not_found("Member")
    return row[0], row[1], row[2]


def _rank(db: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> int:
    rank = db.scalar(
        select(Role.rank)
        .join(OrganizationMember, OrganizationMember.role_id == Role.id)
        .where(OrganizationMember.organization_id == org_id, OrganizationMember.user_id == user_id)
    )
    return int(rank or 0)


# -------------------------------------------------------------------------------- executors
def _v_notify(
    db: Session, org_id: uuid.UUID, target: dict[str, Any], user: User
) -> tuple[dict[str, Any], str]:
    message = " ".join(str(target.get("message", "")).split())[:300]
    if len(message) < 3:
        raise ActionError("invalid_target", "Write the message to send to responders")
    return {"message": message}, "Notify responders"


def _x_notify(
    db: Session, request: Request | None, a: ResponseAction, user: User
) -> tuple[dict[str, Any], dict[str, Any]]:
    recipients = members_with(db, a.organization_id, "alerts:manage")
    sent = notify(
        db,
        a.organization_id,
        recipients,
        kind="response",
        title=f"Response team: {a.target['message']}"[:200],
        link=f"/incidents/{a.incident_id}" if a.incident_id else "/incidents",
        severity="high",
    )
    return {"notified": sent}, {}


def _v_monitor(
    db: Session, org_id: uuid.UUID, target: dict[str, Any], user: User
) -> tuple[dict[str, Any], str]:
    device = _device(db, org_id, target)
    return {"device_id": str(device.id), "device_name": device.name}, f"Heighten monitoring on {device.name}"


def _x_monitor(
    db: Session, request: Request | None, a: ResponseAction, user: User
) -> tuple[dict[str, Any], dict[str, Any]]:
    device = _device(db, a.organization_id, a.target)
    previous = dict(device.config or {})
    config = AgentConfig.model_validate(previous or {}).model_copy(
        update={"heartbeat_interval_seconds": 15, "collectors": ["network", "ports", "system"]}
    )
    device_service.update_device(db, request, device, actor_id=user.id, name=None, config=config)  # type: ignore[arg-type]
    return {"heartbeat_interval_seconds": 15, "config_version": device.config_version}, {
        "previous_config": previous
    }


def _r_monitor(db: Session, request: Request | None, a: ResponseAction, user: User) -> dict[str, Any]:
    device = _device(db, a.organization_id, a.target)
    previous = AgentConfig.model_validate(a.rollback_plan.get("previous_config") or {})
    device_service.update_device(db, request, device, actor_id=user.id, name=None, config=previous)  # type: ignore[arg-type]
    return {"restored_config_version": device.config_version}


def _v_block(
    db: Session, org_id: uuid.UUID, target: dict[str, Any], user: User
) -> tuple[dict[str, Any], str]:
    kind, value = _indicator(target)
    return {"indicator_type": kind, "value": value}, f"Block {kind} {value}"


def _x_block(
    db: Session, request: Request | None, a: ResponseAction, user: User
) -> tuple[dict[str, Any], dict[str, Any]]:
    kind, value = a.target["indicator_type"], a.target["value"]
    row = db.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.organization_id == a.organization_id,
            ThreatIndicator.indicator_type == kind,
            ThreatIndicator.value == value,
        )
    )
    plan: dict[str, Any]
    if row is None:
        row = ThreatIndicator(
            id=uuid.uuid4(),
            organization_id=a.organization_id,
            indicator_type=kind,
            value=value,
            source="response",
            confidence=100,
            is_verified=True,
            context={},
        )
        db.add(row)
        plan = {"created_indicator_id": str(row.id)}
    else:
        plan = {
            "indicator_id": str(row.id),
            "previous": {
                "verdict": row.verdict,
                "confidence": row.confidence,
                "blocked": (row.context or {}).get("blocked"),
            },
        }
    row.verdict = "malicious"
    row.confidence = 100
    row.last_seen_at = now()
    row.context = {**(row.context or {}), "blocked": {"action_id": str(a.id), "at": now().isoformat()}}
    db.flush()
    return {"indicator_id": str(row.id), "blocklist": True}, plan


def _r_block(db: Session, request: Request | None, a: ResponseAction, user: User) -> dict[str, Any]:
    plan = a.rollback_plan
    if plan.get("created_indicator_id"):
        row = db.scalar(
            select(ThreatIndicator).where(
                ThreatIndicator.organization_id == a.organization_id,
                ThreatIndicator.id == uuid.UUID(plan["created_indicator_id"]),
            )
        )
        if row is not None:
            db.delete(row)
        return {"removed_indicator": plan["created_indicator_id"]}
    row = db.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.organization_id == a.organization_id,
            ThreatIndicator.id == uuid.UUID(plan["indicator_id"]),
        )
    )
    if row is None:
        return {"note": "indicator no longer exists"}
    previous = plan["previous"]
    row.verdict = previous["verdict"]
    row.confidence = previous["confidence"]
    context = {k: v for k, v in (row.context or {}).items() if k != "blocked"}
    if previous.get("blocked"):
        context["blocked"] = previous["blocked"]
    row.context = context
    return {"restored_verdict": previous["verdict"]}


def _v_revoke(
    db: Session, org_id: uuid.UUID, target: dict[str, Any], user: User
) -> tuple[dict[str, Any], str]:
    device = _device(db, org_id, target)
    return {"device_id": str(device.id), "device_name": device.name}, f"Revoke device {device.name}"


def _x_revoke(
    db: Session, request: Request | None, a: ResponseAction, user: User
) -> tuple[dict[str, Any], dict[str, Any]]:
    device = _device(db, a.organization_id, a.target)
    device_service.decommission(db, request, device, actor_id=user.id, reason=f"response action {a.id}")  # type: ignore[arg-type]
    return {"device_status": device.status}, {"note": "Not reversible: re-enroll the device with a new token"}


def _v_suspend(
    db: Session, org_id: uuid.UUID, target: dict[str, Any], user: User
) -> tuple[dict[str, Any], str]:
    member, role, target_user = _member(db, org_id, target)
    if target_user.id == user.id:
        raise ActionError("invalid_target", "You cannot suspend yourself")
    if member.status != "active":
        raise ActionError("invalid_target", f"{target_user.full_name} is not active")
    if role.rank > _rank(db, org_id, user.id):
        raise ActionError("invalid_target", "You cannot suspend a member with a higher role than yours", 403)
    if role.key == "owner":
        owners = db.scalar(
            select(OrganizationMember.id)
            .join(Role, Role.id == OrganizationMember.role_id)
            .where(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.status == "active",
                Role.key == "owner",
                OrganizationMember.user_id != target_user.id,
            )
            .limit(1)
        )
        if owners is None:
            raise ActionError("invalid_target", "The last active owner cannot be suspended")
    return {"user_id": str(target_user.id), "name": target_user.full_name}, f"Suspend {target_user.full_name}"


def _x_suspend(
    db: Session, request: Request | None, a: ResponseAction, user: User
) -> tuple[dict[str, Any], dict[str, Any]]:
    _v_suspend(db, a.organization_id, a.target, user)  # re-check guards at execution time
    member, _, _ = _member(db, a.organization_id, a.target)
    member.status = "suspended"
    return {"membership": "suspended"}, {"restore_status": "active"}


def _r_suspend(db: Session, request: Request | None, a: ResponseAction, user: User) -> dict[str, Any]:
    member, _, _ = _member(db, a.organization_id, a.target)
    member.status = "active"
    return {"membership": "active"}


ACTIONS: dict[str, ActionSpec] = {
    spec.key: spec
    for spec in (
        ActionSpec(
            "notify_team",
            "Notify responders",
            "low",
            False,
            "Sends an in-app notification to every member who can manage alerts.",
            ("message",),
            _v_notify,
            _x_notify,
        ),
        ActionSpec(
            "heighten_monitoring",
            "Heighten monitoring",
            "medium",
            True,
            "Sets the device agent to report every 15 seconds with all collectors on. Rollback restores the "
            "previous configuration.",
            ("device_id",),
            _v_monitor,
            _x_monitor,
            _r_monitor,
        ),
        ActionSpec(
            "block_indicator",
            "Add to block list",
            "medium",
            True,
            "Marks an IP, domain, URL, email or hash as malicious on your watchlist and adds it to the block-list "
            "export for your firewall or DNS filter. Rollback restores the previous verdict.",
            ("indicator_type", "value"),
            _v_block,
            _x_block,
            _r_block,
        ),
        ActionSpec(
            "revoke_device",
            "Revoke device",
            "high",
            False,
            "Revokes the device credential immediately: its agent is disconnected and can no longer report. "
            "Not reversible — the device must be re-enrolled.",
            ("device_id",),
            _v_revoke,
            _x_revoke,
        ),
        ActionSpec(
            "suspend_member",
            "Suspend member",
            "high",
            True,
            "Suspends a member's access to this organization (e.g. a compromised account). Rollback "
            "reactivates the membership.",
            ("user_id",),
            _v_suspend,
            _x_suspend,
            _r_suspend,
        ),
    )
}


# ----------------------------------------------------------------------------- emergency stop
def emergency_stop(org: Organization) -> dict[str, Any]:
    state = (org.settings or {}).get("emergency_stop") or {}
    return {
        "engaged": bool(state.get("engaged")),
        **{k: state.get(k) for k in ("reason", "at", "actor", "actor_id")},
    }


def set_emergency_stop(
    db: Session, request: Request, org: Organization, *, user: User, engaged: bool, reason: str | None
) -> dict[str, Any]:
    if emergency_stop(org)["engaged"] == engaged:
        return emergency_stop(org)
    org.settings = {
        **(org.settings or {}),
        "emergency_stop": {"engaged": engaged, "reason": reason, "at": now().isoformat(), **actor(user)},
    }
    audit.record(
        db,
        "response.emergency_stop",
        request=request,
        actor_id=user.id,
        org_id=org.id,
        target_type="organization",
        target_id=org.id,
        details={"engaged": engaged, "reason": reason},
    )
    notify(
        db,
        org.id,
        members_with(db, org.id, "responses:propose"),
        kind="response",
        title="Emergency stop engaged — all response actions are on hold"
        if engaged
        else "Emergency stop released",
        body=reason,
        link="/incidents",
        severity="critical" if engaged else "info",
        exclude=user.id,
    )
    realtime.queue_broadcast(db, org.id, "response.emergency_stop", {"engaged": engaged})
    return emergency_stop(org)


# ------------------------------------------------------------------------------------ lifecycle
def _org(db: Session, org_id: uuid.UUID) -> Organization:
    org = db.get(Organization, org_id)
    assert org is not None
    return org


def _summary(a: ResponseAction) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "status": a.status,
        "action_type": a.action_type,
        "title": a.title,
        "incident_id": str(a.incident_id) if a.incident_id else None,
    }


def _log(db: Session, a: ResponseAction, user: User | None, text: str) -> None:
    if a.incident_id is None:
        return
    incident = db.scalar(
        select(Incident).where(Incident.id == a.incident_id, Incident.organization_id == a.organization_id)
    )
    if incident is not None:
        incident_service.append(incident, incident_service.entry("action", text, user, action_id=str(a.id)))


def _pending_approval(db: Session, a: ResponseAction) -> Approval | None:
    return db.scalar(
        select(Approval).where(
            Approval.response_action_id == a.id,
            Approval.organization_id == a.organization_id,
            Approval.status == "pending",
        )
    )


def get(db: Session, org_id: uuid.UUID, action_id: uuid.UUID) -> ResponseAction:
    a = db.scalar(
        select(ResponseAction).where(ResponseAction.id == action_id, ResponseAction.organization_id == org_id)
    )
    if a is None:
        raise not_found("Response action")
    return a


def expire_stale(db: Session, org_id: uuid.UUID) -> int:
    """Pending approvals past their deadline expire; their actions are cancelled (lazy, on read)."""
    stale = db.scalars(
        select(Approval).where(
            Approval.organization_id == org_id, Approval.status == "pending", Approval.expires_at < now()
        )
    ).all()
    for approval in stale:
        approval.status = "expired"
        approval.decided_at = now()
        action = db.get(ResponseAction, approval.response_action_id)
        if action is not None and action.status == "pending_approval":
            action.status = "cancelled"
            action.result = {**(action.result or {}), "cancelled": "approval expired"}
            _log(db, action, None, f"Approval expired: {action.title}")
    return len(stale)


def propose(
    db: Session,
    request: Request,
    *,
    org_id: uuid.UUID,
    user: User,
    action_type: str,
    target: dict[str, Any],
    reason: str | None,
    incident_id: uuid.UUID | None,
    run_id: uuid.UUID | None,
) -> ResponseAction:
    spec = ACTIONS.get(action_type)
    if spec is None:
        raise ActionError("unknown_action", "This action type is not on the allow-list")
    if incident_id is not None:
        incident = incident_service.get(db, org_id, incident_id)
        if incident.status == "closed":
            raise ActionError("incident_closed", "The incident is closed", status.HTTP_409_CONFLICT)
    clean_target, title = spec.validate(db, org_id, target, user)
    needs_approval = spec.impact != "low"
    a = ResponseAction(
        id=uuid.uuid4(),
        organization_id=org_id,
        incident_id=incident_id,
        proposed_by_run_id=run_id,
        action_type=action_type,
        title=title[:255],
        reason=reason,
        reversible=spec.reversible,
        target=clean_target,
        impact=spec.impact,
        requires_approval=needs_approval,
        status="pending_approval" if needs_approval else "approved",
        requested_by=user.id,
        result={},
        rollback_plan={},
    )
    db.add(a)
    db.flush()
    _log(db, a, user, f"Proposed: {a.title} ({spec.impact} impact)")
    audit.record(
        db,
        "response.propose",
        request=request,
        actor_id=user.id,
        org_id=org_id,
        target_type="response_action",
        target_id=a.id,
        details={"action_type": action_type, "target": clean_target, "impact": spec.impact},
    )
    if needs_approval:
        db.add(
            Approval(
                id=uuid.uuid4(),
                organization_id=org_id,
                response_action_id=a.id,
                status="pending",
                requested_by=user.id,
                expires_at=now() + timedelta(hours=get_settings().approval_ttl_hours),
            )
        )
        notify(
            db,
            org_id,
            members_with(db, org_id, "responses:approve"),
            kind="approval",
            title=f"Approval needed ({spec.impact} impact): {a.title}",
            body=reason,
            link=f"/incidents/{incident_id}" if incident_id else "/incidents",
            severity="high",
            exclude=user.id,
        )
    else:
        execute(db, request, a, user=user)
    realtime.queue_broadcast(db, org_id, "action.updated", _summary(a))
    return a


def decide(
    db: Session, request: Request, a: ResponseAction, *, user: User, approve: bool, comment: str | None
) -> ResponseAction:
    expire_stale(db, a.organization_id)
    if a.status != "pending_approval":
        raise ActionError(
            "not_pending",
            f"The action is {a.status.replace('_', ' ')}, not waiting for approval",
            status.HTTP_409_CONFLICT,
        )
    approval = _pending_approval(db, a)
    assert approval is not None
    self_approved = user.id == a.requested_by
    # Separation of duties: a high-impact action needs a second person, unless nobody else can approve.
    sole_approver = len(members_with(db, a.organization_id, "responses:approve")) <= 1
    if approve and a.impact == "high" and self_approved and not sole_approver:
        raise ActionError(
            "separation_of_duties",
            "High-impact actions must be approved by someone other than the requester",
            status.HTTP_403_FORBIDDEN,
        )
    approval.status = "approved" if approve else "rejected"
    approval.decided_by = user.id
    approval.decided_at = now()
    approval.comment = (comment or "") + (
        " [self-approved: only approver in this organization]"
        if approve and self_approved and a.impact == "high"
        else ""
    )
    approval.comment = approval.comment.strip() or None
    a.status = "approved" if approve else "rejected"
    _log(
        db,
        a,
        user,
        f"{'Approved' if approve else 'Rejected'}: {a.title}" + (f" — {comment}" if comment else ""),
    )
    audit.record(
        db,
        "response.approve" if approve else "response.reject",
        request=request,
        actor_id=user.id,
        org_id=a.organization_id,
        target_type="response_action",
        target_id=a.id,
        details={
            "action_type": a.action_type,
            "self_approved": approve and self_approved,
            "comment": comment,
        },
    )
    if a.requested_by and a.requested_by != user.id:
        notify(
            db,
            a.organization_id,
            [a.requested_by],
            kind="approval",
            title=f"{'Approved' if approve else 'Rejected'}: {a.title}",
            body=comment,
            link=f"/incidents/{a.incident_id}" if a.incident_id else "/incidents",
        )
    if approve:
        execute(db, request, a, user=user)
    realtime.queue_broadcast(db, a.organization_id, "action.updated", _summary(a))
    return a


def execute(db: Session, request: Request | None, a: ResponseAction, *, user: User) -> ResponseAction:
    if a.status != "approved":
        raise ActionError("not_approved", "Only approved actions can run", status.HTTP_409_CONFLICT)
    stop = emergency_stop(_org(db, a.organization_id))
    if stop["engaged"]:
        a.result = {
            **(a.result or {}),
            "held": "Emergency stop is engaged — run it after the stop is released",
        }
        _log(db, a, user, f"Held by emergency stop: {a.title}")
        return a
    spec = ACTIONS[a.action_type]
    a.status = "executing"
    try:
        with db.begin_nested():
            result, plan = spec.execute(db, request, a, user)
    except AppError as exc:
        a.status = "failed"
        a.result = {"error": exc.message}
        _log(db, a, user, f"Failed: {a.title} — {exc.message}")
        audit.record(
            db,
            "response.execute",
            request=request,
            actor_id=user.id,
            org_id=a.organization_id,
            target_type="response_action",
            target_id=a.id,
            outcome="failure",
            details={"error": exc.message},
        )
        return a
    a.status = "succeeded"
    a.result = {k: v for k, v in result.items()} | {"executed_by": str(user.id)}
    a.rollback_plan = plan
    a.executed_at = now()
    _log(db, a, user, f"Executed: {a.title}")
    audit.record(
        db,
        "response.execute",
        request=request,
        actor_id=user.id,
        org_id=a.organization_id,
        target_type="response_action",
        target_id=a.id,
        details={"action_type": a.action_type, "result": result},
    )
    return a


def run(db: Session, request: Request, a: ResponseAction, *, user: User) -> ResponseAction:
    """Run an approved action that was held (e.g. by the emergency stop)."""
    execute(db, request, a, user=user)
    realtime.queue_broadcast(db, a.organization_id, "action.updated", _summary(a))
    return a


def rollback(db: Session, request: Request, a: ResponseAction, *, user: User) -> ResponseAction:
    spec = ACTIONS[a.action_type]
    if a.status != "succeeded":
        raise ActionError(
            "not_executed", "Only actions that ran successfully can be rolled back", status.HTTP_409_CONFLICT
        )
    if spec.rollback is None:
        raise ActionError(
            "not_reversible", f"'{spec.title}' cannot be rolled back automatically", status.HTTP_409_CONFLICT
        )
    if emergency_stop(_org(db, a.organization_id))["engaged"]:
        raise ActionError("emergency_stop", "The emergency stop is engaged", status.HTTP_409_CONFLICT)
    with db.begin_nested():
        outcome = spec.rollback(db, request, a, user)
    a.status = "rolled_back"
    a.rolled_back_at = now()
    a.result = {**(a.result or {}), "rollback": outcome}
    _log(db, a, user, f"Rolled back: {a.title}")
    audit.record(
        db,
        "response.rollback",
        request=request,
        actor_id=user.id,
        org_id=a.organization_id,
        target_type="response_action",
        target_id=a.id,
        details={"action_type": a.action_type, "outcome": outcome},
    )
    realtime.queue_broadcast(db, a.organization_id, "action.updated", _summary(a))
    return a


def cancel(
    db: Session, request: Request, a: ResponseAction, *, user: User, can_approve: bool
) -> ResponseAction:
    if a.status not in ("pending_approval", "approved"):
        raise ActionError(
            "not_cancellable", f"The action is already {a.status.replace('_', ' ')}", status.HTTP_409_CONFLICT
        )
    if user.id != a.requested_by and not can_approve:
        raise ActionError(
            "forbidden", "Only the requester or an approver can cancel", status.HTTP_403_FORBIDDEN
        )
    approval = _pending_approval(db, a)
    if approval is not None:
        approval.status = "rejected"
        approval.decided_by = user.id
        approval.decided_at = now()
        approval.comment = "cancelled"
    a.status = "cancelled"
    _log(db, a, user, f"Cancelled: {a.title}")
    audit.record(
        db,
        "response.cancel",
        request=request,
        actor_id=user.id,
        org_id=a.organization_id,
        target_type="response_action",
        target_id=a.id,
    )
    realtime.queue_broadcast(db, a.organization_id, "action.updated", _summary(a))
    return a


def is_overdue(approval: Approval) -> bool:
    expires = aware(approval.expires_at)
    return bool(expires and expires < now())
