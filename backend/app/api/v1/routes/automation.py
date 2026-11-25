"""Automation API (Phase 8): workflows, approval-gated runs, signed webhooks in and out.

Permissions: ``automation:read`` to view, ``integrations:manage`` to configure and run,
``responses:approve`` to approve or reject runs. Incoming hooks are authenticated by signature only.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select

from app.api.deps import DB, OrgContext, require
from app.automation import catalog, delivery, engine, signing, targets
from app.core import limits
from app.core.config import get_settings
from app.core.errors import AppError, not_found
from app.core.rate_limit import enforce
from app.db.session import set_tenant_context
from app.models import AutomationRun, AutomationWorkflow, Integration, User, WebhookDelivery
from app.schemas.automation import (
    AutomationOverview,
    DeliveryOut,
    HookAccepted,
    RunDecision,
    RunOut,
    StepOut,
    WebhookCreate,
    WebhookOut,
    WebhookSecret,
    WebhookUpdate,
    WorkflowIn,
    WorkflowOut,
    WorkflowSecret,
    WorkflowUpdate,
)
from app.schemas.common import Page
from app.services import audit
from app.soc.common import now

router = APIRouter(prefix="/organizations/{org_id}/automation", tags=["automation"])
hooks_router = APIRouter(prefix="/hooks", tags=["automation"])

Read = Annotated[OrgContext, Depends(require("automation:read"))]
Manage = Annotated[OrgContext, Depends(require("integrations:manage"))]
Approve = Annotated[OrgContext, Depends(require("responses:approve"))]


def _names(db: DB, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return {u.id: u.full_name or u.email for u in db.scalars(select(User).where(User.id.in_(wanted)))}


def _hook_path(org_id: uuid.UUID, wf_id: uuid.UUID) -> str:
    return f"{get_settings().api_prefix}/hooks/{org_id}/{wf_id}"


# ------------------------------------------------------------------------------------ outputs
def _masked(url: str) -> str:
    """Webhook URLs often carry a token in the path (Slack, n8n): only managers see it in full."""
    try:
        scheme, host, _port = targets.parse(url)
    except targets.TargetRefused:
        return "…"
    return f"{scheme}://{targets.display_host(url) or host}/…"


def _webhook_out(hook: Integration, used_by: int, *, full_url: bool) -> WebhookOut:
    url = (hook.config or {}).get("url", "")
    return WebhookOut(
        id=hook.id,
        name=hook.name,
        provider=hook.provider,
        url=url if full_url else _masked(url),
        host=targets.display_host(url),
        description=(hook.config or {}).get("description"),
        enabled=hook.status == "active",
        failure_count=hook.failure_count or 0,
        last_error=hook.last_error,
        last_success_at=hook.last_sync_at,
        created_at=hook.created_at,
        used_by=used_by,
    )


def _usage(db: DB, org_id: uuid.UUID) -> dict[str, int]:
    counts: dict[str, int] = {}
    for steps in db.scalars(
        select(AutomationWorkflow.steps).where(AutomationWorkflow.organization_id == org_id)
    ):
        for hook_id in {s.get("webhook_id") for s in steps or [] if s.get("type") == "send_webhook"}:
            counts[hook_id] = counts.get(hook_id, 0) + 1
    return counts


def _hooks_by_id(db: DB, org_id: uuid.UUID) -> dict[str, str]:
    return {
        str(i): n
        for i, n in db.execute(
            select(Integration.id, Integration.name).where(Integration.organization_id == org_id)
        ).all()
    }


def _workflow_out(
    db: DB, wf: AutomationWorkflow, hooks: dict[str, str], names: dict[uuid.UUID, str]
) -> WorkflowOut:
    forced = any(
        catalog.STEPS[s["type"]].risk != "low" for s in wf.steps or [] if s.get("type") in catalog.STEPS
    )
    return WorkflowOut(
        id=wf.id,
        name=wf.name,
        description=wf.description,
        trigger_type=wf.trigger_type,
        trigger_config=wf.trigger_config or {},
        trigger_label=engine.trigger_label(wf),
        steps=[
            StepOut(
                type=s.get("type", ""),
                title=engine.step_title(s, hooks),
                risk=catalog.STEPS[s["type"]].risk if s.get("type") in catalog.STEPS else "unknown",
                params={k: v for k, v in s.items() if k != "type"},
            )
            for s in wf.steps or []
        ],
        requires_approval=engine.needs_approval(wf.requires_approval, wf.steps or []),
        approval_forced=forced,
        enabled=wf.enabled,
        hook_path=_hook_path(wf.organization_id, wf.id) if wf.trigger_type == "webhook" else None,
        next_run_at=wf.next_run_at if wf.enabled else None,
        last_run_at=wf.last_run_at,
        last_status=wf.last_status,
        owner_name=names.get(wf.created_by) if wf.created_by else None,
        created_at=wf.created_at,
        updated_at=wf.updated_at,
    )


def _one_workflow_out(db: DB, wf: AutomationWorkflow) -> WorkflowOut:
    return _workflow_out(db, wf, _hooks_by_id(db, wf.organization_id), _names(db, {wf.created_by}))


def _runs_out(db: DB, rows: list[AutomationRun]) -> list[RunOut]:
    names = _names(db, {r.requested_by for r in rows} | {r.decided_by for r in rows})
    out = []
    for r in rows:
        item = RunOut.model_validate(r)
        item.requested_by_name = names.get(r.requested_by) if r.requested_by else None
        item.decided_by_name = names.get(r.decided_by) if r.decided_by else None
        out.append(item)
    return out


def _get_workflow(db: DB, org_id: uuid.UUID, wf_id: uuid.UUID) -> AutomationWorkflow:
    wf = db.scalar(
        select(AutomationWorkflow).where(
            AutomationWorkflow.organization_id == org_id, AutomationWorkflow.id == wf_id
        )
    )
    if wf is None:
        raise not_found("Workflow")
    return wf


def _get_hook(db: DB, org_id: uuid.UUID, hook_id: uuid.UUID) -> Integration:
    hook = db.scalar(
        select(Integration).where(Integration.organization_id == org_id, Integration.id == hook_id)
    )
    if hook is None:
        raise not_found("Webhook")
    return hook


def _check_url(url: str) -> str:
    url = url.strip()
    try:
        targets.check(url)
    except targets.TargetRefused as exc:
        raise AppError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_url", str(exc)) from None
    return url


# ----------------------------------------------------------------------------------- overview
@router.get("/overview", response_model=AutomationOverview)
def overview(ctx: Read, db: DB) -> AutomationOverview:
    from app.soc.actions import emergency_stop

    org_id = ctx.org_id
    engine.expire_stale(db, org_id)
    db.commit()
    since = now() - timedelta(hours=24)
    runs = dict(
        db.execute(
            select(AutomationRun.status, func.count())
            .where(AutomationRun.organization_id == org_id, AutomationRun.created_at >= since)
            .group_by(AutomationRun.status)
        ).all()
    )
    deliveries = dict(
        db.execute(
            select(WebhookDelivery.status, func.count())
            .where(WebhookDelivery.organization_id == org_id)
            .group_by(WebhookDelivery.status)
        ).all()
    )
    wf = db.execute(
        select(func.count(), func.count().filter(AutomationWorkflow.enabled.is_(True))).where(
            AutomationWorkflow.organization_id == org_id
        )
    ).one()
    settings = get_settings()
    return AutomationOverview(
        workflows=wf[0],
        enabled=wf[1],
        webhooks=db.scalar(select(func.count()).where(Integration.organization_id == org_id)) or 0,
        awaiting_approval=db.scalar(
            select(func.count()).where(
                AutomationRun.organization_id == org_id, AutomationRun.status == "awaiting_approval"
            )
        )
        or 0,
        runs_today=sum(runs.values()),
        failed_today=runs.get("failed", 0),
        deliveries_pending=deliveries.get("pending", 0),
        deliveries_failed=deliveries.get("failed", 0),
        signing_key=signing.key_source(),
        delivery_enabled=settings.automation_delivery_enabled,
        private_targets_allowed=settings.automation_allow_private_targets,
        emergency_stop=emergency_stop(ctx.organization)["engaged"],
    )


@router.get("/catalog")
def automation_catalog(ctx: Read) -> dict[str, Any]:
    return {
        "trigger_types": [{"key": k, "title": v} for k, v in catalog.TRIGGER_TYPES.items()],
        "events": [
            {
                "key": e.key,
                "title": e.title,
                "description": e.description,
                "filters": e.filters,
                "fields": e.fields,
            }
            for e in catalog.EVENTS.values()
        ],
        "schedules": [{"every_minutes": k, "title": v} for k, v in catalog.SCHEDULES.items()],
        "steps": [
            {
                "key": s.key,
                "title": s.title,
                "description": s.description,
                "risk": s.risk,
                "permission": s.permission,
                "triggers": s.triggers,
                "events": s.events,
            }
            for s in catalog.STEPS.values()
        ],
        "indicator_types": catalog.INDICATOR_TYPES,
        "audiences": list(catalog.STEPS["notify"].extra["audiences"]),
        "recipes": catalog.RECIPES,
        "signature": {
            "header": signing.SIGNATURE_HEADER,
            "timestamp_header": signing.TIMESTAMP_HEADER,
            "algorithm": "HMAC-SHA256 over '<timestamp>.<raw body>', hex, prefixed with v1=",
            "tolerance_seconds": get_settings().signature_tolerance_seconds,
        },
    }


# ---------------------------------------------------------------------------------- workflows
@router.get("/workflows", response_model=list[WorkflowOut])
def list_workflows(ctx: Read, db: DB) -> list[WorkflowOut]:
    rows = db.scalars(
        select(AutomationWorkflow)
        .where(AutomationWorkflow.organization_id == ctx.org_id)
        .order_by(AutomationWorkflow.created_at.desc())
    ).all()
    hooks = _hooks_by_id(db, ctx.org_id)
    names = _names(db, {r.created_by for r in rows})
    return [_workflow_out(db, r, hooks, names) for r in rows]


@router.post("/workflows", status_code=status.HTTP_201_CREATED, response_model=WorkflowOut | WorkflowSecret)
def create_workflow(body: WorkflowIn, ctx: Manage, db: DB, request: Request) -> WorkflowOut | WorkflowSecret:
    wf = AutomationWorkflow(
        id=uuid.uuid4(),
        organization_id=ctx.org_id,
        name=body.name,
        description=body.description,
        trigger_type=body.trigger_type,
        trigger_config={},
        steps=[],
        enabled=body.enabled,
        created_by=ctx.user.id,
        secret_version=1,
    )
    engine.apply_definition(
        db,
        wf,
        trigger_type=body.trigger_type,
        trigger_config=body.trigger_config,
        steps=body.steps,
        requires_approval=body.requires_approval,
    )
    db.add(wf)
    db.flush()
    audit.record(
        db,
        "automation.workflow_create",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="automation_workflow",
        target_id=wf.id,
        details={"name": wf.name, "trigger": wf.trigger_type, "steps": [s["type"] for s in wf.steps]},
    )
    db.commit()
    out = _one_workflow_out(db, wf)
    if wf.trigger_type == "webhook":
        return WorkflowSecret(
            workflow=out,
            secret=signing.derive_secret("workflow", wf.id, wf.secret_version),
            hook_path=out.hook_path or "",
        )
    return out


@router.get("/workflows/{workflow_id}", response_model=WorkflowOut)
def get_workflow(workflow_id: uuid.UUID, ctx: Read, db: DB) -> WorkflowOut:
    return _one_workflow_out(db, _get_workflow(db, ctx.org_id, workflow_id))


@router.patch("/workflows/{workflow_id}", response_model=WorkflowOut)
def update_workflow(
    workflow_id: uuid.UUID, body: WorkflowUpdate, ctx: Manage, db: DB, request: Request
) -> WorkflowOut:
    wf = _get_workflow(db, ctx.org_id, workflow_id)
    changes = body.model_dump(exclude_unset=True)
    if changes.get("name"):
        wf.name = changes["name"]
    if "description" in changes:
        wf.description = changes["description"]
    if {"trigger_type", "trigger_config", "steps", "requires_approval"} & changes.keys():
        engine.apply_definition(
            db,
            wf,
            trigger_type=changes.get("trigger_type") or wf.trigger_type,
            trigger_config=changes["trigger_config"]
            if changes.get("trigger_config") is not None
            else wf.trigger_config,
            steps=changes["steps"] if changes.get("steps") is not None else wf.steps,
            requires_approval=changes["requires_approval"]
            if changes.get("requires_approval") is not None
            else wf.requires_approval,
        )
    if changes.get("enabled") is not None:
        wf.enabled = bool(changes["enabled"])
        if wf.enabled and wf.trigger_type == "schedule" and wf.next_run_at is None:
            wf.next_run_at = now() + timedelta(minutes=int(wf.trigger_config.get("every_minutes", 1440)))
    previous_owner = wf.created_by
    wf.created_by = ctx.user.id  # whoever saves a workflow owns it (and its runs act as them)
    audit.record(
        db,
        "automation.workflow_update",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="automation_workflow",
        target_id=wf.id,
        details={
            "fields": sorted(changes),
            "enabled": wf.enabled,
            "owner_changed": previous_owner != ctx.user.id,
        },
    )
    db.commit()
    return _one_workflow_out(db, wf)


@router.delete("/workflows/{workflow_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_workflow(workflow_id: uuid.UUID, ctx: Manage, db: DB, request: Request) -> None:
    wf = _get_workflow(db, ctx.org_id, workflow_id)
    audit.record(
        db,
        "automation.workflow_delete",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="automation_workflow",
        target_id=wf.id,
        details={"name": wf.name},
    )
    db.delete(wf)
    db.commit()


@router.post("/workflows/{workflow_id}/run", response_model=RunOut, status_code=status.HTTP_201_CREATED)
def run_workflow(workflow_id: uuid.UUID, ctx: Manage, db: DB, request: Request) -> RunOut:
    wf = _get_workflow(db, ctx.org_id, workflow_id)
    run = engine.run_manual(db, wf, ctx.user)
    audit.record(
        db,
        "automation.run_manual",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="automation_run",
        target_id=run.id,
        details={"workflow": wf.name, "status": run.status},
    )
    db.commit()
    return _runs_out(db, [run])[0]


@router.post("/workflows/{workflow_id}/rotate-secret", response_model=WorkflowSecret)
def rotate_workflow_secret(workflow_id: uuid.UUID, ctx: Manage, db: DB, request: Request) -> WorkflowSecret:
    wf = _get_workflow(db, ctx.org_id, workflow_id)
    if wf.trigger_type != "webhook":
        raise AppError(
            status.HTTP_409_CONFLICT, "not_webhook", "Only webhook-triggered workflows have a secret"
        )
    wf.secret_version = (wf.secret_version or 1) + 1
    audit.record(
        db,
        "automation.workflow_secret_rotate",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="automation_workflow",
        target_id=wf.id,
        details={"version": wf.secret_version},
    )
    db.commit()
    out = _one_workflow_out(db, wf)
    return WorkflowSecret(
        workflow=out,
        secret=signing.derive_secret("workflow", wf.id, wf.secret_version),
        hook_path=out.hook_path or "",
    )


# --------------------------------------------------------------------------------------- runs
@router.get("/runs", response_model=Page[RunOut])
def list_runs(
    ctx: Read,
    db: DB,
    status_: Annotated[str | None, Query(alias="status")] = None,
    workflow_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[RunOut]:
    engine.expire_stale(db, ctx.org_id)
    db.commit()
    filters = [AutomationRun.organization_id == ctx.org_id]
    if status_:
        filters.append(AutomationRun.status == status_)
    if workflow_id:
        filters.append(AutomationRun.workflow_id == workflow_id)
    total = db.scalar(select(func.count()).select_from(AutomationRun).where(*filters)) or 0
    rows = db.scalars(
        select(AutomationRun)
        .where(*filters)
        .order_by(AutomationRun.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return Page(items=_runs_out(db, list(rows)), total=total, limit=limit, offset=offset)


@router.post("/runs/{run_id}/decision", response_model=RunOut)
def decide_run(run_id: uuid.UUID, body: RunDecision, ctx: Approve, db: DB, request: Request) -> RunOut:
    run = db.scalar(
        select(AutomationRun).where(AutomationRun.organization_id == ctx.org_id, AutomationRun.id == run_id)
    )
    if run is None:
        raise not_found("Run")
    engine.decide(db, request, run, user=ctx.user, approve=body.approve, comment=body.comment)
    db.commit()
    return _runs_out(db, [run])[0]


# ----------------------------------------------------------------------------------- webhooks
@router.get("/webhooks", response_model=list[WebhookOut])
def list_webhooks(ctx: Read, db: DB) -> list[WebhookOut]:
    rows = db.scalars(
        select(Integration).where(Integration.organization_id == ctx.org_id).order_by(Integration.name)
    ).all()
    usage = _usage(db, ctx.org_id)
    full = "integrations:manage" in ctx.permissions
    return [_webhook_out(r, usage.get(str(r.id), 0), full_url=full) for r in rows]


@router.post("/webhooks", status_code=status.HTTP_201_CREATED, response_model=WebhookSecret)
def create_webhook(body: WebhookCreate, ctx: Manage, db: DB, request: Request) -> WebhookSecret:
    url = _check_url(body.url)
    if db.scalar(
        select(Integration.id).where(Integration.organization_id == ctx.org_id, Integration.name == body.name)
    ):
        raise AppError(status.HTTP_409_CONFLICT, "duplicate_name", "A webhook with this name already exists")
    hook = Integration(
        id=uuid.uuid4(),
        organization_id=ctx.org_id,
        provider=body.provider,
        name=body.name,
        status="active",
        config={"url": url, "description": body.description},
        secret_version=1,
        failure_count=0,
        created_by=ctx.user.id,
    )
    db.add(hook)
    db.flush()
    audit.record(
        db,
        "automation.webhook_create",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="integration",
        target_id=hook.id,
        details={"name": hook.name, "provider": hook.provider, "host": targets.display_host(url)},
    )
    db.commit()
    return WebhookSecret(webhook=_webhook_out(hook, 0, full_url=True), secret=delivery.secret_for(hook))


@router.patch("/webhooks/{webhook_id}", response_model=WebhookOut)
def update_webhook(
    webhook_id: uuid.UUID, body: WebhookUpdate, ctx: Manage, db: DB, request: Request
) -> WebhookOut:
    hook = _get_hook(db, ctx.org_id, webhook_id)
    changes = body.model_dump(exclude_unset=True)
    config = dict(hook.config or {})
    if changes.get("url"):
        config["url"] = _check_url(changes["url"])
    if "description" in changes:
        config["description"] = changes["description"]
    hook.config = config
    if changes.get("name"):
        clash = db.scalar(
            select(Integration.id).where(
                Integration.organization_id == ctx.org_id,
                Integration.name == changes["name"],
                Integration.id != hook.id,
            )
        )
        if clash:
            raise AppError(
                status.HTTP_409_CONFLICT, "duplicate_name", "A webhook with this name already exists"
            )
        hook.name = changes["name"]
    if changes.get("enabled") is not None:
        hook.status = "active" if changes["enabled"] else "disabled"
        if changes["enabled"]:
            hook.failure_count = 0
    audit.record(
        db,
        "automation.webhook_update",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="integration",
        target_id=hook.id,
        details={"fields": sorted(changes), "host": targets.display_host(config.get("url", ""))},
    )
    db.commit()
    return _webhook_out(hook, _usage(db, ctx.org_id).get(str(hook.id), 0), full_url=True)


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(webhook_id: uuid.UUID, ctx: Manage, db: DB, request: Request) -> None:
    hook = _get_hook(db, ctx.org_id, webhook_id)
    used = _usage(db, ctx.org_id).get(str(hook.id), 0)
    if used:
        raise AppError(
            status.HTTP_409_CONFLICT,
            "in_use",
            f"Used by {used} workflow(s) — remove it from them first",
        )
    audit.record(
        db,
        "automation.webhook_delete",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="integration",
        target_id=hook.id,
        details={"name": hook.name},
    )
    db.delete(hook)
    db.commit()


@router.post("/webhooks/{webhook_id}/rotate-secret", response_model=WebhookSecret)
def rotate_webhook_secret(webhook_id: uuid.UUID, ctx: Manage, db: DB, request: Request) -> WebhookSecret:
    hook = _get_hook(db, ctx.org_id, webhook_id)
    hook.secret_version = (hook.secret_version or 1) + 1
    audit.record(
        db,
        "automation.webhook_secret_rotate",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="integration",
        target_id=hook.id,
        details={"version": hook.secret_version},
    )
    db.commit()
    return WebhookSecret(
        webhook=_webhook_out(hook, _usage(db, ctx.org_id).get(str(hook.id), 0), full_url=True),
        secret=delivery.secret_for(hook),
    )


def _delivery_out(item: WebhookDelivery) -> DeliveryOut:
    return DeliveryOut(
        id=item.id,
        webhook_id=item.integration_id,
        run_id=item.run_id,
        event_type=item.event_type,
        status=item.status,
        attempts=item.attempts,
        next_attempt_at=item.next_attempt_at,
        last_status_code=item.last_status_code,
        last_error=item.last_error,
        response_ms=item.response_ms,
        delivered_at=item.delivered_at,
        is_simulated=item.is_simulated,
        created_at=item.created_at,
    )


@router.post("/webhooks/{webhook_id}/test", response_model=DeliveryOut)
def test_webhook(webhook_id: uuid.UUID, ctx: Manage, db: DB, request: Request) -> DeliveryOut:
    hook = _get_hook(db, ctx.org_id, webhook_id)
    if hook.status != "active":
        raise AppError(status.HTTP_409_CONFLICT, "disabled", "Turn the webhook on first")
    item = delivery.enqueue(
        db,
        hook,
        event_type="test",
        data={"message": "Test delivery from SENTINEL X", "sent_by": ctx.user.full_name or ctx.user.email},
    )
    db.commit()  # the outbox row exists even if the call below takes a while
    delivery.attempt(db, item, hook)
    audit.record(
        db,
        "automation.webhook_test",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="integration",
        target_id=hook.id,
        details={"status": item.status, "code": item.last_status_code},
    )
    db.commit()
    return _delivery_out(item)


@router.get("/deliveries", response_model=Page[DeliveryOut])
def list_deliveries(
    ctx: Read,
    db: DB,
    webhook_id: uuid.UUID | None = None,
    status_: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[DeliveryOut]:
    filters = [WebhookDelivery.organization_id == ctx.org_id]
    if webhook_id:
        filters.append(WebhookDelivery.integration_id == webhook_id)
    if status_:
        filters.append(WebhookDelivery.status == status_)
    total = db.scalar(select(func.count()).select_from(WebhookDelivery).where(*filters)) or 0
    rows = db.scalars(
        select(WebhookDelivery)
        .where(*filters)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return Page(items=[_delivery_out(r) for r in rows], total=total, limit=limit, offset=offset)


@router.post("/deliveries/{delivery_id}/retry", response_model=DeliveryOut)
def retry_delivery(delivery_id: uuid.UUID, ctx: Manage, db: DB, request: Request) -> DeliveryOut:
    item = db.scalar(
        select(WebhookDelivery).where(
            WebhookDelivery.organization_id == ctx.org_id, WebhookDelivery.id == delivery_id
        )
    )
    if item is None:
        raise not_found("Delivery")
    if item.status == "delivered":
        raise AppError(status.HTTP_409_CONFLICT, "delivered", "This delivery already succeeded")
    hook = _get_hook(db, ctx.org_id, item.integration_id)
    if hook.status != "active":
        raise AppError(status.HTTP_409_CONFLICT, "disabled", "Turn the webhook on first")
    delivery.attempt(db, item, hook)
    audit.record(
        db,
        "automation.delivery_retry",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="webhook_delivery",
        target_id=item.id,
        details={"status": item.status, "code": item.last_status_code},
    )
    db.commit()
    return _delivery_out(item)


# ------------------------------------------------------------------------------ incoming hooks
@hooks_router.post(
    "/{org_id}/{workflow_id}",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=HookAccepted,
    max_body_size=limits.inbound_hook(),
)
async def incoming_hook(org_id: uuid.UUID, workflow_id: uuid.UUID, request: Request, db: DB) -> HookAccepted:
    """Start a webhook-triggered workflow. Authenticated only by the HMAC signature."""
    from starlette.concurrency import run_in_threadpool

    settings = get_settings()
    enforce(request, "hook", settings.rate_limit_hooks_per_minute, str(workflow_id))
    limit = settings.inbound_hook_max_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise AppError(status.HTTP_413_CONTENT_TOO_LARGE, "too_large", f"Body larger than {limit} bytes")
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise AppError(status.HTTP_413_CONTENT_TOO_LARGE, "too_large", f"Body larger than {limit} bytes")

    def _handle() -> HookAccepted:
        set_tenant_context(db, org_id=org_id)
        wf = db.scalar(
            select(AutomationWorkflow).where(
                AutomationWorkflow.organization_id == org_id,
                AutomationWorkflow.id == workflow_id,
                AutomationWorkflow.trigger_type == "webhook",
            )
        )
        if wf is None:
            raise not_found("Hook")
        reason = signing.verify(
            signing.derive_secret("workflow", wf.id, wf.secret_version),
            request.headers.get(signing.TIMESTAMP_HEADER),
            request.headers.get(signing.SIGNATURE_HEADER),
            body,
        )
        if reason is not None:
            raise AppError(status.HTTP_401_UNAUTHORIZED, "bad_signature", f"Invalid signature: {reason}")
        if not wf.enabled:
            raise AppError(status.HTTP_409_CONFLICT, "disabled", "This workflow is turned off")
        try:
            payload = json.loads(body or b"{}")
        except ValueError:
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_json", "Body must be JSON"
            ) from None
        if not isinstance(payload, dict):
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_json", "Body must be a JSON object"
            )
        dedupe = hashlib.sha256(request.headers.get(signing.SIGNATURE_HEADER, "").encode()).hexdigest()
        run = engine.receive_hook(db, wf, payload, dedupe_key=dedupe)
        audit.record(
            db,
            "automation.hook_received",
            request=request,
            org_id=org_id,
            actor_type="system",
            target_type="automation_run",
            target_id=run.id,
            details={"workflow": wf.name, "status": run.status, "bytes": len(body)},
        )
        db.commit()
        return HookAccepted(run_id=run.id, status=run.status)

    return await run_in_threadpool(_handle)
