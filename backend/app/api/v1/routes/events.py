from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select

from app.api.deps import DB, OrgContext, require
from app.core.errors import AppError, not_found
from app.models import AgentRun, Alert, Device, SecurityEvent
from app.schemas.common import Page
from app.schemas.events import (
    AlertOut,
    EventDetail,
    EventOut,
    EventStatusUpdate,
    IngestResult,
    ManualEventIn,
    RejectedEvent,
    TriageSummary,
)
from app.services import audit, realtime
from app.services import events as event_service


def alerts_out(db: DB, org_id: uuid.UUID, alerts: list[Alert]) -> list[AlertOut]:
    """Alerts with their latest Security Brain triage (one extra query for the whole page)."""
    latest: dict[uuid.UUID, AgentRun] = {}
    if alerts:
        runs = db.scalars(
            select(AgentRun)
            .where(
                AgentRun.organization_id == org_id,
                AgentRun.subject_type == "alert",
                AgentRun.subject_id.in_([a.id for a in alerts]),
            )
            .order_by(AgentRun.created_at.desc())
        ).all()
        for run in runs:
            if run.subject_id is not None:
                latest.setdefault(run.subject_id, run)
    out = []
    for alert in alerts:
        item = AlertOut.model_validate(alert)
        run = latest.get(alert.id)
        if run is not None:
            item.triage = TriageSummary(
                run_id=run.id,
                risk_score=run.risk_score,
                risk_level=run.risk_level,
                priority=(run.output_summary or {}).get("priority"),
                created_at=run.created_at,
            )
        out.append(item)
    return out


router = APIRouter(prefix="/organizations/{org_id}", tags=["events"])

SEVERITY_RE = r"^(info|low|medium|high|critical)$"


def _event_out(event: SecurityEvent, device_name: str | None) -> EventOut:
    out = EventOut.model_validate(event)
    out.device_name = device_name
    return out


@router.get("/events", response_model=Page[EventOut])
def list_events(
    ctx: Annotated[OrgContext, Depends(require("events:read"))],
    db: DB,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    severity: Annotated[str | None, Query(pattern=SEVERITY_RE)] = None,
    category: Annotated[str | None, Query(max_length=32)] = None,
    status: Annotated[str | None, Query(pattern=r"^(new|triaged|closed|open)$")] = None,
    device_id: uuid.UUID | None = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    since: datetime | None = None,
) -> Page[EventOut]:
    filters = [SecurityEvent.organization_id == ctx.org_id]
    if severity:
        filters.append(SecurityEvent.severity == severity)
    if category:
        filters.append(SecurityEvent.category == category)
    if status == "open":
        filters.append(SecurityEvent.status != "closed")
    elif status:
        filters.append(SecurityEvent.status == status)
    if device_id:
        filters.append(SecurityEvent.device_id == device_id)
    if q:
        filters.append(func.lower(SecurityEvent.title).like(f"%{q.lower()}%"))
    if since:
        filters.append(SecurityEvent.occurred_at >= since)
    total = db.scalar(select(func.count()).select_from(SecurityEvent).where(*filters)) or 0
    rows = db.execute(
        select(SecurityEvent, Device.name)
        .outerjoin(Device, Device.id == SecurityEvent.device_id)
        .where(*filters)
        .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.ingested_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return Page[EventOut](
        items=[_event_out(e, name) for e, name in rows], total=total, limit=limit, offset=offset
    )


@router.post("/events", response_model=IngestResult, status_code=201)
def submit_event(
    body: ManualEventIn,
    ctx: Annotated[OrgContext, Depends(require("events:ingest"))],
    request: Request,
    db: DB,
) -> IngestResult:
    device = None
    if body.device_id:
        device = db.scalar(
            select(Device).where(Device.id == body.device_id, Device.organization_id == ctx.org_id)
        )
        if device is None:
            raise not_found("Device")
    outcome = event_service.ingest(db, ctx.org_id, [body], source="manual", device=device)
    if outcome.rejected:
        raise AppError(422, "event_rejected", outcome.rejected[0]["reason"])
    audit.record(
        db,
        "event.submit",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="security_event",
        target_id=outcome.event_ids[0] if outcome.event_ids else None,
        details={"event_type": body.event_type, "severity": body.severity},
    )
    db.commit()
    return IngestResult(
        accepted=outcome.accepted,
        deduplicated=outcome.deduplicated,
        rejected=[RejectedEvent(**r) for r in outcome.rejected],
        alerts_created=len(outcome.alerts),
        event_ids=outcome.event_ids,
    )


@router.get("/events/{event_id}", response_model=EventDetail)
def get_event(
    event_id: uuid.UUID, ctx: Annotated[OrgContext, Depends(require("events:read"))], db: DB
) -> EventDetail:
    row = db.execute(
        select(SecurityEvent, Device.name)
        .outerjoin(Device, Device.id == SecurityEvent.device_id)
        .where(SecurityEvent.id == event_id, SecurityEvent.organization_id == ctx.org_id)
    ).first()
    if row is None:
        raise not_found("Event")
    event, device_name = row
    alerts = db.scalars(
        select(Alert).where(Alert.event_id == event.id, Alert.organization_id == ctx.org_id)
    ).all()
    base = _event_out(event, device_name).model_dump()
    return EventDetail(
        **base,
        description=event.description,
        raw=event.raw,
        normalized=event.normalized,
        alerts=alerts_out(db, ctx.org_id, list(alerts)),
    )


@router.patch("/events/{event_id}", response_model=EventOut)
def update_event_status(
    event_id: uuid.UUID,
    body: EventStatusUpdate,
    ctx: Annotated[OrgContext, Depends(require("alerts:manage"))],
    request: Request,
    db: DB,
) -> EventOut:
    event = db.scalar(
        select(SecurityEvent).where(SecurityEvent.id == event_id, SecurityEvent.organization_id == ctx.org_id)
    )
    if event is None:
        raise not_found("Event")
    if event.status != body.status:
        previous = event.status
        event.status = body.status
        audit.record(
            db,
            "event.status_change",
            request=request,
            actor_id=ctx.user.id,
            org_id=ctx.org_id,
            target_type="security_event",
            target_id=event.id,
            details={"from": previous, "to": body.status},
        )
        realtime.queue_broadcast(db, ctx.org_id, "event.updated", event_service.event_summary(event))
        db.commit()
    device_name = (
        db.scalar(select(Device.name).where(Device.id == event.device_id)) if event.device_id else None
    )
    return _event_out(event, device_name)


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    ctx: Annotated[OrgContext, Depends(require("alerts:read"))],
    db: DB,
    status: Annotated[str | None, Query(pattern=r"^(open|acknowledged|resolved|false_positive)$")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[AlertOut]:
    filters = [Alert.organization_id == ctx.org_id]
    if status:
        filters.append(Alert.status == status)
    rows = db.scalars(select(Alert).where(*filters).order_by(Alert.created_at.desc()).limit(limit)).all()
    return alerts_out(db, ctx.org_id, list(rows))
