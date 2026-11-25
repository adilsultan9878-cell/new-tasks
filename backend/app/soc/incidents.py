"""Incident lifecycle: creation from alerts, status changes, assignment, notes, alert triage."""

from __future__ import annotations

import re
import uuid
from typing import Any

from fastapi import Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError, not_found
from app.models import Alert, Incident, OrganizationMember, ResponseAction, User
from app.models.identity import SEVERITIES
from app.models.operations import INCIDENT_STATUSES
from app.services import audit, realtime
from app.soc.common import actor, members_with, notify, now

OPEN_ACTION_STATUSES = ("pending_approval", "approved", "executing")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def entry(kind: str, text: str, user: User | None, **data: Any) -> dict[str, Any]:
    return {
        "at": now().isoformat(),
        "kind": kind,
        "text": text,
        **actor(user),
        **({"data": data} if data else {}),
    }


def append(incident: Incident, *entries: dict[str, Any]) -> None:
    # Reassign (not mutate) so SQLAlchemy persists the JSON change.
    incident.timeline = [*(incident.timeline or []), *entries]


def summary(incident: Incident) -> dict[str, Any]:
    return {
        "id": str(incident.id),
        "reference": incident.reference,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
    }


def _next_reference(db: Session, org_id: uuid.UUID) -> str:
    year = now().year
    prefix = f"INC-{year}-"
    refs = db.scalars(
        select(Incident.reference).where(
            Incident.organization_id == org_id, Incident.reference.like(f"{prefix}%")
        )
    ).all()
    numbers = [int(m.group(1)) for r in refs if (m := re.fullmatch(rf"{prefix}(\d+)", r))]
    return f"{prefix}{(max(numbers) if numbers else 0) + 1:04d}"


def get(db: Session, org_id: uuid.UUID, incident_id: uuid.UUID) -> Incident:
    row = db.scalar(select(Incident).where(Incident.id == incident_id, Incident.organization_id == org_id))
    if row is None:
        raise not_found("Incident")
    return row


def _org_alerts(db: Session, org_id: uuid.UUID, alert_ids: list[uuid.UUID]) -> list[Alert]:
    if not alert_ids:
        return []
    rows = db.scalars(select(Alert).where(Alert.organization_id == org_id, Alert.id.in_(alert_ids))).all()
    if len(rows) != len(set(alert_ids)):
        raise not_found("Alert")
    return list(rows)


def _acknowledge(alert: Alert) -> None:
    if alert.status == "open":
        alert.status = "acknowledged"
    if alert.acknowledged_at is None:
        alert.acknowledged_at = now()


def create(
    db: Session,
    request: Request,
    *,
    org_id: uuid.UUID,
    user: User,
    title: str,
    severity: str | None,
    summary_text: str | None,
    alert_ids: list[uuid.UUID],
) -> Incident:
    alerts = _org_alerts(db, org_id, alert_ids)
    if severity is None:
        severity = max((a.severity for a in alerts), key=SEVERITY_RANK.__getitem__, default="medium")
    incident = Incident(
        id=uuid.uuid4(),
        organization_id=org_id,
        reference=_next_reference(db, org_id),
        title=title,
        summary=summary_text,
        severity=severity,
        status="open",
        opened_by=user.id,
        opened_at=now(),
        timeline=[],
    )
    db.add(incident)
    db.flush()
    append(incident, entry("created", f"Incident opened ({severity})", user))
    for alert in alerts:
        alert.incident_id = incident.id
        _acknowledge(alert)
    if alerts:
        append(
            incident,
            entry(
                "alerts_linked",
                f"{len(alerts)} alert(s) linked",
                user,
                alerts=[{"id": str(a.id), "title": a.title} for a in alerts],
            ),
        )
    audit.record(
        db,
        "incident.create",
        request=request,
        actor_id=user.id,
        org_id=org_id,
        target_type="incident",
        target_id=incident.id,
        details={"reference": incident.reference, "alerts": len(alerts)},
    )
    notify(
        db,
        org_id,
        members_with(db, org_id, "incidents:manage"),
        kind="incident",
        title=f"Incident {incident.reference} opened: {title}",
        link=f"/incidents/{incident.id}",
        severity=severity,
        exclude=user.id,
    )
    realtime.queue_broadcast(db, org_id, "incident.updated", summary(incident))
    from app.automation.engine import on_incident  # local import: avoids an import cycle

    on_incident(db, incident)
    return incident


def update(
    db: Session,
    request: Request,
    incident: Incident,
    *,
    user: User,
    status_: str | None = None,
    severity: str | None = None,
    title: str | None = None,
    summary_text: str | None = None,
    assigned_to: uuid.UUID | None = None,
    unassign: bool = False,
) -> Incident:
    org_id = incident.organization_id
    changes: dict[str, Any] = {}
    if status_ is not None and status_ != incident.status:
        if status_ not in INCIDENT_STATUSES:
            raise AppError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_status", "Unknown incident status")
        if status_ == "closed":
            pending = db.scalar(
                select(func.count())
                .select_from(ResponseAction)
                .where(
                    ResponseAction.organization_id == org_id,
                    ResponseAction.incident_id == incident.id,
                    ResponseAction.status.in_(OPEN_ACTION_STATUSES),
                )
            )
            if pending:
                raise AppError(
                    status.HTTP_409_CONFLICT,
                    "actions_pending",
                    f"{pending} response action(s) are still pending — decide or cancel them first",
                )
            incident.closed_at = now()
            for alert in db.scalars(
                select(Alert).where(
                    Alert.organization_id == org_id,
                    Alert.incident_id == incident.id,
                    Alert.status.in_(("open", "acknowledged")),
                )
            ):
                _acknowledge(alert)
                alert.status = "resolved"
                alert.resolved_at = now()
        elif incident.status == "closed":
            incident.closed_at = None
        changes["status"] = [incident.status, status_]
        append(incident, entry("status", f"Status: {incident.status} → {status_}", user))
        incident.status = status_
    if severity is not None and severity != incident.severity:
        changes["severity"] = [incident.severity, severity]
        append(incident, entry("severity", f"Severity: {incident.severity} → {severity}", user))
        incident.severity = severity
    if title is not None and title != incident.title:
        changes["title"] = True
        incident.title = title
    if summary_text is not None and summary_text != (incident.summary or ""):
        changes["summary"] = True
        incident.summary = summary_text or None
    if unassign and incident.assigned_to is not None:
        changes["assigned_to"] = None
        incident.assigned_to = None
        append(incident, entry("assignment", "Unassigned", user))
    elif assigned_to is not None and assigned_to != incident.assigned_to:
        member = db.scalar(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.user_id == assigned_to,
                OrganizationMember.status == "active",
            )
        )
        if member is None:
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_assignee", "Assignee must be an active member"
            )
        assignee = db.get(User, assigned_to)
        incident.assigned_to = assigned_to
        changes["assigned_to"] = str(assigned_to)
        append(
            incident,
            entry("assignment", f"Assigned to {assignee.full_name if assignee else assigned_to}", user),
        )
        notify(
            db,
            org_id,
            [assigned_to],
            kind="incident",
            title=f"You were assigned {incident.reference}: {incident.title}",
            link=f"/incidents/{incident.id}",
            severity=incident.severity,
            exclude=user.id,
        )
    if changes:
        audit.record(
            db,
            "incident.update",
            request=request,
            actor_id=user.id,
            org_id=org_id,
            target_type="incident",
            target_id=incident.id,
            details={"reference": incident.reference, "changes": changes},
        )
        realtime.queue_broadcast(db, org_id, "incident.updated", summary(incident))
    return incident


def add_note(db: Session, request: Request, incident: Incident, *, user: User, text: str) -> Incident:
    append(incident, entry("note", text, user))
    audit.record(
        db,
        "incident.note",
        request=request,
        actor_id=user.id,
        org_id=incident.organization_id,
        target_type="incident",
        target_id=incident.id,
        details={"reference": incident.reference},
    )
    realtime.queue_broadcast(db, incident.organization_id, "incident.updated", summary(incident))
    return incident


def link_alerts(
    db: Session, request: Request, incident: Incident, *, user: User, alert_ids: list[uuid.UUID]
) -> Incident:
    alerts = [a for a in _org_alerts(db, incident.organization_id, alert_ids) if a.incident_id != incident.id]
    for alert in alerts:
        alert.incident_id = incident.id
        _acknowledge(alert)
    if alerts:
        append(
            incident,
            entry(
                "alerts_linked",
                f"{len(alerts)} alert(s) linked",
                user,
                alerts=[{"id": str(a.id), "title": a.title} for a in alerts],
            ),
        )
        audit.record(
            db,
            "incident.link_alerts",
            request=request,
            actor_id=user.id,
            org_id=incident.organization_id,
            target_type="incident",
            target_id=incident.id,
            details={"alerts": [str(a.id) for a in alerts]},
        )
        realtime.queue_broadcast(db, incident.organization_id, "incident.updated", summary(incident))
    return incident


def set_alert_status(db: Session, request: Request, alert: Alert, *, user: User, status_: str) -> Alert:
    if status_ == alert.status:
        return alert
    previous = alert.status
    if status_ in ("acknowledged", "resolved", "false_positive"):
        _acknowledge(alert)
    alert.status = status_
    alert.resolved_at = now() if status_ in ("resolved", "false_positive") else None
    if alert.assigned_to is None and status_ == "acknowledged":
        alert.assigned_to = user.id
    audit.record(
        db,
        "alert.update",
        request=request,
        actor_id=user.id,
        org_id=alert.organization_id,
        target_type="alert",
        target_id=alert.id,
        details={"status": [previous, status_]},
    )
    realtime.queue_broadcast(
        db, alert.organization_id, "alert.updated", {"id": str(alert.id), "status": status_}
    )
    return alert
