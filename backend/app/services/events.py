"""Security event ingestion: validation, normalisation, de-duplication and deterministic detection.

Detection here is rule-based only (no AI). Every alert records the rule that produced it, so an
analyst can always see *why* it fired.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import (
    Alert,
    Device,
    Notification,
    OrganizationMember,
    Permission,
    RolePermission,
    SecurityEvent,
)
from app.schemas.events import EventIn
from app.services import realtime

SEVERITY_SCORE = {"info": 10, "low": 30, "medium": 50, "high": 75, "critical": 95}
ALERTING_SEVERITIES = {"high", "critical"}
BRUTEFORCE_EVENT = "auth.login_failed"
# raw fields lifted into normalized.observables (matched against the watchlist by the Brain)
OBSERVABLE_KEYS = (
    "source_ip",
    "destination_ip",
    "port",
    "process",
    "user",
    "domain",
    "url",
    "file_hash",
    "sha256",
    "md5",
    "sha1",
)


@dataclass
class IngestOutcome:
    accepted: int = 0
    deduplicated: int = 0
    rejected: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    event_ids: list[uuid.UUID] = field(default_factory=list)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def fingerprint(item: EventIn, device_id: uuid.UUID | None) -> str:
    basis: list[Any] = [str(device_id) if device_id else None, item.event_type, item.category]
    basis += [item.dedup_key] if item.dedup_key else [item.severity, item.title]
    return hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()


def normalize(item: EventIn, device: Device | None, source: str) -> dict[str, Any]:
    """A small, stable, ECS-inspired view used by rules, search and the future AI orchestrator."""
    normalized: dict[str, Any] = {
        "event": {
            "kind": "alert" if item.severity in ALERTING_SEVERITIES else "event",
            "category": item.category,
            "type": item.event_type,
            "severity_score": SEVERITY_SCORE[item.severity],
            "source": source,
        }
    }
    if device is not None:
        normalized["host"] = {
            "id": str(device.id),
            "name": device.name,
            "hostname": device.hostname,
            "os": device.os,
            "ip": device.ip_address,
        }
    for key in OBSERVABLE_KEYS:
        if key in item.raw and isinstance(item.raw[key], str | int):
            normalized.setdefault("observables", {})[key] = item.raw[key]
    return normalized


def event_summary(event: SecurityEvent, device_name: str | None = None) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "title": event.title,
        "severity": event.severity,
        "category": event.category,
        "event_type": event.event_type,
        "device_id": str(event.device_id) if event.device_id else None,
        "device_name": device_name,
        "occurrence_count": event.occurrence_count,
        "occurred_at": event.occurred_at.isoformat(),
    }


def _alert_summary(alert: Alert) -> dict[str, Any]:
    return {
        "id": str(alert.id),
        "title": alert.title,
        "severity": alert.severity,
        "detection_rule": alert.detection_rule,
        "event_id": str(alert.event_id) if alert.event_id else None,
    }


def _notify_responders(db: Session, org_id: uuid.UUID, alert: Alert) -> None:
    responders = db.scalars(
        select(OrganizationMember.user_id)
        .join(RolePermission, RolePermission.role_id == OrganizationMember.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.status == "active",
            Permission.key == "alerts:manage",
        )
    ).all()
    for user_id in set(responders):
        db.add(
            Notification(
                id=uuid.uuid4(),
                user_id=user_id,
                organization_id=org_id,
                kind="alert",
                title=f"{alert.severity.capitalize()} alert: {alert.title}"[:200],
                body=alert.description[:500] if alert.description else None,
                link="/events",
                severity=alert.severity,
            )
        )


def _raise_alert(
    db: Session,
    event: SecurityEvent,
    *,
    title: str,
    severity: str,
    rule: str,
    description: str,
) -> Alert:
    alert = Alert(
        id=uuid.uuid4(),
        organization_id=event.organization_id,
        event_id=event.id,
        title=title[:255],
        description=description,
        severity=severity,
        status="open",
        risk_score=SEVERITY_SCORE[severity],
        detection_rule=rule,
        is_simulated=event.is_simulated,
    )
    db.add(alert)
    db.flush()
    _notify_responders(db, event.organization_id, alert)
    realtime.queue_broadcast(db, event.organization_id, "alert.created", _alert_summary(alert))
    return alert


def _run_rules(db: Session, event: SecurityEvent, device: Device | None, is_new: bool) -> list[Alert]:
    settings = get_settings()
    alerts: list[Alert] = []
    where = device.name if device else "the organization"

    # Rule 1 — severity threshold: every *new* high/critical event becomes an alert.
    if is_new and event.severity in ALERTING_SEVERITIES:
        alerts.append(
            _raise_alert(
                db,
                event,
                title=event.title,
                severity=event.severity,
                rule="severity-threshold",
                description=f"{event.severity.capitalize()} {event.category} event reported by {where}.",
            )
        )

    # Rule 2 — brute force: N failed logins on one device within the window (duplicates count).
    if event.event_type == BRUTEFORCE_EVENT and event.device_id is not None:
        since = _now() - timedelta(minutes=settings.bruteforce_window_minutes)
        failures = db.scalar(
            select(func.coalesce(func.sum(SecurityEvent.occurrence_count), 0)).where(
                SecurityEvent.organization_id == event.organization_id,
                SecurityEvent.device_id == event.device_id,
                SecurityEvent.event_type == BRUTEFORCE_EVENT,
                func.coalesce(SecurityEvent.last_occurred_at, SecurityEvent.occurred_at) >= since,
            )
        )
        if (failures or 0) >= settings.bruteforce_threshold:
            already = db.scalar(
                select(Alert.id)
                .join(SecurityEvent, SecurityEvent.id == Alert.event_id)
                .where(
                    Alert.organization_id == event.organization_id,
                    Alert.detection_rule == "auth-bruteforce",
                    Alert.status.in_(("open", "acknowledged")),
                    SecurityEvent.device_id == event.device_id,
                )
            )
            if already is None:
                alerts.append(
                    _raise_alert(
                        db,
                        event,
                        title=f"Possible brute-force attack on {where}",
                        severity="high",
                        rule="auth-bruteforce",
                        description=(
                            f"{failures} failed logins within {settings.bruteforce_window_minutes} "
                            f"minutes (threshold {settings.bruteforce_threshold})."
                        ),
                    )
                )
    return alerts


def ingest(
    db: Session,
    org_id: uuid.UUID,
    items: list[EventIn],
    *,
    source: str,
    device: Device | None = None,
    simulated: bool = False,
) -> IngestOutcome:
    settings = get_settings()
    now = _now()
    outcome = IngestOutcome()
    window_start = now - timedelta(minutes=settings.event_dedup_window_minutes)
    device_name = device.name if device else None

    for index, item in enumerate(items):
        occurred = item.occurred_at or now
        if occurred > now + timedelta(seconds=settings.event_max_clock_skew_seconds):
            outcome.rejected.append({"index": index, "reason": "occurred_at is in the future"})
            continue
        if occurred < now - timedelta(days=settings.event_max_age_days):
            outcome.rejected.append({"index": index, "reason": "occurred_at is too old"})
            continue

        device_id = device.id if device else None
        fp = fingerprint(item, device_id)
        existing = db.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.organization_id == org_id,
                SecurityEvent.fingerprint == fp,
                SecurityEvent.status != "closed",
                func.coalesce(SecurityEvent.last_occurred_at, SecurityEvent.occurred_at) >= window_start,
            )
            .order_by(SecurityEvent.ingested_at.desc())
            .limit(1)
        )
        if existing is not None:
            existing.occurrence_count += 1
            existing.last_occurred_at = max(_aware(existing.last_occurred_at) or occurred, occurred)
            db.flush()
            outcome.deduplicated += 1
            outcome.event_ids.append(existing.id)
            outcome.alerts += _run_rules(db, existing, device, is_new=False)
            realtime.queue_broadcast(db, org_id, "event.updated", event_summary(existing, device_name))
            continue

        event = SecurityEvent(
            id=uuid.uuid4(),
            organization_id=org_id,
            device_id=device_id,
            source=source,
            category=item.category,
            event_type=item.event_type,
            severity=item.severity,
            status="new",
            title=item.title,
            description=item.description,
            fingerprint=fp,
            raw=item.raw,
            normalized=normalize(item, device, source),
            occurred_at=occurred,
            ingested_at=now,
            occurrence_count=1,
            is_simulated=simulated,
        )
        db.add(event)
        db.flush()
        outcome.accepted += 1
        outcome.event_ids.append(event.id)
        outcome.alerts += _run_rules(db, event, device, is_new=True)
        realtime.queue_broadcast(db, org_id, "event.created", event_summary(event, device_name))
    if outcome.alerts:
        from app.brain.orchestrator import auto_triage  # local import: the Brain reads event data

        auto_triage(db, org_id, [a.id for a in outcome.alerts])
        from app.automation.engine import on_alerts  # local import: automation reads alerts

        on_alerts(db, org_id, outcome.alerts)
    return outcome
