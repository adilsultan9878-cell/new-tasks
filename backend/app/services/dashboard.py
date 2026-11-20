"""Command Center aggregates. Every number comes from a real query on the tenant's data —
an empty organization honestly reports zeros. Simulated records are excluded and counted
separately so demo data is never presented as a real security posture."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    AgentRun,
    Alert,
    Device,
    Incident,
    Investigation,
    OrganizationMember,
    SecurityEvent,
)
from app.schemas.dashboard import (
    CountBy,
    DashboardSummary,
    RecentAgentRun,
    RecentInvestigation,
    TimeBucket,
)
from app.services.health import system_health

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _count(db: Session, stmt) -> int:  # type: ignore[no-untyped-def]
    return int(db.scalar(stmt) or 0)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def build_summary(db: Session, org_id: uuid.UUID) -> DashboardSummary:
    now = datetime.now(UTC)
    since = now - timedelta(hours=24)

    real_devices = (
        Device.organization_id == org_id,
        Device.is_simulated.is_(False),
        Device.status != "decommissioned",
    )
    devices_by_status = [
        CountBy(key=k, count=c)
        for k, c in db.execute(
            select(Device.status, func.count()).where(*real_devices).group_by(Device.status)
        ).all()
    ]
    health_avg = db.scalar(select(func.avg(Device.health_score)).where(*real_devices))

    real_events = (SecurityEvent.organization_id == org_id, SecurityEvent.is_simulated.is_(False))
    active_events = _count(
        db,
        select(func.count()).select_from(SecurityEvent).where(*real_events, SecurityEvent.status != "closed"),
    )
    events_24h = _count(
        db,
        select(func.count())
        .select_from(SecurityEvent)
        .where(*real_events, SecurityEvent.occurred_at >= since),
    )

    # Hourly network-event histogram, bucketed in Python to stay database-portable.
    network_times = db.scalars(
        select(SecurityEvent.occurred_at).where(
            *real_events, SecurityEvent.category == "network", SecurityEvent.occurred_at >= since
        )
    ).all()
    per_hour = Counter(_aware(t).replace(minute=0, second=0, microsecond=0) for t in network_times)
    start_hour = (now - timedelta(hours=23)).replace(minute=0, second=0, microsecond=0)
    network_activity = [
        TimeBucket(
            bucket=start_hour + timedelta(hours=i), count=per_hour.get(start_hour + timedelta(hours=i), 0)
        )
        for i in range(24)
    ]

    open_incidents = _count(
        db,
        select(func.count())
        .select_from(Incident)
        .where(
            Incident.organization_id == org_id, Incident.is_simulated.is_(False), Incident.status != "closed"
        ),
    )

    open_alert_filter = (
        Alert.organization_id == org_id,
        Alert.is_simulated.is_(False),
        Alert.status.in_(("open", "acknowledged")),
    )
    by_sev = dict(
        db.execute(
            select(Alert.severity, func.count()).where(*open_alert_filter).group_by(Alert.severity)
        ).all()
    )
    alerts_by_severity = [CountBy(key=s, count=int(by_sev.get(s, 0))) for s in SEVERITY_ORDER]

    investigations = db.scalars(
        select(Investigation)
        .where(Investigation.organization_id == org_id)
        .order_by(Investigation.created_at.desc())
        .limit(5)
    ).all()
    agent_runs = db.scalars(
        select(AgentRun)
        .where(AgentRun.organization_id == org_id)
        .order_by(AgentRun.created_at.desc())
        .limit(5)
    ).all()
    runs_by_status = [
        CountBy(key=k, count=c)
        for k, c in db.execute(
            select(AgentRun.status, func.count())
            .where(AgentRun.organization_id == org_id, AgentRun.created_at >= since)
            .group_by(AgentRun.status)
        ).all()
    ]

    simulated = sum(
        _count(
            db,
            select(func.count())
            .select_from(model)
            .where(model.organization_id == org_id, model.is_simulated.is_(True)),
        )
        for model in (Device, SecurityEvent, Incident, Alert)
    )
    members = _count(
        db,
        select(func.count())
        .select_from(OrganizationMember)
        .where(OrganizationMember.organization_id == org_id, OrganizationMember.status == "active"),
    )

    return DashboardSummary(
        generated_at=now,
        devices_total=sum(c.count for c in devices_by_status),
        devices_by_status=devices_by_status,
        device_health_avg=round(float(health_avg), 1) if health_avg is not None else None,
        active_events=active_events,
        events_last_24h=events_24h,
        open_incidents=open_incidents,
        critical_alerts=int(by_sev.get("critical", 0)),
        open_alerts_by_severity=alerts_by_severity,
        network_activity_24h=network_activity,
        recent_investigations=[RecentInvestigation.model_validate(i) for i in investigations],
        recent_agent_runs=[RecentAgentRun.model_validate(r) for r in agent_runs],
        agent_runs_24h_by_status=runs_by_status,
        members=members,
        simulated_records_excluded=simulated,
        system=system_health(db),
    )
