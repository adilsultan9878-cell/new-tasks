from __future__ import annotations

import uuid
from datetime import datetime

from app.schemas.common import APIModel


class CountBy(APIModel):
    key: str
    count: int


class TimeBucket(APIModel):
    bucket: datetime
    count: int


class RecentInvestigation(APIModel):
    id: uuid.UUID
    title: str
    subject_type: str
    status: str
    verdict: str
    risk_score: int | None
    created_at: datetime


class RecentEvent(APIModel):
    id: uuid.UUID
    title: str
    severity: str
    category: str
    device_name: str | None
    occurrence_count: int
    occurred_at: datetime


class RecentAgentRun(APIModel):
    id: uuid.UUID
    agent_name: str
    status: str
    trigger: str
    created_at: datetime
    finished_at: datetime | None


class DatabaseHealth(APIModel):
    status: str
    latency_ms: float | None
    engine: str
    row_level_security: str  # "enforced", "bypassed_by_role", "not_supported"


class SystemHealth(APIModel):
    api: str
    version: str
    environment: str
    database: DatabaseHealth
    realtime: str
    uptime_seconds: int


class DashboardSummary(APIModel):
    generated_at: datetime
    devices_total: int
    devices_by_status: list[CountBy]
    device_health_avg: float | None
    active_events: int
    events_last_24h: int
    open_incidents: int
    critical_alerts: int
    open_alerts_by_severity: list[CountBy]
    network_activity_24h: list[TimeBucket]
    recent_events: list[RecentEvent]
    recent_investigations: list[RecentInvestigation]
    recent_agent_runs: list[RecentAgentRun]
    agent_runs_24h_by_status: list[CountBy]
    members: int
    simulated_records_excluded: int
    system: SystemHealth
