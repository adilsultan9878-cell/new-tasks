"""Tenant-owned security operations data for AEGIS ONE, NEXUS ZERO and SENTINEL X.

Every table here carries ``organization_id`` and is protected by PostgreSQL Row-Level Security
(see the initial migration). Phase 1 creates the schema so the Command Center can report real
(initially empty) numbers; later phases add the ingestion and workflow APIs that populate it.

``is_simulated`` marks demo/simulator data so it is never presented as a real incident.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPrimaryKey, in_values, utcnow
from app.models.identity import SEVERITIES

DEVICE_TYPES = ("workstation", "server", "mobile", "iot", "camera", "sensor_hub", "network", "other")
DEVICE_STATUSES = ("online", "offline", "degraded", "unknown", "decommissioned")
ENROLLMENT_STATUSES = ("pending", "enrolled", "revoked")
EVENT_STATUSES = ("new", "triaged", "closed")
EVENT_CATEGORIES = (
    "network",
    "auth",
    "malware",
    "phishing",
    "vision",
    "iot",
    "system",
    "agent",
    "policy",
    "other",
)
EVENT_SOURCES = ("agent", "manual", "integration", "camera", "sensor", "network", "system")
ALERT_STATUSES = ("open", "acknowledged", "resolved", "false_positive")
INCIDENT_STATUSES = ("open", "investigating", "contained", "eradicated", "recovered", "closed")
INVESTIGATION_STATUSES = ("pending", "running", "completed", "failed")
VERDICTS = ("unknown", "benign", "suspicious", "malicious")
INDICATOR_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")
AGENT_RUN_STATUSES = ("queued", "running", "succeeded", "failed", "cancelled")
ACTION_STATUSES = (
    "proposed",
    "pending_approval",
    "approved",
    "rejected",
    "executing",
    "succeeded",
    "failed",
    "rolled_back",
    "cancelled",
)
IMPACT_LEVELS = ("low", "medium", "high")
APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired")
REPORT_STATUSES = ("draft", "generating", "ready", "failed")


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))


def _user_fk() -> Mapped[uuid.UUID | None]:
    return mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


def _simulated() -> Mapped[bool]:
    return mapped_column(Boolean, default=False, server_default=false())


# --------------------------------------------------------------------------- assets (AEGIS ONE)
class Device(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(in_values("device_type", DEVICE_TYPES), name="device_type"),
        CheckConstraint(in_values("status", DEVICE_STATUSES), name="status"),
        CheckConstraint(in_values("enrollment_status", ENROLLMENT_STATUSES), name="enrollment_status"),
        CheckConstraint("health_score IS NULL OR (health_score BETWEEN 0 AND 100)", name="health_score"),
        CheckConstraint("risk_score IS NULL OR (risk_score BETWEEN 0 AND 100)", name="risk_score"),
        Index("ix_devices_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(120))
    device_type: Mapped[str] = mapped_column(String(24))
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    mac_address: Mapped[str | None] = mapped_column(String(17))
    os: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(16), default="unknown")
    enrollment_status: Mapped[str] = mapped_column(String(16), default="pending")
    health_score: Mapped[int | None] = mapped_column(Integer)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    credential_hash: Mapped[str | None] = mapped_column(String(255))  # device auth secret (hashed)
    credential_rotated_at: Mapped[datetime | None]
    enrolled_at: Mapped[datetime | None]
    last_seen_at: Mapped[datetime | None]
    location: Mapped[dict[str, Any]] = mapped_column(default=dict)  # site/zone/x,y,z for the twin
    tags: Mapped[list[Any]] = mapped_column(default=list)
    attributes: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Latest approved telemetry reported by the local agent (CPU, memory, disk, ports, ...).
    telemetry: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Desired agent configuration (allow-listed keys only) and its version.
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    config_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    is_simulated: Mapped[bool] = _simulated()


class EnrollmentToken(UUIDPrimaryKey, Base):
    """One-time (or limited-use) secret an administrator hands to a device to enroll it."""

    __tablename__ = "enrollment_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash"),
        CheckConstraint("max_uses BETWEEN 1 AND 1000", name="max_uses"),
        CheckConstraint("use_count >= 0", name="use_count"),
        Index("ix_enrollment_tokens_org_created", "organization_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    label: Mapped[str] = mapped_column(String(120))
    token_hash: Mapped[str] = mapped_column(String(64))
    device_type: Mapped[str] = mapped_column(String(24), default="workstation")
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    use_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID | None] = _user_fk()
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class Camera(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "cameras"
    __table_args__ = (
        CheckConstraint(in_values("status", DEVICE_STATUSES), name="status"),
        Index("ix_cameras_org", "organization_id"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(120))
    # Reference to a secret held outside the DB (e.g. env var name) — never a raw stream password.
    stream_secret_ref: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="unknown")
    privacy_mode: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    detection_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    retention_days: Mapped[int] = mapped_column(Integer, default=7, server_default="7")
    zones: Mapped[list[Any]] = mapped_column(default=list)  # restricted-zone polygons
    last_frame_at: Mapped[datetime | None]
    is_simulated: Mapped[bool] = _simulated()


class Sensor(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "sensors"
    __table_args__ = (
        CheckConstraint(in_values("status", DEVICE_STATUSES), name="status"),
        Index("ix_sensors_org", "organization_id"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(120))
    sensor_type: Mapped[str] = mapped_column(String(48))  # temperature, motion, gas, door, ...
    unit: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="unknown")
    thresholds: Mapped[dict[str, Any]] = mapped_column(default=dict)
    last_value: Mapped[float | None] = mapped_column(Float)
    last_reading_at: Mapped[datetime | None]
    is_simulated: Mapped[bool] = _simulated()


class NetworkAsset(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "network_assets"
    __table_args__ = (UniqueConstraint("organization_id", "ip_address"),)

    organization_id: Mapped[uuid.UUID] = _org_fk()
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    ip_address: Mapped[str] = mapped_column(String(45))
    mac_address: Mapped[str | None] = mapped_column(String(17))
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(120))
    open_ports: Mapped[list[Any]] = mapped_column(default=list)
    services: Mapped[list[Any]] = mapped_column(default=list)
    in_authorized_scope: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)


# ----------------------------------------------------------------- detection (SENTINEL X SOC)
class SecurityEvent(UUIDPrimaryKey, Base):
    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint(in_values("severity", SEVERITIES), name="severity"),
        CheckConstraint(in_values("status", EVENT_STATUSES), name="status"),
        Index("ix_security_events_org_occurred", "organization_id", "occurred_at"),
        Index("ix_security_events_org_status", "organization_id", "status"),
        Index("ix_security_events_fingerprint", "organization_id", "fingerprint"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(32))  # agent, camera, sensor, network, integration...
    category: Mapped[str] = mapped_column(String(32))  # network, auth, malware, phishing, vision, iot
    event_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    status: Mapped[str] = mapped_column(String(16), default="new")
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    fingerprint: Mapped[str | None] = mapped_column(String(64))  # de-duplication key
    raw: Mapped[dict[str, Any]] = mapped_column(default=dict)
    normalized: Mapped[dict[str, Any]] = mapped_column(default=dict)
    occurred_at: Mapped[datetime] = mapped_column(default=utcnow)
    ingested_at: Mapped[datetime] = mapped_column(default=utcnow)
    # Duplicates (same fingerprint inside the de-duplication window) are folded into one row.
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    last_occurred_at: Mapped[datetime | None]
    is_simulated: Mapped[bool] = _simulated()


class Incident(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(in_values("severity", SEVERITIES), name="severity"),
        CheckConstraint(in_values("status", INCIDENT_STATUSES), name="status"),
        Index("ix_incidents_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    reference: Mapped[str] = mapped_column(String(32))  # human-friendly, e.g. INC-2026-0001
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(16), default="open")
    assigned_to: Mapped[uuid.UUID | None] = _user_fk()
    opened_by: Mapped[uuid.UUID | None] = _user_fk()
    opened_at: Mapped[datetime] = mapped_column(default=utcnow)
    closed_at: Mapped[datetime | None]
    is_simulated: Mapped[bool] = _simulated()


class Alert(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(in_values("severity", SEVERITIES), name="severity"),
        CheckConstraint(in_values("status", ALERT_STATUSES), name="status"),
        CheckConstraint("risk_score IS NULL OR (risk_score BETWEEN 0 AND 100)", name="risk_score"),
        Index("ix_alerts_org_status_severity", "organization_id", "status", "severity"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("security_events.id", ondelete="SET NULL"))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(16), default="open")
    risk_score: Mapped[int | None] = mapped_column(Integer)
    detection_rule: Mapped[str | None] = mapped_column(String(120))
    assigned_to: Mapped[uuid.UUID | None] = _user_fk()
    resolved_at: Mapped[datetime | None]
    is_simulated: Mapped[bool] = _simulated()


class Investigation(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint(in_values("status", INVESTIGATION_STATUSES), name="status"),
        CheckConstraint(in_values("verdict", VERDICTS), name="verdict"),
        Index("ix_investigations_org_created", "organization_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    alert_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"))
    subject_type: Mapped[str] = mapped_column(String(32))  # url, hash, ip, domain, email, event...
    subject: Mapped[str] = mapped_column(String(2048))
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")
    risk_score: Mapped[int | None] = mapped_column(Integer)
    summary: Mapped[str | None] = mapped_column(Text)
    # Verified facts (from trusted sources / deterministic checks) are kept apart from AI output.
    verified_findings: Mapped[list[Any]] = mapped_column(default=list)
    ai_assessment: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = _user_fk()
    started_at: Mapped[datetime | None]
    completed_at: Mapped[datetime | None]


class ThreatIndicator(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint("organization_id", "indicator_type", "value"),
        CheckConstraint(in_values("indicator_type", INDICATOR_TYPES), name="indicator_type"),
        CheckConstraint(in_values("verdict", VERDICTS), name="verdict"),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    indicator_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(2048))
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(64))  # e.g. cisa_kev, urlhaus, analyst, ai
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)
    context: Mapped[dict[str, Any]] = mapped_column(default=dict)


class VulnerabilityRecord(UUIDPrimaryKey, Base):
    """Global CVE catalogue cached from NVD / CISA KEV (public data, not tenant-owned)."""

    __tablename__ = "vulnerability_records"
    __table_args__ = (
        UniqueConstraint("cve_id"),
        CheckConstraint("cvss_score IS NULL OR (cvss_score BETWEEN 0 AND 10)", name="cvss_score"),
    )

    cve_id: Mapped[str] = mapped_column(String(32))
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str | None] = mapped_column(String(16))
    published_at: Mapped[datetime | None]
    last_modified_at: Mapped[datetime | None]
    in_cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    kev_date_added: Mapped[datetime | None]
    references: Mapped[list[Any]] = mapped_column(default=list)
    source: Mapped[str] = mapped_column(String(32), default="nvd")
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow)


class Evidence(UUIDPrimaryKey, Base):
    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_org_collected", "organization_id", "collected_at"),)

    organization_id: Mapped[uuid.UUID] = _org_fk()
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL")
    )
    evidence_type: Mapped[str] = mapped_column(String(32))  # file, snapshot, log, pcap, note
    description: Mapped[str | None] = mapped_column(Text)
    storage_uri: Mapped[str | None] = mapped_column(String(1024))
    sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    collected_by: Mapped[uuid.UUID | None] = _user_fk()
    collected_at: Mapped[datetime] = mapped_column(default=utcnow)
    chain_of_custody: Mapped[list[Any]] = mapped_column(default=list)


# --------------------------------------------------------------------------- AI agents & response
class AgentRun(UUIDPrimaryKey, Base):
    __tablename__ = "agent_runs"
    __table_args__ = (
        CheckConstraint(in_values("status", AGENT_RUN_STATUSES), name="status"),
        Index("ix_agent_runs_org_created", "organization_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="SET NULL")
    )
    agent_name: Mapped[str] = mapped_column(String(64))
    trigger: Mapped[str] = mapped_column(String(32))  # event, manual, schedule
    status: Mapped[str] = mapped_column(String(16), default="queued")
    model_provider: Mapped[str | None] = mapped_column(String(32))  # none, ollama, anthropic, ...
    model_name: Mapped[str | None] = mapped_column(String(64))
    input_summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    output_summary: Mapped[dict[str, Any]] = mapped_column(default=dict)
    tokens_used: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AgentDecision(UUIDPrimaryKey, Base):
    __tablename__ = "agent_decisions"
    __table_args__ = (
        Index("ix_agent_decisions_org_run", "organization_id", "agent_run_id"),
        CheckConstraint("confidence IS NULL OR (confidence BETWEEN 0 AND 100)", name="confidence"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    agent_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_runs.id", ondelete="CASCADE"))
    decision_type: Mapped[str] = mapped_column(String(48))  # classify, score, recommend_action...
    summary: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[int | None] = mapped_column(Integer)
    is_ai_generated: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    evidence_refs: Mapped[list[Any]] = mapped_column(default=list)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class ResponseAction(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        CheckConstraint(in_values("status", ACTION_STATUSES), name="status"),
        CheckConstraint(in_values("impact", IMPACT_LEVELS), name="impact"),
        Index("ix_response_actions_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    proposed_by_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("agent_runs.id", ondelete="SET NULL")
    )
    action_type: Mapped[str] = mapped_column(String(48))  # notify_admin, block_indicator, ...
    target: Mapped[dict[str, Any]] = mapped_column(default=dict)
    impact: Mapped[str] = mapped_column(String(16), default="low")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    status: Mapped[str] = mapped_column(String(24), default="proposed")
    requested_by: Mapped[uuid.UUID | None] = _user_fk()
    result: Mapped[dict[str, Any]] = mapped_column(default=dict)
    rollback_plan: Mapped[dict[str, Any]] = mapped_column(default=dict)
    executed_at: Mapped[datetime | None]
    rolled_back_at: Mapped[datetime | None]


class Approval(UUIDPrimaryKey, Base):
    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint(in_values("status", APPROVAL_STATUSES), name="status"),
        Index("ix_approvals_org_status", "organization_id", "status"),
        Index("ix_approvals_action", "response_action_id"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    response_action_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("response_actions.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(String(16), default="pending")
    requested_by: Mapped[uuid.UUID | None] = _user_fk()
    decided_by: Mapped[uuid.UUID | None] = _user_fk()
    decided_at: Mapped[datetime | None]
    comment: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


# --------------------------------------------------------------------- automation & reporting
class Integration(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    organization_id: Mapped[uuid.UUID] = _org_fk()
    provider: Mapped[str] = mapped_column(String(48))  # n8n, firewall, abuseipdb, urlhaus, ...
    name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(16), default="disabled")
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)  # non-secret settings only
    secret_ref: Mapped[str | None] = mapped_column(String(120))  # name of env var / vault key
    last_sync_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID | None] = _user_fk()


class AutomationWorkflow(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "automation_workflows"
    __table_args__ = (Index("ix_automation_workflows_org", "organization_id"),)

    organization_id: Mapped[uuid.UUID] = _org_fk()
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("integrations.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str | None] = mapped_column(Text)
    trigger_type: Mapped[str] = mapped_column(String(16))  # event, schedule, manual, webhook
    trigger_config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    external_workflow_id: Mapped[str | None] = mapped_column(String(120))  # e.g. n8n workflow id
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    last_run_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID | None] = _user_fk()


class Report(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint(in_values("status", REPORT_STATUSES), name="status"),
        Index("ix_reports_org_created", "organization_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = _org_fk()
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(255))
    report_type: Mapped[str] = mapped_column(String(32))  # incident, executive, compliance, ...
    status: Mapped[str] = mapped_column(String(16), default="draft")
    content: Mapped[dict[str, Any]] = mapped_column(default=dict)
    is_ai_generated: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    generated_by: Mapped[uuid.UUID | None] = _user_fk()


# Tables protected by the tenant_isolation RLS policy (organization_id = current org).
TENANT_TABLES: tuple[str, ...] = (
    "devices",
    "enrollment_tokens",
    "cameras",
    "sensors",
    "network_assets",
    "security_events",
    "incidents",
    "alerts",
    "investigations",
    "threat_indicators",
    "evidence",
    "agent_runs",
    "agent_decisions",
    "response_actions",
    "approvals",
    "integrations",
    "automation_workflows",
    "reports",
)
