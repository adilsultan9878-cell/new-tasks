from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import APIModel
from app.schemas.events import AlertOut

Severity = Literal["info", "low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "investigating", "contained", "eradicated", "recovered", "closed"]
ActionType = Literal[
    "notify_team", "heighten_monitoring", "block_indicator", "revoke_device", "suspend_member"
]


def _clean(value: str | None) -> str | None:
    return " ".join(value.split()) if value is not None else None


# ------------------------------------------------------------------------------- incidents
class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    severity: Severity | None = None  # default: highest severity of the linked alerts
    summary: str | None = Field(default=None, max_length=8000)
    alert_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)

    _t = field_validator("title")(_clean)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    status: IncidentStatus | None = None
    severity: Severity | None = None
    summary: str | None = Field(default=None, max_length=8000)
    assigned_to: uuid.UUID | None = None
    unassign: bool = False

    _t = field_validator("title")(_clean)


class NoteCreate(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class LinkAlerts(BaseModel):
    alert_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)


class AlertUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved", "false_positive"]


class TimelineEntry(APIModel):
    at: str
    kind: str
    text: str
    actor: str | None = None
    actor_id: str | None = None
    data: dict[str, Any] | None = None


class IncidentOut(APIModel):
    id: uuid.UUID
    reference: str
    title: str
    summary: str | None
    severity: str
    status: str
    assigned_to: uuid.UUID | None
    assignee_name: str | None = None
    opened_by: uuid.UUID | None
    opened_at: datetime
    closed_at: datetime | None
    updated_at: datetime
    alert_count: int = 0
    pending_actions: int = 0


# -------------------------------------------------------------------------- response actions
class ActionCreate(BaseModel):
    action_type: ActionType
    target: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = Field(default=None, max_length=2000)
    incident_id: uuid.UUID | None = None
    agent_run_id: uuid.UUID | None = None

    @field_validator("target")
    @classmethod
    def _small(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 5 or any(len(str(v)) > 2048 for v in value.values()):
            raise ValueError("target is too large")
        return value


class Decision(BaseModel):
    approve: bool
    comment: str | None = Field(default=None, max_length=1000)


class ApprovalOut(APIModel):
    id: uuid.UUID
    status: str
    requested_by: uuid.UUID | None
    decided_by: uuid.UUID | None
    decided_by_name: str | None = None
    decided_at: datetime | None
    comment: str | None
    expires_at: datetime | None


class ActionOut(APIModel):
    id: uuid.UUID
    incident_id: uuid.UUID | None
    incident_reference: str | None = None
    proposed_by_run_id: uuid.UUID | None
    action_type: str
    title: str | None
    reason: str | None
    impact: str
    reversible: bool
    requires_approval: bool
    status: str
    target: dict[str, Any]
    result: dict[str, Any]
    requested_by: uuid.UUID | None
    requested_by_name: str | None = None
    executed_at: datetime | None
    rolled_back_at: datetime | None
    created_at: datetime
    approval: ApprovalOut | None = None


class ActionTypeOut(APIModel):
    key: str
    title: str
    impact: str
    reversible: bool
    description: str
    target_fields: list[str]


class EmergencyStop(APIModel):
    engaged: bool
    reason: str | None = None
    at: str | None = None
    actor: str | None = None
    actor_id: str | None = None


class EmergencyStopUpdate(BaseModel):
    engaged: bool
    reason: str | None = Field(default=None, max_length=500)


class ResponseStatus(APIModel):
    emergency_stop: EmergencyStop
    pending_approvals: int
    approvers: int
    action_types: list[ActionTypeOut]


# --------------------------------------------------------------------------------- evidence
class EvidenceCreate(BaseModel):
    kind: Literal["file", "note", "external"]
    title: str = Field(min_length=2, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    filename: str | None = Field(default=None, max_length=255)
    content_type: str | None = Field(default=None, max_length=120)
    content_base64: str | None = Field(default=None, max_length=34_000_000)
    note: str | None = Field(default=None, max_length=100_000)
    sha256: str | None = Field(default=None, max_length=64)
    size_bytes: int | None = Field(default=None, ge=0)

    _t = field_validator("title")(_clean)

    @field_validator("filename")
    @classmethod
    def _filename(cls, value: str | None) -> str | None:
        if value is None:
            return None
        name = value.replace("\\", "/").rsplit("/", 1)[-1].strip()
        return "".join(c for c in name if c.isprintable())[:255] or None


class CustodyEntry(APIModel):
    at: str
    action: str
    actor: str | None = None
    actor_id: str | None = None
    note: str | None = None
    sha256: str | None = None
    result: str | None = None


class EvidenceOut(APIModel):
    id: uuid.UUID
    incident_id: uuid.UUID | None
    incident_reference: str | None = None
    evidence_type: str
    title: str | None
    description: str | None
    filename: str | None
    content_type: str | None
    sha256: str | None
    size_bytes: int | None
    stored: bool
    collected_by: uuid.UUID | None
    collected_at: datetime
    chain_of_custody: list[CustodyEntry]


class VerifyResult(APIModel):
    intact: bool
    expected: str | None
    actual: str
    evidence: EvidenceOut


# ---------------------------------------------------------------------------------- reports
class ReportCreate(BaseModel):
    report_type: Literal["incident", "executive"]
    incident_id: uuid.UUID | None = None
    period_days: int = Field(default=30, ge=1, le=365)


class ReportOut(APIModel):
    id: uuid.UUID
    incident_id: uuid.UUID | None
    title: str
    report_type: str
    status: str
    is_ai_generated: bool
    generated_by: uuid.UUID | None
    created_at: datetime


class ReportDetail(ReportOut):
    markdown: str
    metrics: dict[str, Any]


class IncidentDetail(IncidentOut):
    timeline: list[TimelineEntry]
    alerts: list[AlertOut]
    actions: list[ActionOut]
    evidence: list[EvidenceOut]
    reports: list[ReportOut]
