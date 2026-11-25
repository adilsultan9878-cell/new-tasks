from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import APIModel

TriggerType = Literal["event", "schedule", "manual", "webhook"]


def _clean(value: str | None) -> str | None:
    return " ".join(value.split()) if value is not None else None


# ---------------------------------------------------------------------------------- webhooks
class WebhookCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    url: str = Field(min_length=8, max_length=2048)
    provider: Literal["webhook", "n8n"] = "webhook"
    description: str | None = Field(default=None, max_length=500)

    _n = field_validator("name")(_clean)


class WebhookUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    url: str | None = Field(default=None, min_length=8, max_length=2048)
    description: str | None = Field(default=None, max_length=500)
    enabled: bool | None = None

    _n = field_validator("name")(_clean)


class WebhookOut(APIModel):
    id: uuid.UUID
    name: str
    provider: str
    url: str
    host: str
    description: str | None
    enabled: bool
    failure_count: int
    last_error: str | None
    last_success_at: datetime | None
    created_at: datetime
    used_by: int = 0


class WebhookSecret(APIModel):
    webhook: WebhookOut
    secret: str  # shown once; derived, never stored


class DeliveryOut(APIModel):
    id: uuid.UUID
    webhook_id: uuid.UUID
    run_id: uuid.UUID | None
    event_type: str
    status: str
    attempts: int
    next_attempt_at: datetime | None
    last_status_code: int | None
    last_error: str | None
    response_ms: int | None
    delivered_at: datetime | None
    is_simulated: bool
    created_at: datetime


# --------------------------------------------------------------------------------- workflows
class WorkflowIn(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    trigger_type: TriggerType
    trigger_config: dict[str, Any] = Field(default_factory=dict)
    steps: list[dict[str, Any]] = Field(min_length=1, max_length=10)
    requires_approval: bool = True
    enabled: bool = False

    _n = field_validator("name")(_clean)


class WorkflowUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    trigger_type: TriggerType | None = None
    trigger_config: dict[str, Any] | None = None
    steps: list[dict[str, Any]] | None = Field(default=None, min_length=1, max_length=10)
    requires_approval: bool | None = None
    enabled: bool | None = None

    _n = field_validator("name")(_clean)


class StepOut(APIModel):
    type: str
    title: str
    risk: str
    params: dict[str, Any]


class WorkflowOut(APIModel):
    id: uuid.UUID
    name: str
    description: str | None
    trigger_type: str
    trigger_config: dict[str, Any]
    trigger_label: str
    steps: list[StepOut]
    requires_approval: bool
    approval_forced: bool  # a step needs approval, so it cannot be switched off
    enabled: bool
    hook_path: str | None  # incoming webhook URL path (webhook trigger)
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_status: str | None
    owner_name: str | None
    created_at: datetime
    updated_at: datetime


class WorkflowSecret(APIModel):
    workflow: WorkflowOut
    secret: str
    hook_path: str


# -------------------------------------------------------------------------------------- runs
class RunStepOut(APIModel):
    type: str | None = None
    title: str | None = None
    risk: str | None = None
    status: str
    detail: str | None = None
    link: str | None = None


class RunOut(APIModel):
    id: uuid.UUID
    workflow_id: uuid.UUID
    workflow_name: str
    status: str
    trigger_kind: str
    trigger_label: str
    steps: list[RunStepOut]
    context: dict[str, Any]
    requested_by_name: str | None = None
    decided_by_name: str | None = None
    decided_at: datetime | None
    decision_comment: str | None
    expires_at: datetime | None
    error: str | None
    is_simulated: bool
    created_at: datetime
    finished_at: datetime | None


class RunDecision(BaseModel):
    approve: bool
    comment: str | None = Field(default=None, max_length=1000)


class HookAccepted(APIModel):
    run_id: uuid.UUID
    status: str


class AutomationOverview(APIModel):
    workflows: int
    enabled: int
    webhooks: int
    awaiting_approval: int
    runs_today: int
    failed_today: int
    deliveries_pending: int
    deliveries_failed: int
    signing_key: str  # dedicated | jwt | ephemeral
    delivery_enabled: bool
    private_targets_allowed: bool
    emergency_stop: bool
