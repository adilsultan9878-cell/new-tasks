from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import get_settings
from app.models.operations import EVENT_CATEGORIES
from app.schemas.common import APIModel

Severity = Literal["info", "low", "medium", "high", "critical"]


class EventIn(BaseModel):
    """A single security event as submitted by an agent or an analyst."""

    model_config = ConfigDict(extra="ignore")

    event_type: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9]+([._][a-z0-9]+)*$")
    category: str
    severity: Severity = "info"
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    occurred_at: datetime | None = None
    # Optional stable key from the sender for de-duplication (hashed with the device id).
    dedup_key: str | None = Field(default=None, max_length=200)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("category")
    @classmethod
    def _category(cls, value: str) -> str:
        if value not in EVENT_CATEGORIES:
            raise ValueError(f"must be one of: {', '.join(EVENT_CATEGORIES)}")
        return value

    @field_validator("title")
    @classmethod
    def _title(cls, value: str) -> str:
        return " ".join(value.split())

    @field_validator("occurred_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value

    @field_validator("raw")
    @classmethod
    def _raw_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        limit = get_settings().ingest_max_raw_bytes
        if len(json.dumps(value, default=str)) > limit:
            raise ValueError(f"raw payload exceeds {limit} bytes")
        return value


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="ignore")

    events: list[EventIn] = Field(min_length=1)

    @field_validator("events")
    @classmethod
    def _batch(cls, value: list[EventIn]) -> list[EventIn]:
        limit = get_settings().ingest_max_events_per_batch
        if len(value) > limit:
            raise ValueError(f"at most {limit} events per batch")
        return value


class ManualEventIn(EventIn):
    device_id: uuid.UUID | None = None


class RejectedEvent(APIModel):
    index: int
    reason: str


class IngestResult(APIModel):
    accepted: int
    deduplicated: int
    rejected: list[RejectedEvent]
    alerts_created: int
    event_ids: list[uuid.UUID]


class EventOut(APIModel):
    id: uuid.UUID
    device_id: uuid.UUID | None
    device_name: str | None = None
    source: str
    category: str
    event_type: str
    severity: str
    status: str
    title: str
    occurred_at: datetime
    ingested_at: datetime
    occurrence_count: int
    last_occurred_at: datetime | None
    is_simulated: bool


class TriageSummary(APIModel):
    run_id: uuid.UUID
    risk_score: int | None
    risk_level: str | None
    priority: str | None
    created_at: datetime


class AlertOut(APIModel):
    id: uuid.UUID
    event_id: uuid.UUID | None
    title: str
    description: str | None
    severity: str
    status: str
    risk_score: int | None
    detection_rule: str | None
    created_at: datetime
    # Latest Security Brain triage of this alert (null until analysed).
    triage: TriageSummary | None = None


class EventDetail(EventOut):
    description: str | None
    raw: dict[str, Any]
    normalized: dict[str, Any]
    alerts: list[AlertOut]


class EventStatusUpdate(APIModel):
    status: Literal["new", "triaged", "closed"]
