from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.lab.rules import Rule
from app.models.operations import EVENT_CATEGORIES
from app.schemas.common import APIModel
from app.schemas.events import Severity


def _clean(value: str | None) -> str | None:
    return " ".join(value.split()) if value is not None else None


class DatasetFromEvents(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    days: int = Field(default=30, ge=1, le=365)
    include_simulated: bool = False

    _n = field_validator("name")(_clean)


class UploadRow(BaseModel):
    id: str | None = Field(default=None, max_length=64)
    occurred_at: datetime
    category: str
    event_type: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9]+([._][a-z0-9]+)*$")
    severity: Severity
    title: str = Field(min_length=1, max_length=255)
    source: str | None = Field(default=None, max_length=32)
    device: str | None = Field(default=None, max_length=120)
    count: int = Field(default=1, ge=1, le=1_000_000)
    label: Literal["malicious", "benign"] | None = None

    @field_validator("category")
    @classmethod
    def _category(cls, value: str) -> str:
        if value not in EVENT_CATEGORIES:
            raise ValueError(f"must be one of: {', '.join(EVENT_CATEGORIES)}")
        return value


class DatasetUpload(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    rows: list[UploadRow] = Field(min_length=1, max_length=5000)

    _n = field_validator("name")(_clean)


class DatasetOut(APIModel):
    id: uuid.UUID
    name: str
    description: str | None
    source: str
    params: dict[str, Any]
    row_count: int
    label_counts: dict[str, int]
    sha256: str
    includes_simulated: bool
    created_by_name: str | None = None
    created_at: datetime
    experiments: int = 0


class DatasetDetail(DatasetOut):
    preview: list[dict[str, Any]]


class ExperimentIn(BaseModel):
    dataset_id: uuid.UUID
    name: str = Field(min_length=2, max_length=120)
    rule: Rule

    _n = field_validator("name")(_clean)


class ExperimentOut(APIModel):
    id: uuid.UUID
    dataset_id: uuid.UUID
    dataset_name: str | None = None
    name: str
    rule: dict[str, Any]
    rule_sha256: str
    dataset_sha256: str
    engine_version: str
    results: dict[str, Any]
    created_by_name: str | None = None
    created_at: datetime


class Reproduction(APIModel):
    reproduced: bool
    checks: dict[str, bool]
    engine_version: str
