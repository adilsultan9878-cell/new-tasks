from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import APIModel

SubjectType = Literal["alert", "device", "organization"]


class RunCreate(BaseModel):
    subject_type: SubjectType
    subject_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _subject(self) -> RunCreate:
        if self.subject_type == "organization":
            self.subject_id = None  # the organization in the URL is the subject
        elif self.subject_id is None:
            raise ValueError(f"subject_id is required for a {self.subject_type} analysis")
        return self


class FactorOut(APIModel):
    key: str
    label: str
    agent: str
    points: int
    max_points: int
    has_data: bool
    evidence: str


class TraceOut(APIModel):
    seq: int
    agent: str
    tool: str
    args: dict[str, Any]
    rows: int
    duration_ms: float


class EvidenceRef(APIModel):
    type: str
    id: str
    label: str = ""


class ProposalOut(APIModel):
    action_type: str
    target: dict[str, Any]


class RecommendationOut(APIModel):
    code: str
    text: str
    urgency: Literal["now", "soon", "later"]
    changes_system: bool
    agent: str
    because: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    proposal: ProposalOut | None = None


class DecisionOut(APIModel):
    id: uuid.UUID
    agent_run_id: uuid.UUID
    decision_type: str
    agent_name: str | None
    severity: str | None
    summary: str
    rationale: str | None
    confidence: int | None
    is_ai_generated: bool
    evidence_refs: list[EvidenceRef]
    created_at: datetime


class DecisionWithRun(DecisionOut):
    subject_type: str | None
    subject_label: str | None


class RunOut(APIModel):
    id: uuid.UUID
    agent_name: str
    trigger: str
    status: str
    model_provider: str | None
    subject_type: str | None
    subject_id: uuid.UUID | None
    subject_label: str | None
    risk_score: int | None
    risk_level: str | None
    coverage: int | None
    priority: str | None
    summary: str | None
    finding_count: int
    recommendation_count: int
    created_by: uuid.UUID | None
    created_at: datetime
    finished_at: datetime | None


class RunDetail(RunOut):
    factors: list[FactorOut]
    trace: list[TraceOut]
    recommendations: list[RecommendationOut]
    decisions: list[DecisionOut]
    agents: list[str]
    lookback_days: int | None
    engine_version: str | None


class AgentOut(APIModel):
    name: str
    title: str
    description: str
    subjects: list[str]
    tools: list[str]


class ToolOut(APIModel):
    name: str
    description: str


class FactorModelOut(APIModel):
    key: str
    label: str
    max_points: int
    agent: str
    description: str


class EngineOut(APIModel):
    provider: str
    mode: str
    model: str | None
    ai_enabled: bool
    engine_version: str
    description: str


class BrainStatus(APIModel):
    engine: EngineOut
    auto_triage: bool
    lookback_days: int
    agents: list[AgentOut]
    tools: list[ToolOut]
    models: dict[str, list[FactorModelOut]]


class AgentActivity(APIModel):
    agent: str
    findings: int
    recommendations: int
    last_decision_at: datetime | None


class BrainActivity(APIModel):
    runs_total: int
    runs_by_trigger: dict[str, int]
    agents: list[AgentActivity]
