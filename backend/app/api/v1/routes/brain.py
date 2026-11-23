from __future__ import annotations

import re
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select

from app.api.deps import DB, CurrentPrincipal, OrgContext, require
from app.brain.agents import AGENTS
from app.brain.engine import engine_info
from app.brain.orchestrator import analyse
from app.brain.scoring import models_catalogue
from app.brain.toolbox import TOOLS
from app.core.config import get_settings
from app.core.errors import not_found
from app.core.rate_limit import enforce
from app.models import AgentDecision, AgentRun
from app.schemas.brain import (
    AgentActivity,
    AgentOut,
    BrainActivity,
    BrainStatus,
    DecisionOut,
    DecisionWithRun,
    RunCreate,
    RunDetail,
    RunOut,
    ToolOut,
)
from app.schemas.common import Page

router = APIRouter(tags=["security-brain"])


def _run_fields(run: AgentRun) -> dict[str, Any]:
    out = run.output_summary or {}
    return {
        "id": run.id,
        "agent_name": run.agent_name,
        "trigger": run.trigger,
        "status": run.status,
        "model_provider": run.model_provider,
        "subject_type": run.subject_type,
        "subject_id": run.subject_id,
        "subject_label": run.subject_label,
        "risk_score": run.risk_score,
        "risk_level": run.risk_level,
        "coverage": run.coverage,
        "priority": out.get("priority"),
        "summary": out.get("summary"),
        "finding_count": int(out.get("finding_count") or 0),
        "recommendation_count": int(out.get("recommendation_count") or 0),
        "created_by": run.created_by,
        "created_at": run.created_at,
        "finished_at": run.finished_at,
    }


def _detail(db: DB, run: AgentRun) -> RunDetail:
    decisions = db.scalars(
        select(AgentDecision)
        .where(AgentDecision.agent_run_id == run.id, AgentDecision.organization_id == run.organization_id)
        .order_by(AgentDecision.created_at, AgentDecision.id)
    ).all()
    out = run.output_summary or {}
    return RunDetail(
        **_run_fields(run),
        factors=run.factors or [],
        trace=run.trace or [],
        recommendations=out.get("recommendations") or [],
        decisions=[DecisionOut.model_validate(d) for d in decisions],
        agents=out.get("agents") or [],
        lookback_days=(run.input_summary or {}).get("lookback_days"),
        engine_version=out.get("engine"),
    )


def _get_run(db: DB, org_id: uuid.UUID, run_id: uuid.UUID) -> AgentRun:
    run = db.scalar(select(AgentRun).where(AgentRun.id == run_id, AgentRun.organization_id == org_id))
    if run is None:
        raise not_found("Analysis")
    return run


@router.get("/brain/status", response_model=BrainStatus)
def status(_: CurrentPrincipal) -> BrainStatus:
    settings = get_settings()
    return BrainStatus(
        engine=engine_info(),
        auto_triage=settings.brain_auto_triage,
        lookback_days=settings.brain_lookback_days,
        agents=[
            AgentOut(
                name=a.name,
                title=a.title,
                description=a.description,
                subjects=list(a.subjects),
                tools=list(a.tools),
            )
            for a in AGENTS.values()
        ],
        tools=[ToolOut(name=name, description=desc) for name, desc in sorted(TOOLS.items())],
        models=models_catalogue(),
    )


@router.post("/organizations/{org_id}/brain/runs", response_model=RunDetail, status_code=201)
def create_run(
    body: RunCreate,
    ctx: Annotated[OrgContext, Depends(require("brain:run"))],
    request: Request,
    db: DB,
) -> RunDetail:
    enforce(request, "brain", get_settings().rate_limit_brain_per_minute, extra_key=str(ctx.user.id))
    run = analyse(
        db,
        org_id=ctx.org_id,
        subject_type=body.subject_type,
        subject_id=body.subject_id,
        trigger="manual",
        user_id=ctx.user.id,
        request=request,
    )
    db.commit()
    return _detail(db, run)


@router.get("/organizations/{org_id}/brain/runs", response_model=Page[RunOut])
def list_runs(
    ctx: Annotated[OrgContext, Depends(require("brain:read"))],
    db: DB,
    subject_type: Annotated[str | None, Query(pattern=r"^(alert|device|organization)$")] = None,
    subject_id: uuid.UUID | None = None,
    trigger: Annotated[str | None, Query(pattern=r"^(manual|alert)$")] = None,
    risk_level: Annotated[str | None, Query(pattern=r"^(info|low|medium|high|critical)$")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[RunOut]:
    filters = [AgentRun.organization_id == ctx.org_id, AgentRun.subject_type.is_not(None)]
    if subject_type:
        filters.append(AgentRun.subject_type == subject_type)
    if subject_id:
        filters.append(AgentRun.subject_id == subject_id)
    if trigger:
        filters.append(AgentRun.trigger == trigger)
    if risk_level:
        filters.append(AgentRun.risk_level == risk_level)
    total = db.scalar(select(func.count()).select_from(AgentRun).where(*filters)) or 0
    rows = db.scalars(
        select(AgentRun).where(*filters).order_by(AgentRun.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[RunOut](
        items=[RunOut(**_run_fields(r)) for r in rows], total=total, limit=limit, offset=offset
    )


@router.get("/organizations/{org_id}/brain/runs/{run_id}", response_model=RunDetail)
def get_run(
    run_id: uuid.UUID, ctx: Annotated[OrgContext, Depends(require("brain:read"))], db: DB
) -> RunDetail:
    return _detail(db, _get_run(db, ctx.org_id, run_id))


@router.get(
    "/organizations/{org_id}/brain/runs/{run_id}/report",
    response_class=Response,
    responses={200: {"content": {"text/markdown": {}}}},
)
def download_report(
    run_id: uuid.UUID, ctx: Annotated[OrgContext, Depends(require("brain:read"))], db: DB
) -> Response:
    run = _get_run(db, ctx.org_id, run_id)
    slug = re.sub(r"[^a-z0-9]+", "-", (run.subject_label or run.subject_type or "analysis").lower()).strip(
        "-"
    )[:40]
    filename = f"sentinel-x-{run.subject_type}-{slug or 'analysis'}-{run.created_at:%Y%m%d-%H%M}.md"
    return Response(
        content=run.report or "",
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


@router.get("/organizations/{org_id}/brain/decisions", response_model=Page[DecisionWithRun])
def list_decisions(
    ctx: Annotated[OrgContext, Depends(require("brain:read"))],
    db: DB,
    agent: Annotated[
        str | None, Query(pattern=r"^(orchestrator|triage|device|exposure|intel|posture)$")
    ] = None,
    decision_type: Annotated[str | None, Query(pattern=r"^(finding|score|classify|recommend)$")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[DecisionWithRun]:
    filters = [AgentDecision.organization_id == ctx.org_id]
    if agent:
        filters.append(AgentDecision.agent_name == agent)
    if decision_type:
        filters.append(AgentDecision.decision_type == decision_type)
    total = db.scalar(select(func.count()).select_from(AgentDecision).where(*filters)) or 0
    rows = db.execute(
        select(AgentDecision, AgentRun.subject_type, AgentRun.subject_label)
        .join(AgentRun, AgentRun.id == AgentDecision.agent_run_id)
        .where(*filters, AgentRun.organization_id == ctx.org_id)
        .order_by(AgentDecision.created_at.desc(), AgentDecision.id)
        .limit(limit)
        .offset(offset)
    ).all()
    items = [
        DecisionWithRun(**DecisionOut.model_validate(d).model_dump(), subject_type=st, subject_label=label)
        for d, st, label in rows
    ]
    return Page[DecisionWithRun](items=items, total=total, limit=limit, offset=offset)


@router.get("/organizations/{org_id}/brain/activity", response_model=BrainActivity)
def activity(ctx: Annotated[OrgContext, Depends(require("brain:read"))], db: DB) -> BrainActivity:
    by_trigger = dict(
        db.execute(
            select(AgentRun.trigger, func.count())
            .where(AgentRun.organization_id == ctx.org_id, AgentRun.subject_type.is_not(None))
            .group_by(AgentRun.trigger)
        ).all()
    )
    rows = db.execute(
        select(
            AgentDecision.agent_name,
            AgentDecision.decision_type,
            func.count(),
            func.max(AgentDecision.created_at),
        )
        .where(
            AgentDecision.organization_id == ctx.org_id,
            AgentDecision.decision_type.in_(("finding", "recommend")),
        )
        .group_by(AgentDecision.agent_name, AgentDecision.decision_type)
    ).all()
    stats: dict[str, dict[str, Any]] = {
        name: {"agent": name, "findings": 0, "recommendations": 0, "last_decision_at": None}
        for name in AGENTS
    }
    for name, kind, count, last in rows:
        if name not in stats:
            continue
        stats[name]["findings" if kind == "finding" else "recommendations"] += int(count)
        current = stats[name]["last_decision_at"]
        stats[name]["last_decision_at"] = max(filter(None, [current, last]), default=None)
    return BrainActivity(
        runs_total=sum(int(n) for n in by_trigger.values()),
        runs_by_trigger={k: int(v) for k, v in by_trigger.items()},
        agents=[AgentActivity(**s) for s in stats.values()],
    )
