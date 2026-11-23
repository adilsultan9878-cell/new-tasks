"""Security Brain orchestrator: resolve the subject, run the planned agents, score, persist.

The orchestrator is the only part of the Brain that writes: it stores the run, its decisions
and (for a device) the device's latest risk score, records an audit entry and broadcasts the
result. Agents themselves only read through the toolbox.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.brain import report
from app.brain.agents import AGENTS, Context, Finding
from app.brain.engine import ENGINE_VERSION, engine_info
from app.brain.playbook import recommend
from app.brain.scoring import Score, compute
from app.brain.toolbox import Toolbox
from app.core.config import get_settings
from app.core.errors import not_found
from app.models import AgentDecision, AgentRun, Device, Organization
from app.services import audit, realtime

log = logging.getLogger(__name__)

PLANS: dict[str, tuple[str, ...]] = {
    "alert": ("triage", "device", "exposure", "intel"),
    "device": ("device", "exposure", "intel"),
    "organization": ("posture", "exposure", "intel"),
}


def _resolve(
    tb: Toolbox, subject_type: str, subject_id: uuid.UUID | None, org_name: str
) -> tuple[Context, str]:
    ctx = Context(subject_type=subject_type, lookback_days=get_settings().brain_lookback_days)
    if subject_type == "alert":
        alert = tb.get_alert(subject_id) if subject_id else None
        if alert is None:
            raise not_found("Alert")
        ctx.alert = alert
        if alert["event_id"]:
            ctx.event = tb.get_event(uuid.UUID(alert["event_id"]))
        if ctx.event and ctx.event["device_id"]:
            ctx.device = tb.get_device(uuid.UUID(ctx.event["device_id"]))
        return ctx, alert["title"]
    if subject_type == "device":
        device = tb.get_device(subject_id) if subject_id else None
        if device is None:
            raise not_found("Device")
        ctx.device = device
        return ctx, device["name"]
    return ctx, org_name


def _summary(subject_type: str, score: Score) -> str:
    drivers = sorted((f for f in score.factors if f["points"]), key=lambda f: -f["points"])[:3]
    text = f"Risk {score.score}/100 ({score.level})"
    if subject_type == "alert":
        text += f", priority {score.priority}"
    text += f", with {score.coverage}% data coverage. "
    if drivers:
        text += (
            "Main drivers: "
            + ", ".join(f"{f['label'].lower()} {f['points']}/{f['max_points']}" for f in drivers)
            + "."
        )
    else:
        text += "No risk factor was triggered by the available data."
    missing = [f["label"].lower() for f in score.factors if not f["has_data"]]
    if missing:
        text += " No data for: " + ", ".join(missing) + "."
    return text


def _decisions(
    run: AgentRun, subject_type: str, score: Score, findings: list[Finding], recs: list[dict[str, Any]]
) -> list[AgentDecision]:
    def make(**kw: Any) -> AgentDecision:
        return AgentDecision(
            id=uuid.uuid4(),
            organization_id=run.organization_id,
            agent_run_id=run.id,
            is_ai_generated=False,
            **kw,
        )

    rows = [
        make(
            decision_type="score",
            agent_name="orchestrator",
            severity=score.level,
            summary=f"Risk score {score.score}/100 — {score.level}",
            rationale="; ".join(
                f"{f['label']}: {f['points']}/{f['max_points']}"
                if f["has_data"]
                else f"{f['label']}: no data"
                for f in score.factors
            ),
            evidence_refs=[],
        )
    ]
    if subject_type == "alert":
        rows.append(
            make(
                decision_type="classify",
                agent_name="orchestrator",
                severity=score.level,
                summary=f"Triage priority {score.priority}",
                rationale="Priority follows the risk level: P1 critical (75+), P2 high (50+), P3 medium (25+), "
                "P4 below 25.",
                evidence_refs=[],
            )
        )
    rows += [
        make(
            decision_type="finding",
            agent_name=f.agent,
            severity=f.severity,
            summary=f.title[:2000],
            rationale=f.detail[:4000] or None,
            evidence_refs=f.evidence[:20],
        )
        for f in findings
    ]
    rows += [
        make(
            decision_type="recommend",
            agent_name=r["agent"],
            severity=None,
            summary=r["text"],
            rationale=f"Because: {r['because']}"
            + (" — changes a system, requires human approval." if r["changes_system"] else ""),
            evidence_refs=r["evidence"],
        )
        for r in recs
    ]
    return rows


def run_summary(run: AgentRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "subject_type": run.subject_type,
        "subject_id": str(run.subject_id) if run.subject_id else None,
        "subject_label": run.subject_label,
        "trigger": run.trigger,
        "risk_score": run.risk_score,
        "risk_level": run.risk_level,
        "priority": (run.output_summary or {}).get("priority"),
    }


def analyse(
    db: Session,
    *,
    org_id: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID | None,
    trigger: str,
    user_id: uuid.UUID | None = None,
    request: Request | None = None,
) -> AgentRun:
    started = datetime.now(UTC)
    org = db.scalar(select(Organization).where(Organization.id == org_id))
    if org is None:
        raise not_found("Organization")
    tb = Toolbox(db, org_id, now=started)
    ctx, label = _resolve(tb, subject_type, subject_id, org.name)

    findings: list[Finding] = []
    factor_results = {}
    plan = PLANS[subject_type]
    for name in plan:
        tb.agent = name
        result = AGENTS[name].run(ctx, tb)
        findings += result.findings
        factor_results.update(result.factors)
    tb.agent = "orchestrator"

    score = compute(subject_type, factor_results)
    recs = recommend(findings)
    summary = _summary(subject_type, score)
    finished = datetime.now(UTC)
    engine = engine_info()

    run = AgentRun(
        id=uuid.uuid4(),
        organization_id=org_id,
        agent_name="orchestrator",
        trigger=trigger,
        status="succeeded",
        model_provider=engine["provider"],
        model_name=None,
        subject_type=subject_type,
        subject_id=org_id if subject_type == "organization" else subject_id,
        subject_label=label[:255],
        created_by=user_id,
        risk_score=score.score,
        risk_level=score.level,
        coverage=score.coverage,
        factors=score.factors,
        trace=tb.trace,
        input_summary={
            "subject_type": subject_type,
            "lookback_days": ctx.lookback_days,
            "agents": list(plan),
        },
        output_summary={
            "summary": summary,
            "priority": score.priority if subject_type == "alert" else None,
            "agents": list(plan),
            "finding_count": len(findings),
            "recommendation_count": len(recs),
            "recommendations": recs,
            "findings": [f.as_dict() for f in findings],
            "engine": ENGINE_VERSION,
        },
        started_at=started,
        finished_at=finished,
        created_at=started,
    )
    run.report = report.render(
        subject_type=subject_type,
        subject_label=label,
        organization=org.name,
        generated_at=finished,
        trigger=trigger,
        score=score,
        summary=summary,
        findings=findings,
        recommendations=recs,
        trace=tb.trace,
        agents=list(plan),
    )
    db.add(run)
    db.flush()
    db.add_all(_decisions(run, subject_type, score, findings, recs))

    if subject_type == "device" and subject_id is not None:
        device = db.scalar(select(Device).where(Device.id == subject_id, Device.organization_id == org_id))
        if device is not None:
            device.risk_score = score.score

    audit.record(
        db,
        "brain.run",
        request=request,
        actor_id=user_id,
        actor_type="user" if user_id else "system",
        org_id=org_id,
        target_type=subject_type,
        target_id=run.subject_id,
        details={"run_id": str(run.id), "trigger": trigger, "risk": score.score, "level": score.level},
    )
    realtime.queue_broadcast(db, org_id, "brain.run_completed", run_summary(run))
    return run


def auto_triage(db: Session, org_id: uuid.UUID, alert_ids: list[uuid.UUID]) -> None:
    """Analyse freshly raised alerts. Never lets a Brain problem break event ingestion."""
    if not get_settings().brain_auto_triage:
        return
    for alert_id in alert_ids:
        try:
            with db.begin_nested():
                analyse(db, org_id=org_id, subject_type="alert", subject_id=alert_id, trigger="alert")
        except Exception:  # pragma: no cover - defensive: logged, ingestion continues
            log.exception("auto-triage failed for alert %s", alert_id)
