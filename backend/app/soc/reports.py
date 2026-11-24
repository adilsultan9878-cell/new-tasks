"""Deterministic incident and executive reports (Markdown + structured metrics).

Every number comes from the organization's own records; nothing is AI-written
(``reports.is_ai_generated`` stays false).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from statistics import mean
from typing import Any

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    AgentRun,
    Alert,
    Approval,
    Device,
    Evidence,
    Incident,
    Organization,
    Report,
    ResponseAction,
    User,
)
from app.models.identity import SEVERITIES
from app.services import audit, realtime
from app.soc.common import aware, now


def _cell(value: Any) -> str:
    return " ".join(str(value if value is not None else "—").replace("|", "\\|").split())


def _hours(delta: timedelta | None) -> str:
    if delta is None:
        return "—"
    hours = delta.total_seconds() / 3600
    return f"{hours * 60:.0f} min" if hours < 1 else f"{hours:.1f} h"


def _avg(deltas: list[timedelta]) -> timedelta | None:
    return timedelta(seconds=mean(d.total_seconds() for d in deltas)) if deltas else None


def _fmt(value: datetime | None) -> str:
    value = aware(value)
    return f"{value:%Y-%m-%d %H:%M} UTC" if value else "—"


# ------------------------------------------------------------------------------- incident
def incident_report(db: Session, org: Organization, incident: Incident) -> tuple[str, dict[str, Any]]:
    org_id = org.id
    alerts = db.scalars(
        select(Alert)
        .where(Alert.organization_id == org_id, Alert.incident_id == incident.id)
        .order_by(Alert.created_at)
    ).all()
    actions = db.scalars(
        select(ResponseAction)
        .where(ResponseAction.organization_id == org_id, ResponseAction.incident_id == incident.id)
        .order_by(ResponseAction.created_at)
    ).all()
    approvals = {
        a.response_action_id: a
        for a in db.scalars(
            select(Approval).where(
                Approval.organization_id == org_id,
                Approval.response_action_id.in_([x.id for x in actions] or [uuid.uuid4()]),
            )
        )
    }
    evidence = db.scalars(
        select(Evidence)
        .where(Evidence.organization_id == org_id, Evidence.incident_id == incident.id)
        .order_by(Evidence.collected_at)
    ).all()
    triage = db.scalars(
        select(AgentRun)
        .where(
            AgentRun.organization_id == org_id,
            AgentRun.subject_type == "alert",
            AgentRun.subject_id.in_([a.id for a in alerts] or [uuid.uuid4()]),
        )
        .order_by(AgentRun.created_at.desc())
    ).all()
    users = {
        u.id: u.full_name
        for u in db.scalars(
            select(User).where(
                User.id.in_(
                    {
                        x
                        for x in [
                            incident.opened_by,
                            incident.assigned_to,
                            *[a.requested_by for a in actions],
                            *[p.decided_by for p in approvals.values()],
                            *[e.collected_by for e in evidence],
                        ]
                        if x
                    }
                )
            )
        )
    }
    duration = (aware(incident.closed_at) or now()) - aware(incident.opened_at)  # type: ignore[operator]

    lines = [
        f"# Incident report — {incident.reference}: {_cell(incident.title)}",
        "",
        f"- **Organization:** {_cell(org.name)}",
        f"- **Severity:** {incident.severity} · **Status:** {incident.status}",
        f"- **Opened:** {_fmt(incident.opened_at)} by {_cell(users.get(incident.opened_by, 'system'))}",
        f"- **Closed:** {_fmt(incident.closed_at)}" + ("" if incident.closed_at else " (still open)"),
        f"- **Duration:** {_hours(duration)}",
        f"- **Assigned to:** {_cell(users.get(incident.assigned_to, 'unassigned'))}",
        f"- **Generated:** {_fmt(now())} — deterministic report, no AI-written text",
        "",
        "## Summary",
        "",
        incident.summary or "_No summary written._",
        "",
        f"## Alerts ({len(alerts)})",
        "",
    ]
    if alerts:
        lines += ["| Raised | Severity | Alert | Rule | Status | Brain triage |", "|---|---|---|---|---|---|"]
        latest = {}
        for run in triage:
            latest.setdefault(run.subject_id, run)
        for a in alerts:
            run = latest.get(a.id)
            tri = (
                f"{(run.output_summary or {}).get('priority') or ''} {run.risk_score}/100".strip()
                if run
                else "—"
            )
            lines.append(
                f"| {_fmt(a.created_at)} | {a.severity} | {_cell(a.title)} | {_cell(a.detection_rule)} | {a.status} | {tri} |"
            )
    else:
        lines.append("No alerts linked.")
    lines += ["", f"## Response actions ({len(actions)})", ""]
    if actions:
        lines += [
            "| Action | Impact | Status | Requested by | Decision | Executed |",
            "|---|---|---|---|---|---|",
        ]
        for x in actions:
            p = approvals.get(x.id)
            decision = (
                f"{p.status} by {_cell(users.get(p.decided_by, '—'))}"
                if p and p.decided_by
                else (p.status if p else "no approval needed")
            )
            lines.append(
                f"| {_cell(x.title)} | {x.impact} | {x.status} | {_cell(users.get(x.requested_by, 'system'))} | "
                f"{decision} | {_fmt(x.executed_at)} |"
            )
    else:
        lines.append("No response actions.")
    lines += ["", f"## Evidence ({len(evidence)})", ""]
    if evidence:
        lines += [
            "| Item | Type | SHA-256 | Size | Collected | Custody entries |",
            "|---|---|---|---|---|---|",
        ]
        for e in evidence:
            lines.append(
                f"| {_cell(e.title)} | {e.evidence_type} | `{e.sha256}` | {e.size_bytes or '—'} | "
                f"{_fmt(e.collected_at)} by {_cell(users.get(e.collected_by, '—'))} | {len(e.chain_of_custody or [])} |"
            )
    else:
        lines.append("No evidence collected.")
    lines += ["", "## Timeline", ""]
    for t in incident.timeline or []:
        lines.append(
            f"- {t['at'][:16].replace('T', ' ')} UTC — **{_cell(t.get('actor', 'system'))}**: {_cell(t['text'])}"
        )
    lines.append("")
    metrics = {
        "alerts": len(alerts),
        "actions": len(actions),
        "evidence": len(evidence),
        "duration_hours": round(duration.total_seconds() / 3600, 2),
    }
    return "\n".join(lines), metrics


# ------------------------------------------------------------------------------ executive
def executive_report(db: Session, org: Organization, days: int) -> tuple[str, dict[str, Any]]:
    org_id = org.id
    since = now() - timedelta(days=days)
    alerts = db.scalars(
        select(Alert).where(
            Alert.organization_id == org_id, Alert.is_simulated.is_(False), Alert.created_at >= since
        )
    ).all()
    by_sev = {s: sum(1 for a in alerts if a.severity == s) for s in reversed(SEVERITIES)}
    tta = _avg([aware(a.acknowledged_at) - aware(a.created_at) for a in alerts if a.acknowledged_at])  # type: ignore[operator]
    closed_alerts = [a for a in alerts if a.status in ("resolved", "false_positive")]
    fp_rate = (
        round(100 * sum(1 for a in closed_alerts if a.status == "false_positive") / len(closed_alerts))
        if closed_alerts
        else None
    )

    opened = db.scalars(
        select(Incident).where(
            Incident.organization_id == org_id, Incident.is_simulated.is_(False), Incident.opened_at >= since
        )
    ).all()
    closed = db.scalars(
        select(Incident).where(
            Incident.organization_id == org_id, Incident.is_simulated.is_(False), Incident.closed_at >= since
        )
    ).all()
    open_now = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(
                Incident.organization_id == org_id,
                Incident.is_simulated.is_(False),
                Incident.status != "closed",
            )
        )
        or 0
    )
    ttr = _avg([aware(i.closed_at) - aware(i.opened_at) for i in closed if i.closed_at])  # type: ignore[operator]

    actions = db.scalars(
        select(ResponseAction).where(
            ResponseAction.organization_id == org_id, ResponseAction.created_at >= since
        )
    ).all()
    by_status: dict[str, int] = {}
    for x in actions:
        by_status[x.status] = by_status.get(x.status, 0) + 1
    risky = db.execute(
        select(Device.name, Device.risk_score)
        .where(
            Device.organization_id == org_id,
            Device.risk_score.is_not(None),
            Device.enrollment_status == "enrolled",
        )
        .order_by(Device.risk_score.desc())
        .limit(5)
    ).all()
    posture = db.scalar(
        select(AgentRun)
        .where(AgentRun.organization_id == org_id, AgentRun.subject_type == "organization")
        .order_by(AgentRun.created_at.desc())
        .limit(1)
    )

    metrics = {
        "period_days": days,
        "alerts": len(alerts),
        "alerts_by_severity": by_sev,
        "mean_time_to_acknowledge_hours": round(tta.total_seconds() / 3600, 2) if tta else None,
        "false_positive_rate_percent": fp_rate,
        "incidents_opened": len(opened),
        "incidents_closed": len(closed),
        "incidents_open_now": open_now,
        "mean_time_to_resolve_hours": round(ttr.total_seconds() / 3600, 2) if ttr else None,
        "actions": len(actions),
        "actions_by_status": by_status,
        "riskiest_devices": [{"name": n, "risk_score": s} for n, s in risky],
        "posture": {
            "risk_score": posture.risk_score,
            "risk_level": posture.risk_level,
            "coverage": posture.coverage,
            "at": aware(posture.created_at).isoformat(),
        }
        if posture
        else None,  # type: ignore[union-attr]
    }
    lines = [
        f"# Executive security summary — {_cell(org.name)}",
        "",
        f"Period: last {days} days (to {_fmt(now())}). Deterministic report from the organization's own records; "
        "simulated data is excluded and no text is AI-written.",
        "",
        "## Headline numbers",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Alerts raised | {len(alerts)} |",
        f"| Mean time to acknowledge | {_hours(tta)} |",
        f"| False-positive rate (closed alerts) | {f'{fp_rate}%' if fp_rate is not None else '—'} |",
        f"| Incidents opened / closed | {len(opened)} / {len(closed)} |",
        f"| Incidents open now | {open_now} |",
        f"| Mean time to resolve | {_hours(ttr)} |",
        f"| Response actions | {len(actions)} ({', '.join(f'{k.replace(chr(95), chr(32))} {v}' for k, v in sorted(by_status.items())) or 'none'}) |",
        "",
        "## Alerts by severity",
        "",
        "| " + " | ".join(by_sev) + " |",
        "|" + "---|" * len(by_sev),
        "| " + " | ".join(str(v) for v in by_sev.values()) + " |",
        "",
        "## Posture",
        "",
        (
            f"Latest Security Brain organization score: **{posture.risk_score}/100 ({posture.risk_level})**, "
            f"{posture.coverage}% data coverage, {_fmt(posture.created_at)}."
            if posture
            else "The organization has not been analysed by the Security Brain yet."
        ),
        "",
        "## Highest-risk devices",
        "",
    ]
    lines += [f"- {_cell(n)}: {s}/100" for n, s in risky] or ["No device has been analysed yet."]
    lines.append("")
    return "\n".join(lines), metrics


def create(
    db: Session,
    request: Request,
    *,
    org_id: uuid.UUID,
    user: User,
    report_type: str,
    incident: Incident | None,
    period_days: int,
) -> Report:
    org = db.get(Organization, org_id)
    assert org is not None
    if report_type == "incident":
        assert incident is not None
        markdown, metrics = incident_report(db, org, incident)
        title = f"Incident report — {incident.reference}"
    else:
        markdown, metrics = executive_report(db, org, period_days)
        title = f"Executive summary — last {period_days} days"
    report = Report(
        id=uuid.uuid4(),
        organization_id=org_id,
        incident_id=incident.id if incident else None,
        title=title,
        report_type=report_type,
        status="ready",
        content={"markdown": markdown, "metrics": metrics, "generated_at": now().isoformat()},
        is_ai_generated=False,
        generated_by=user.id,
    )
    db.add(report)
    db.flush()
    audit.record(
        db,
        "report.generate",
        request=request,
        actor_id=user.id,
        org_id=org_id,
        target_type="report",
        target_id=report.id,
        details={"type": report_type},
    )
    realtime.queue_broadcast(db, org_id, "report.created", {"id": str(report.id), "title": title})
    return report
