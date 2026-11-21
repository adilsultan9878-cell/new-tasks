"""Run NEXUS ZERO investigations and persist them with full provenance."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.rate_limit import enforce
from app.intel import domain as domain_intel
from app.intel import email_headers, hashes, ip, url
from app.intel.findings import Analysis, Finding
from app.models import Investigation, ThreatIndicator
from app.schemas.events import EventIn
from app.services import audit, realtime
from app.services import events as event_service

ANALYZERS = {
    "url": url.analyze,
    "domain": domain_intel.analyze,
    "ip": ip.analyze,
    "hash": hashes.analyze,
    "email": email_headers.analyze,
}
EVENT_CATEGORY = {
    "url": "phishing",
    "email": "phishing",
    "hash": "malware",
    "ip": "network",
    "domain": "network",
}
VERDICT_LABEL = {
    "malicious": "Malicious",
    "suspicious": "Suspicious",
    "unknown": "No known threat found",
    "benign": "Benign",
}


def _now() -> datetime:
    return datetime.now(UTC)


def _title(subject_type: str, subject: str) -> str:
    label = {"url": "URL", "domain": "Domain", "ip": "IP", "hash": "File hash", "email": "Email"}[
        subject_type
    ]
    return f"{label}: {subject[:200]}"


def _watchlist(db: Session, org_id: uuid.UUID, analysis: Analysis) -> None:
    values = [v.lower() for _, v in analysis.indicators]
    if not values:
        return
    rows = db.scalars(
        select(ThreatIndicator).where(
            ThreatIndicator.organization_id == org_id,
            ThreatIndicator.value.in_(values),
            ThreatIndicator.source == "analyst",
            ThreatIndicator.verdict.in_(("malicious", "suspicious")),
        )
    ).all()
    for row in rows:
        bad = row.verdict == "malicious"
        analysis.add(
            Finding(
                "watchlist",
                f"On your organization's watchlist ({row.verdict})",
                f"{row.indicator_type} {row.value}"
                + (f" — {row.context.get('note')}" if row.context.get("note") else ""),
                "high" if bad else "medium",
                60 if bad else 30,
                "watchlist",
                "intel",
                data={"indicator_id": str(row.id)},
            )
        )


def _summary(analysis: Analysis) -> str:
    consulted = sorted({c.source for c in analysis.checks if c.status == "ok"})
    missing = sorted({c.source for c in analysis.checks if c.status == "not_configured"})
    down = sorted({c.source for c in analysis.checks if c.status == "unavailable"})
    intel = sum(1 for f in analysis.findings if f.kind == "intel" and f.score > 0)
    heur = sum(1 for f in analysis.findings if f.kind == "heuristic" and f.score > 0)
    parts = [
        f"{VERDICT_LABEL[analysis.verdict]} — risk {analysis.risk_score}/100.",
        f"{intel} intelligence finding(s) and {heur} deterministic check(s) contributed.",
    ]
    parts.append(f"Consulted: {', '.join(consulted) if consulted else 'deterministic checks only'}.")
    if missing:
        parts.append(f"Not configured: {', '.join(missing)}.")
    if down:
        parts.append(f"Unavailable: {', '.join(down)}.")
    if analysis.verdict == "unknown":
        parts.append("Absence of findings is not proof of safety.")
    return " ".join(parts)


def _upsert_indicators(
    db: Session, org_id: uuid.UUID, analysis: Analysis, investigation_id: uuid.UUID
) -> None:
    verified = any(f.kind == "intel" and f.score > 0 for f in analysis.findings)
    for kind, value in analysis.indicators[:25]:
        value = value.lower()[:2048]
        row = db.scalar(
            select(ThreatIndicator).where(
                ThreatIndicator.organization_id == org_id,
                ThreatIndicator.indicator_type == kind,
                ThreatIndicator.value == value,
            )
        )
        if row is None:
            row = ThreatIndicator(
                id=uuid.uuid4(),
                organization_id=org_id,
                indicator_type=kind,
                value=value,
                source="investigation",
                verdict="unknown",
                confidence=0,
                context={},
            )
            db.add(row)
        row.last_seen_at = _now()
        history = [*list((row.context or {}).get("investigations", []))[-9:], str(investigation_id)]
        row.context = {**(row.context or {}), "investigations": history}
        if row.source != "analyst":  # never override an analyst's decision
            row.verdict = analysis.verdict
            row.confidence = analysis.risk_score
            row.is_verified = verified


def run(
    db: Session, request: Request, *, org_id: uuid.UUID, user_id: uuid.UUID, subject_type: str, subject: str
) -> Investigation:
    enforce(
        request, "investigations", get_settings().rate_limit_investigations_per_minute, extra_key=str(user_id)
    )
    started = _now()
    try:
        analysis = ANALYZERS[subject_type](subject)
    except ValueError as exc:
        raise AppError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_subject", str(exc)) from None
    _watchlist(db, org_id, analysis)
    finished = _now()

    timeline: list[dict[str, Any]] = [
        {"at": started.isoformat(), "step": "Input validated and normalized", "status": "ok"}
    ]
    timeline += [
        {
            "at": finished.isoformat(),
            "step": f"Source: {c.source}",
            "status": c.status,
            "detail": c.detail,
            "duration_ms": c.duration_ms,
        }
        for c in analysis.checks
    ]
    timeline.append(
        {
            "at": finished.isoformat(),
            "step": f"Risk scored {analysis.risk_score}/100 → {analysis.verdict}",
            "status": "ok",
        }
    )

    inv = Investigation(
        id=uuid.uuid4(),
        organization_id=org_id,
        subject_type=subject_type,
        subject=analysis.subject[:2048],
        title=_title(subject_type, analysis.subject),
        status="completed",
        verdict=analysis.verdict,
        risk_score=analysis.risk_score,
        summary=_summary(analysis),
        verified_findings=[f.as_dict() for f in sorted(analysis.findings, key=lambda f: -f.score)],
        ai_assessment=None,  # Phase 4: optional, always labelled as AI-generated
        timeline=timeline,
        details={
            **analysis.details,
            "checks": [c.__dict__ for c in analysis.checks],
            "indicators": [{"type": k, "value": v} for k, v in analysis.indicators[:25]],
        },
        created_by=user_id,
        started_at=started,
        completed_at=finished,
    )
    db.add(inv)
    db.flush()
    _upsert_indicators(db, org_id, analysis, inv.id)

    if analysis.verdict in ("malicious", "suspicious"):
        event_service.ingest(
            db,
            org_id,
            [
                EventIn(
                    event_type=f"intel.{subject_type}_{analysis.verdict}",
                    category=EVENT_CATEGORY[subject_type],
                    severity="high" if analysis.verdict == "malicious" else "medium",
                    title=f"{VERDICT_LABEL[analysis.verdict]} {subject_type} investigated: {analysis.subject[:150]}",
                    description=inv.summary,
                    dedup_key=f"investigation:{subject_type}:{analysis.subject[:150]}",
                    raw={"investigation_id": str(inv.id), "risk_score": analysis.risk_score},
                )
            ],
            source="integration",
        )

    audit.record(
        db,
        "investigation.run",
        request=request,
        actor_id=user_id,
        org_id=org_id,
        target_type="investigation",
        target_id=inv.id,
        details={"subject_type": subject_type, "verdict": analysis.verdict, "risk": analysis.risk_score},
    )
    realtime.queue_broadcast(
        db,
        org_id,
        "investigation.completed",
        {"id": str(inv.id), "title": inv.title, "verdict": inv.verdict, "risk_score": inv.risk_score},
    )
    return inv
