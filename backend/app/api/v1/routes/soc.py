"""SENTINEL X SOC API (Phase 5): incidents, alert triage, response actions, evidence, reports."""

from __future__ import annotations

import re
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select

from app.api.deps import DB, OrgContext, require
from app.api.v1.routes.events import alerts_out
from app.core import limits
from app.core.errors import AppError, not_found
from app.models import (
    Alert,
    Approval,
    Evidence,
    Incident,
    Report,
    ResponseAction,
    ThreatIndicator,
    User,
)
from app.schemas.common import Page
from app.schemas.events import AlertOut
from app.schemas.soc import (
    ActionCreate,
    ActionOut,
    ActionTypeOut,
    AlertUpdate,
    ApprovalOut,
    Decision,
    EmergencyStop,
    EmergencyStopUpdate,
    EvidenceCreate,
    EvidenceOut,
    IncidentCreate,
    IncidentDetail,
    IncidentOut,
    IncidentUpdate,
    LinkAlerts,
    NoteCreate,
    ReportCreate,
    ReportDetail,
    ReportOut,
    ResponseStatus,
    VerifyResult,
)
from app.soc import actions as action_service
from app.soc import evidence as evidence_service
from app.soc import incidents as incident_service
from app.soc import reports as report_service
from app.soc.common import members_with

router = APIRouter(prefix="/organizations/{org_id}", tags=["soc"])

Read = Annotated[OrgContext, Depends(require("incidents:read"))]
Manage = Annotated[OrgContext, Depends(require("incidents:manage"))]


def _names(db: DB, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return {u.id: u.full_name or u.email for u in db.scalars(select(User).where(User.id.in_(wanted)))}


# ---------------------------------------------------------------------------------- outputs
def _actions_out(db: DB, org_id: uuid.UUID, rows: list[ResponseAction]) -> list[ActionOut]:
    if not rows:
        return []
    approvals: dict[uuid.UUID, Approval] = {}
    for a in db.scalars(
        select(Approval)
        .where(Approval.organization_id == org_id, Approval.response_action_id.in_([r.id for r in rows]))
        .order_by(Approval.created_at)
    ):
        approvals[a.response_action_id] = a
    refs = dict(
        db.execute(
            select(Incident.id, Incident.reference).where(
                Incident.organization_id == org_id,
                Incident.id.in_({r.incident_id for r in rows if r.incident_id} or {uuid.uuid4()}),
            )
        ).all()
    )
    names = _names(db, {r.requested_by for r in rows} | {a.decided_by for a in approvals.values()})
    out = []
    for r in rows:
        item = ActionOut.model_validate(r)
        item.incident_reference = refs.get(r.incident_id) if r.incident_id else None
        item.requested_by_name = names.get(r.requested_by) if r.requested_by else None
        appr = approvals.get(r.id)
        if appr is not None:
            item.approval = ApprovalOut.model_validate(appr)
            item.approval.decided_by_name = names.get(appr.decided_by) if appr.decided_by else None
        out.append(item)
    return out


def _evidence_out(db: DB, org_id: uuid.UUID, rows: list[Evidence]) -> list[EvidenceOut]:
    refs = (
        dict(
            db.execute(
                select(Incident.id, Incident.reference).where(
                    Incident.organization_id == org_id,
                    Incident.id.in_({r.incident_id for r in rows if r.incident_id} or {uuid.uuid4()}),
                )
            ).all()
        )
        if rows
        else {}
    )
    out = []
    for r in rows:
        item = EvidenceOut.model_validate(
            {
                **{
                    c: getattr(r, c)
                    for c in (
                        "id",
                        "incident_id",
                        "evidence_type",
                        "title",
                        "description",
                        "filename",
                        "content_type",
                        "sha256",
                        "size_bytes",
                        "collected_by",
                        "collected_at",
                        "chain_of_custody",
                    )
                },
                "stored": r.storage_uri is not None,
            }
        )
        item.incident_reference = refs.get(r.incident_id) if r.incident_id else None
        out.append(item)
    return out


def _incidents_out(db: DB, org_id: uuid.UUID, rows: list[Incident]) -> list[IncidentOut]:
    ids = [r.id for r in rows] or [uuid.uuid4()]
    alerts = dict(
        db.execute(
            select(Alert.incident_id, func.count())
            .where(Alert.organization_id == org_id, Alert.incident_id.in_(ids))
            .group_by(Alert.incident_id)
        ).all()
    )
    pending = dict(
        db.execute(
            select(ResponseAction.incident_id, func.count())
            .where(
                ResponseAction.organization_id == org_id,
                ResponseAction.incident_id.in_(ids),
                ResponseAction.status.in_(incident_service.OPEN_ACTION_STATUSES),
            )
            .group_by(ResponseAction.incident_id)
        ).all()
    )
    names = _names(db, {r.assigned_to for r in rows})
    out = []
    for r in rows:
        item = IncidentOut.model_validate(r)
        item.alert_count = int(alerts.get(r.id, 0))
        item.pending_actions = int(pending.get(r.id, 0))
        item.assignee_name = names.get(r.assigned_to) if r.assigned_to else None
        out.append(item)
    return out


def _detail(db: DB, incident: Incident) -> IncidentDetail:
    org_id = incident.organization_id
    base = _incidents_out(db, org_id, [incident])[0]
    alerts = db.scalars(
        select(Alert)
        .where(Alert.organization_id == org_id, Alert.incident_id == incident.id)
        .order_by(Alert.created_at)
    ).all()
    actions = db.scalars(
        select(ResponseAction)
        .where(ResponseAction.organization_id == org_id, ResponseAction.incident_id == incident.id)
        .order_by(ResponseAction.created_at.desc())
    ).all()
    evidence = db.scalars(
        select(Evidence)
        .where(Evidence.organization_id == org_id, Evidence.incident_id == incident.id)
        .order_by(Evidence.collected_at.desc())
    ).all()
    reports = db.scalars(
        select(Report)
        .where(Report.organization_id == org_id, Report.incident_id == incident.id)
        .order_by(Report.created_at.desc())
    ).all()
    return IncidentDetail(
        **base.model_dump(),
        timeline=list(reversed(incident.timeline or [])),
        alerts=alerts_out(db, org_id, list(alerts)),
        actions=_actions_out(db, org_id, list(actions)),
        evidence=_evidence_out(db, org_id, list(evidence)),
        reports=[ReportOut.model_validate(r) for r in reports],
    )


# -------------------------------------------------------------------------------- incidents
@router.get("/incidents", response_model=Page[IncidentOut])
def list_incidents(
    ctx: Read,
    db: DB,
    status: Annotated[
        str | None, Query(pattern=r"^(active|open|investigating|contained|eradicated|recovered|closed)$")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[IncidentOut]:
    filters = [Incident.organization_id == ctx.org_id, Incident.is_simulated.is_(False)]
    if status == "active":
        filters.append(Incident.status != "closed")
    elif status:
        filters.append(Incident.status == status)
    total = db.scalar(select(func.count()).select_from(Incident).where(*filters)) or 0
    rows = db.scalars(
        select(Incident).where(*filters).order_by(Incident.opened_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[IncidentOut](
        items=_incidents_out(db, ctx.org_id, list(rows)), total=total, limit=limit, offset=offset
    )


@router.post("/incidents", response_model=IncidentDetail, status_code=201)
def create_incident(body: IncidentCreate, ctx: Manage, request: Request, db: DB) -> IncidentDetail:
    incident = incident_service.create(
        db,
        request,
        org_id=ctx.org_id,
        user=ctx.user,
        title=body.title,
        severity=body.severity,
        summary_text=body.summary,
        alert_ids=body.alert_ids,
    )
    db.commit()
    return _detail(db, incident)


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: uuid.UUID, ctx: Read, db: DB) -> IncidentDetail:
    action_service.expire_stale(db, ctx.org_id)
    db.commit()
    return _detail(db, incident_service.get(db, ctx.org_id, incident_id))


@router.patch("/incidents/{incident_id}", response_model=IncidentDetail)
def update_incident(
    incident_id: uuid.UUID, body: IncidentUpdate, ctx: Manage, request: Request, db: DB
) -> IncidentDetail:
    incident = incident_service.get(db, ctx.org_id, incident_id)
    incident_service.update(
        db,
        request,
        incident,
        user=ctx.user,
        status_=body.status,
        severity=body.severity,
        title=body.title,
        summary_text=body.summary,
        assigned_to=body.assigned_to,
        unassign=body.unassign,
    )
    db.commit()
    return _detail(db, incident)


@router.post("/incidents/{incident_id}/notes", response_model=IncidentDetail, status_code=201)
def add_note(
    incident_id: uuid.UUID, body: NoteCreate, ctx: Manage, request: Request, db: DB
) -> IncidentDetail:
    incident = incident_service.get(db, ctx.org_id, incident_id)
    incident_service.add_note(db, request, incident, user=ctx.user, text=body.text.strip())
    db.commit()
    return _detail(db, incident)


@router.post("/incidents/{incident_id}/alerts", response_model=IncidentDetail)
def link_alerts(
    incident_id: uuid.UUID, body: LinkAlerts, ctx: Manage, request: Request, db: DB
) -> IncidentDetail:
    incident = incident_service.get(db, ctx.org_id, incident_id)
    incident_service.link_alerts(db, request, incident, user=ctx.user, alert_ids=body.alert_ids)
    db.commit()
    return _detail(db, incident)


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: uuid.UUID,
    body: AlertUpdate,
    ctx: Annotated[OrgContext, Depends(require("alerts:manage"))],
    request: Request,
    db: DB,
) -> AlertOut:
    alert = db.scalar(select(Alert).where(Alert.id == alert_id, Alert.organization_id == ctx.org_id))
    if alert is None:
        raise not_found("Alert")
    incident_service.set_alert_status(db, request, alert, user=ctx.user, status_=body.status)
    db.commit()
    return alerts_out(db, ctx.org_id, [alert])[0]


# ------------------------------------------------------------------------- response actions
@router.get("/response/status", response_model=ResponseStatus)
def response_status(ctx: Read, db: DB) -> ResponseStatus:
    action_service.expire_stale(db, ctx.org_id)
    db.commit()
    pending = (
        db.scalar(
            select(func.count())
            .select_from(ResponseAction)
            .where(ResponseAction.organization_id == ctx.org_id, ResponseAction.status == "pending_approval")
        )
        or 0
    )
    return ResponseStatus(
        emergency_stop=EmergencyStop(**action_service.emergency_stop(ctx.organization)),
        pending_approvals=pending,
        approvers=len(members_with(db, ctx.org_id, "responses:approve")),
        action_types=[
            ActionTypeOut(
                key=s.key,
                title=s.title,
                impact=s.impact,
                reversible=s.reversible,
                description=s.description,
                target_fields=list(s.target_fields),
            )
            for s in action_service.ACTIONS.values()
        ],
    )


@router.post("/response/emergency-stop", response_model=EmergencyStop)
def emergency_stop(
    body: EmergencyStopUpdate,
    ctx: Annotated[OrgContext, Depends(require("responses:approve"))],
    request: Request,
    db: DB,
) -> EmergencyStop:
    state = action_service.set_emergency_stop(
        db, request, ctx.organization, user=ctx.user, engaged=body.engaged, reason=body.reason
    )
    db.commit()
    return EmergencyStop(**state)


@router.get("/actions", response_model=Page[ActionOut])
def list_actions(
    ctx: Read,
    db: DB,
    status: Annotated[
        str | None,
        Query(pattern=r"^(pending_approval|approved|rejected|succeeded|failed|rolled_back|cancelled)$"),
    ] = None,
    incident_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[ActionOut]:
    action_service.expire_stale(db, ctx.org_id)
    db.commit()
    filters = [ResponseAction.organization_id == ctx.org_id]
    if status:
        filters.append(ResponseAction.status == status)
    if incident_id:
        filters.append(ResponseAction.incident_id == incident_id)
    total = db.scalar(select(func.count()).select_from(ResponseAction).where(*filters)) or 0
    rows = db.scalars(
        select(ResponseAction)
        .where(*filters)
        .order_by(ResponseAction.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return Page[ActionOut](
        items=_actions_out(db, ctx.org_id, list(rows)), total=total, limit=limit, offset=offset
    )


@router.post("/actions", response_model=ActionOut, status_code=201)
def propose_action(
    body: ActionCreate,
    ctx: Annotated[OrgContext, Depends(require("responses:propose"))],
    request: Request,
    db: DB,
) -> ActionOut:
    a = action_service.propose(
        db,
        request,
        org_id=ctx.org_id,
        user=ctx.user,
        action_type=body.action_type,
        target=body.target,
        reason=body.reason,
        incident_id=body.incident_id,
        run_id=body.agent_run_id,
    )
    db.commit()
    return _actions_out(db, ctx.org_id, [a])[0]


@router.post("/actions/{action_id}/decision", response_model=ActionOut)
def decide_action(
    action_id: uuid.UUID,
    body: Decision,
    ctx: Annotated[OrgContext, Depends(require("responses:approve"))],
    request: Request,
    db: DB,
) -> ActionOut:
    a = action_service.get(db, ctx.org_id, action_id)
    action_service.decide(db, request, a, user=ctx.user, approve=body.approve, comment=body.comment)
    db.commit()
    return _actions_out(db, ctx.org_id, [a])[0]


@router.post("/actions/{action_id}/run", response_model=ActionOut)
def run_action(
    action_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(require("responses:approve"))],
    request: Request,
    db: DB,
) -> ActionOut:
    a = action_service.get(db, ctx.org_id, action_id)
    action_service.run(db, request, a, user=ctx.user)
    db.commit()
    return _actions_out(db, ctx.org_id, [a])[0]


@router.post("/actions/{action_id}/rollback", response_model=ActionOut)
def rollback_action(
    action_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(require("responses:approve"))],
    request: Request,
    db: DB,
) -> ActionOut:
    a = action_service.get(db, ctx.org_id, action_id)
    action_service.rollback(db, request, a, user=ctx.user)
    db.commit()
    return _actions_out(db, ctx.org_id, [a])[0]


@router.post("/actions/{action_id}/cancel", response_model=ActionOut)
def cancel_action(
    action_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(require("responses:propose"))],
    request: Request,
    db: DB,
) -> ActionOut:
    a = action_service.get(db, ctx.org_id, action_id)
    action_service.cancel(db, request, a, user=ctx.user, can_approve="responses:approve" in ctx.permissions)
    db.commit()
    return _actions_out(db, ctx.org_id, [a])[0]


BLOCKLIST_TYPES = {
    "ip": ("ipv4", "ipv6"),
    "domain": ("domain",),
    "url": ("url",),
    "hash": ("md5", "sha1", "sha256"),
    "email": ("email",),
}


@router.get("/blocklist", response_class=Response, responses={200: {"content": {"text/plain": {}}}})
def blocklist(
    ctx: Annotated[OrgContext, Depends(require("intel:read"))],
    db: DB,
    type: Annotated[str, Query(pattern=r"^(ip|domain|url|hash|email)$")] = "ip",
) -> Response:
    """Indicators blocked by response actions, one per line — for a firewall or DNS filter to import."""
    rows = db.scalars(
        select(ThreatIndicator)
        .where(
            ThreatIndicator.organization_id == ctx.org_id,
            ThreatIndicator.verdict == "malicious",
            ThreatIndicator.indicator_type.in_(BLOCKLIST_TYPES[type]),
        )
        .order_by(ThreatIndicator.value)
    ).all()
    values = [r.value for r in rows if (r.context or {}).get("blocked")]
    header = f"# SENTINEL X block list ({type}) — {ctx.organization.name} — {len(values)} entries\n"
    return Response(
        content=header + "".join(f"{v}\n" for v in values),
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


# --------------------------------------------------------------------------------- evidence
@router.post(
    "/incidents/{incident_id}/evidence",
    response_model=EvidenceOut,
    status_code=201,
    max_body_size=limits.evidence(),
)
def add_evidence(
    incident_id: uuid.UUID,
    body: EvidenceCreate,
    ctx: Annotated[OrgContext, Depends(require("evidence:manage"))],
    request: Request,
    db: DB,
) -> EvidenceOut:
    incident = incident_service.get(db, ctx.org_id, incident_id)
    item = evidence_service.add(
        db,
        request,
        incident,
        user=ctx.user,
        kind=body.kind,
        title=body.title,
        description=body.description,
        filename=body.filename,
        content_type=body.content_type,
        content_base64=body.content_base64,
        note=body.note,
        sha256=body.sha256,
        size_bytes=body.size_bytes,
    )
    db.commit()
    return _evidence_out(db, ctx.org_id, [item])[0]


@router.get("/evidence", response_model=Page[EvidenceOut])
def list_evidence(
    ctx: Read,
    db: DB,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[EvidenceOut]:
    filters = [Evidence.organization_id == ctx.org_id]
    total = db.scalar(select(func.count()).select_from(Evidence).where(*filters)) or 0
    rows = db.scalars(
        select(Evidence).where(*filters).order_by(Evidence.collected_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[EvidenceOut](
        items=_evidence_out(db, ctx.org_id, list(rows)), total=total, limit=limit, offset=offset
    )


@router.get("/evidence/{evidence_id}/download", response_class=Response)
def download_evidence(
    evidence_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(require("evidence:manage"))],
    request: Request,
    db: DB,
) -> Response:
    item = evidence_service.get(db, ctx.org_id, evidence_id)
    data = evidence_service.download(db, request, item, user=ctx.user)
    db.commit()
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", item.filename or f"evidence-{item.id}")[:120]
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Evidence-SHA256": item.sha256 or "",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.post("/evidence/{evidence_id}/verify", response_model=VerifyResult)
def verify_evidence(
    evidence_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(require("evidence:manage"))],
    request: Request,
    db: DB,
) -> VerifyResult:
    item = evidence_service.get(db, ctx.org_id, evidence_id)
    result = evidence_service.verify(db, request, item, user=ctx.user)
    db.commit()
    return VerifyResult(**result, evidence=_evidence_out(db, ctx.org_id, [item])[0])


# ---------------------------------------------------------------------------------- reports
def _report_detail(r: Report) -> ReportDetail:
    content: dict[str, Any] = r.content or {}
    return ReportDetail(
        **ReportOut.model_validate(r).model_dump(),
        markdown=content.get("markdown", ""),
        metrics=content.get("metrics", {}),
    )


@router.get("/reports", response_model=Page[ReportOut])
def list_reports(
    ctx: Annotated[OrgContext, Depends(require("reports:read"))],
    db: DB,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[ReportOut]:
    filters = [Report.organization_id == ctx.org_id]
    total = db.scalar(select(func.count()).select_from(Report).where(*filters)) or 0
    rows = db.scalars(
        select(Report).where(*filters).order_by(Report.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[ReportOut](
        items=[ReportOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.post("/reports", response_model=ReportDetail, status_code=201)
def create_report(
    body: ReportCreate,
    ctx: Annotated[OrgContext, Depends(require("reports:manage"))],
    request: Request,
    db: DB,
) -> ReportDetail:
    incident = None
    if body.report_type == "incident":
        if body.incident_id is None:
            raise AppError(422, "incident_required", "Choose the incident to report on")
        incident = incident_service.get(db, ctx.org_id, body.incident_id)
    report = report_service.create(
        db,
        request,
        org_id=ctx.org_id,
        user=ctx.user,
        report_type=body.report_type,
        incident=incident,
        period_days=body.period_days,
    )
    db.commit()
    return _report_detail(report)


def _get_report(db: DB, org_id: uuid.UUID, report_id: uuid.UUID) -> Report:
    r = db.scalar(select(Report).where(Report.id == report_id, Report.organization_id == org_id))
    if r is None:
        raise not_found("Report")
    return r


@router.get("/reports/{report_id}", response_model=ReportDetail)
def get_report(
    report_id: uuid.UUID, ctx: Annotated[OrgContext, Depends(require("reports:read"))], db: DB
) -> ReportDetail:
    return _report_detail(_get_report(db, ctx.org_id, report_id))


@router.get("/reports/{report_id}/download", response_class=Response)
def download_report(
    report_id: uuid.UUID, ctx: Annotated[OrgContext, Depends(require("reports:read"))], db: DB
) -> Response:
    r = _get_report(db, ctx.org_id, report_id)
    slug = re.sub(r"[^a-z0-9]+", "-", r.title.lower()).strip("-")[:60]
    return Response(
        content=(r.content or {}).get("markdown", ""),
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="sentinel-x-{slug}.md"',
            "Cache-Control": "no-store",
        },
    )
