from __future__ import annotations

import re
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, CurrentPrincipal, OrgContext, require
from app.core.errors import AppError, not_found
from app.intel import vulns
from app.intel.client import IntelUnavailable
from app.intel.providers import provider_status
from app.models import Investigation, ThreatIndicator, VulnerabilityRecord
from app.schemas.common import Page
from app.schemas.intel import (
    IndicatorCreate,
    IndicatorOut,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationOut,
    KevSyncResult,
    ProviderOut,
    VulnerabilityDetail,
    VulnerabilityOut,
    VulnerabilityStats,
)
from app.services import audit
from app.services import investigations as investigation_service

router = APIRouter(tags=["threat-intelligence"])
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_kev_lock = threading.Lock()
_last_kev_sync = 0.0


@router.get("/intel/providers", response_model=list[ProviderOut])
def providers(_: CurrentPrincipal) -> list[ProviderOut]:
    return [ProviderOut(**p) for p in provider_status()]


# ------------------------------------------------------------------------------ investigations
@router.post("/organizations/{org_id}/investigations", response_model=InvestigationDetail, status_code=201)
def create_investigation(
    body: InvestigationCreate,
    ctx: Annotated[OrgContext, Depends(require("investigations:run"))],
    request: Request,
    db: DB,
) -> InvestigationDetail:
    inv = investigation_service.run(
        db,
        request,
        org_id=ctx.org_id,
        user_id=ctx.user.id,
        subject_type=body.subject_type,
        subject=body.subject,
    )
    db.commit()
    return InvestigationDetail.model_validate(inv)


@router.get("/organizations/{org_id}/investigations", response_model=Page[InvestigationOut])
def list_investigations(
    ctx: Annotated[OrgContext, Depends(require("intel:read"))],
    db: DB,
    subject_type: Annotated[
        str | None, Query(pattern=r"^(url|domain|ip|hash|email)(,(url|domain|ip|hash|email))*$")
    ] = None,
    verdict: Annotated[str | None, Query(pattern=r"^(unknown|benign|suspicious|malicious)$")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[InvestigationOut]:
    filters = [Investigation.organization_id == ctx.org_id]
    if subject_type:
        filters.append(Investigation.subject_type.in_(subject_type.split(",")))
    if verdict:
        filters.append(Investigation.verdict == verdict)
    total = db.scalar(select(func.count()).select_from(Investigation).where(*filters)) or 0
    rows = db.scalars(
        select(Investigation)
        .where(*filters)
        .order_by(Investigation.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return Page[InvestigationOut](
        items=[InvestigationOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.get("/organizations/{org_id}/investigations/{investigation_id}", response_model=InvestigationDetail)
def get_investigation(
    investigation_id: uuid.UUID, ctx: Annotated[OrgContext, Depends(require("intel:read"))], db: DB
) -> InvestigationDetail:
    inv = db.scalar(
        select(Investigation).where(
            Investigation.id == investigation_id, Investigation.organization_id == ctx.org_id
        )
    )
    if inv is None:
        raise not_found("Investigation")
    return InvestigationDetail.model_validate(inv)


# ------------------------------------------------------------------------------------ indicators
@router.get("/organizations/{org_id}/indicators", response_model=Page[IndicatorOut])
def list_indicators(
    ctx: Annotated[OrgContext, Depends(require("intel:read"))],
    db: DB,
    verdict: Annotated[str | None, Query(pattern=r"^(unknown|benign|suspicious|malicious)$")] = None,
    source: Annotated[str | None, Query(pattern=r"^(analyst|investigation)$")] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[IndicatorOut]:
    filters = [ThreatIndicator.organization_id == ctx.org_id]
    if verdict:
        filters.append(ThreatIndicator.verdict == verdict)
    if source:
        filters.append(ThreatIndicator.source == source)
    if q:
        filters.append(ThreatIndicator.value.like(f"%{q.lower()}%"))
    total = db.scalar(select(func.count()).select_from(ThreatIndicator).where(*filters)) or 0
    rows = db.scalars(
        select(ThreatIndicator)
        .where(*filters)
        .order_by(ThreatIndicator.last_seen_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return Page[IndicatorOut](
        items=[IndicatorOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.post("/organizations/{org_id}/indicators", response_model=IndicatorOut, status_code=201)
def add_indicator(
    body: IndicatorCreate,
    ctx: Annotated[OrgContext, Depends(require("intel:manage"))],
    request: Request,
    db: DB,
) -> IndicatorOut:
    value = body.value.strip().lower()
    row = db.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.organization_id == ctx.org_id,
            ThreatIndicator.indicator_type == body.indicator_type,
            ThreatIndicator.value == value,
        )
    )
    if row is None:
        candidate = ThreatIndicator(
            id=uuid.uuid4(),
            organization_id=ctx.org_id,
            indicator_type=body.indicator_type,
            value=value,
            source="analyst",
            verdict=body.verdict,
            confidence=100,
            is_verified=True,
            context={},
        )
        try:
            with db.begin_nested():
                db.add(candidate)
                db.flush()
            row = candidate
        except IntegrityError:  # added at the same moment by another request: update that one
            row = db.scalar(
                select(ThreatIndicator).where(
                    ThreatIndicator.organization_id == ctx.org_id,
                    ThreatIndicator.indicator_type == body.indicator_type,
                    ThreatIndicator.value == value,
                )
            )
            if row is None:
                raise
    row.source = "analyst"
    row.verdict = body.verdict
    row.confidence = 100
    row.is_verified = True
    row.last_seen_at = datetime.now(UTC)
    row.context = {**(row.context or {}), "note": body.note, "added_by": str(ctx.user.id)}
    audit.record(
        db,
        "indicator.add",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="indicator",
        target_id=row.id,
        details={"type": body.indicator_type, "value": value[:200], "verdict": body.verdict},
    )
    db.commit()
    return IndicatorOut.model_validate(row)


@router.delete("/organizations/{org_id}/indicators/{indicator_id}", status_code=204)
def delete_indicator(
    indicator_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(require("intel:manage"))],
    request: Request,
    db: DB,
) -> Response:
    row = db.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.id == indicator_id, ThreatIndicator.organization_id == ctx.org_id
        )
    )
    if row is None:
        raise not_found("Indicator")
    audit.record(
        db,
        "indicator.delete",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="indicator",
        target_id=row.id,
        details={"value": row.value[:200]},
    )
    db.delete(row)
    db.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------------------- vulnerabilities
@router.get("/vulnerabilities", response_model=Page[VulnerabilityOut])
def search_vulnerabilities(
    _: CurrentPrincipal,
    db: DB,
    q: Annotated[str | None, Query(max_length=100)] = None,
    kev_only: bool = True,
    ransomware_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> Page[VulnerabilityOut]:
    filters = []
    if kev_only:
        filters.append(VulnerabilityRecord.in_cisa_kev.is_(True))
    if ransomware_only:
        filters.append(VulnerabilityRecord.known_ransomware_use.is_(True))
    if q:
        like = f"%{q.lower()}%"
        filters.append(
            or_(
                func.lower(VulnerabilityRecord.cve_id).like(like),
                func.lower(VulnerabilityRecord.vendor).like(like),
                func.lower(VulnerabilityRecord.product).like(like),
                func.lower(VulnerabilityRecord.title).like(like),
            )
        )
    total = db.scalar(select(func.count()).select_from(VulnerabilityRecord).where(*filters)) or 0
    rows = db.scalars(
        select(VulnerabilityRecord)
        .where(*filters)
        .order_by(VulnerabilityRecord.kev_date_added.desc().nulls_last(), VulnerabilityRecord.cve_id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return Page[VulnerabilityOut](
        items=[VulnerabilityOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.get("/vulnerabilities/stats", response_model=VulnerabilityStats)
def vulnerability_stats(_: CurrentPrincipal, db: DB) -> VulnerabilityStats:
    kev = VulnerabilityRecord.in_cisa_kev.is_(True)
    return VulnerabilityStats(
        total=db.scalar(select(func.count()).select_from(VulnerabilityRecord)) or 0,
        kev_total=db.scalar(select(func.count()).select_from(VulnerabilityRecord).where(kev)) or 0,
        ransomware_total=db.scalar(
            select(func.count())
            .select_from(VulnerabilityRecord)
            .where(kev, VulnerabilityRecord.known_ransomware_use.is_(True))
        )
        or 0,
        last_kev_sync=db.scalar(select(func.max(VulnerabilityRecord.fetched_at)).where(kev)),
    )


@router.get("/vulnerabilities/{cve_id}", response_model=VulnerabilityDetail)
def get_vulnerability(cve_id: str, _: CurrentPrincipal, db: DB, refresh: bool = False) -> VulnerabilityDetail:
    if not CVE_RE.match(cve_id):
        raise AppError(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_cve", "Use the format CVE-2024-12345")
    nvd_error = None
    try:
        rec = vulns.enrich_from_nvd(db, cve_id, force=refresh)
        db.commit()
    except (IntelUnavailable, LookupError) as exc:
        db.rollback()
        rec = db.scalar(select(VulnerabilityRecord).where(VulnerabilityRecord.cve_id == cve_id.upper()))
        if rec is None:
            raise AppError(status.HTTP_404_NOT_FOUND, "cve_not_found", str(exc)) from None
        nvd_error = str(exc)
    out = VulnerabilityDetail.model_validate(rec)
    out.nvd_error = nvd_error
    return out


@router.post("/organizations/{org_id}/vulnerabilities/sync-kev", response_model=KevSyncResult)
def sync_kev(
    ctx: Annotated[OrgContext, Depends(require("intel:manage"))], request: Request, db: DB
) -> KevSyncResult:
    global _last_kev_sync
    with _kev_lock:
        if time.monotonic() - _last_kev_sync < 600 and _last_kev_sync:
            raise AppError(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "recently_synced",
                "The KEV catalogue was refreshed less than 10 minutes ago",
                headers={"Retry-After": "600"},
            )
        _last_kev_sync = time.monotonic()
    try:
        result = vulns.sync_kev(db)
    except IntelUnavailable as exc:
        with _kev_lock:
            _last_kev_sync = 0.0
        raise AppError(
            status.HTTP_502_BAD_GATEWAY, "source_unavailable", f"CISA KEV unavailable: {exc}"
        ) from None
    audit.record(
        db, "vulnerability.kev_sync", request=request, actor_id=ctx.user.id, org_id=ctx.org_id, details=result
    )
    db.commit()
    return KevSyncResult(**result)


def reset_kev_throttle() -> None:  # used by tests
    global _last_kev_sync
    _last_kev_sync = 0.0
