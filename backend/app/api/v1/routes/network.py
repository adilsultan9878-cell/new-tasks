from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import select

from app.api.deps import DB, OrgContext, require
from app.core import limits
from app.core.errors import AppError, not_found
from app.models import NetworkAsset, NetworkScope
from app.schemas.intel import AssetOut, ScanImport, ScanImportResult, ScopeCreate, ScopeOut
from app.services import audit
from app.services import network as network_service

router = APIRouter(prefix="/organizations/{org_id}/network", tags=["network"])


@router.get("/scopes", response_model=list[ScopeOut])
def list_scopes(ctx: Annotated[OrgContext, Depends(require("network:read"))], db: DB) -> list[ScopeOut]:
    rows = db.scalars(
        select(NetworkScope).where(NetworkScope.organization_id == ctx.org_id).order_by(NetworkScope.cidr)
    )
    return [ScopeOut.model_validate(r) for r in rows]


@router.post("/scopes", response_model=ScopeOut, status_code=201)
def add_scope(
    body: ScopeCreate,
    ctx: Annotated[OrgContext, Depends(require("network:manage"))],
    request: Request,
    db: DB,
) -> ScopeOut:
    cidr, private = network_service.parse_scope(body.cidr, body.attest_authorized)
    if db.scalar(
        select(NetworkScope.id).where(NetworkScope.organization_id == ctx.org_id, NetworkScope.cidr == cidr)
    ):
        raise AppError(status.HTTP_409_CONFLICT, "scope_exists", "That scope is already declared")
    scope = NetworkScope(
        id=uuid.uuid4(),
        organization_id=ctx.org_id,
        cidr=cidr,
        label=body.label.strip(),
        is_private=private,
        attested_by=ctx.user.id,
    )
    db.add(scope)
    audit.record(
        db,
        "network.scope_add",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="network_scope",
        target_id=scope.id,
        details={"cidr": cidr, "private": private, "attested": body.attest_authorized},
    )
    db.commit()
    return ScopeOut.model_validate(scope)


@router.delete("/scopes/{scope_id}", status_code=204)
def delete_scope(
    scope_id: uuid.UUID,
    ctx: Annotated[OrgContext, Depends(require("network:manage"))],
    request: Request,
    db: DB,
) -> Response:
    scope = db.scalar(
        select(NetworkScope).where(NetworkScope.id == scope_id, NetworkScope.organization_id == ctx.org_id)
    )
    if scope is None:
        raise not_found("Scope")
    audit.record(
        db,
        "network.scope_remove",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="network_scope",
        target_id=scope.id,
        details={"cidr": scope.cidr},
    )
    db.delete(scope)
    db.commit()
    return Response(status_code=204)


@router.post("/imports", response_model=ScanImportResult, max_body_size=limits.scan_import())
def import_scan(
    body: ScanImport, ctx: Annotated[OrgContext, Depends(require("network:manage"))], request: Request, db: DB
) -> ScanImportResult:
    summary = network_service.import_scan(
        db, request, org_id=ctx.org_id, user_id=ctx.user.id, filename=body.filename, xml_text=body.content
    )
    db.commit()
    return ScanImportResult(**summary)


@router.get("/assets", response_model=list[AssetOut])
def list_assets(
    ctx: Annotated[OrgContext, Depends(require("network:read"))],
    db: DB,
    q: Annotated[str | None, Query(max_length=100)] = None,
) -> list[AssetOut]:
    filters = [NetworkAsset.organization_id == ctx.org_id]
    if q:
        filters.append(NetworkAsset.ip_address.like(f"%{q}%") | NetworkAsset.hostname.like(f"%{q.lower()}%"))
    rows = db.scalars(
        select(NetworkAsset).where(*filters).order_by(NetworkAsset.ip_address).limit(1000)
    ).all()
    return [AssetOut.model_validate(r) for r in rows]
