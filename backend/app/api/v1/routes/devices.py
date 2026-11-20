from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select

from app.api.deps import DB, OrgContext, require
from app.core.errors import not_found
from app.models import Device, EnrollmentToken
from app.schemas.devices import (
    DeviceDetail,
    DeviceOut,
    DeviceUpdate,
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollmentTokenOut,
)
from app.services import devices as device_service

router = APIRouter(prefix="/organizations/{org_id}", tags=["devices"])

ReadDevices = Annotated[OrgContext, Depends(require("devices:read"))]
ManageDevices = Annotated[OrgContext, Depends(require("devices:manage"))]


def _token_out(token: EnrollmentToken) -> EnrollmentTokenOut:
    return EnrollmentTokenOut(
        id=token.id,
        label=token.label,
        device_type=token.device_type,
        max_uses=token.max_uses,
        use_count=token.use_count,
        expires_at=token.expires_at,
        revoked_at=token.revoked_at,
        last_used_at=token.last_used_at,
        created_at=token.created_at,
        state=device_service.token_state(token),
    )


def _get_device(db: DB, org_id: uuid.UUID, device_id: uuid.UUID) -> Device:
    device = db.scalar(select(Device).where(Device.id == device_id, Device.organization_id == org_id))
    if device is None:
        raise not_found("Device")
    return device


# ---------------------------------------------------------------------------------- devices
@router.get("/devices", response_model=list[DeviceOut])
def list_devices(
    ctx: ReadDevices,
    db: DB,
    status: Annotated[
        str | None, Query(pattern=r"^(online|offline|degraded|unknown|decommissioned)$")
    ] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    include_decommissioned: bool = False,
) -> list[DeviceOut]:
    filters = [Device.organization_id == ctx.org_id]
    if status:
        filters.append(Device.status == status)
    elif not include_decommissioned:
        filters.append(Device.status != "decommissioned")
    if q:
        like = f"%{q.lower()}%"
        filters.append(or_(func.lower(Device.name).like(like), func.lower(Device.hostname).like(like)))
    rows = db.scalars(select(Device).where(*filters).order_by(Device.name).limit(500)).all()
    return [DeviceOut.model_validate(d) for d in rows]


@router.get("/devices/{device_id}", response_model=DeviceDetail)
def get_device(device_id: uuid.UUID, ctx: ReadDevices, db: DB) -> DeviceDetail:
    return DeviceDetail.model_validate(_get_device(db, ctx.org_id, device_id))


@router.patch("/devices/{device_id}", response_model=DeviceDetail)
def update_device(
    device_id: uuid.UUID, body: DeviceUpdate, ctx: ManageDevices, request: Request, db: DB
) -> DeviceDetail:
    device = _get_device(db, ctx.org_id, device_id)
    device_service.update_device(
        db, request, device, actor_id=ctx.user.id, name=body.name, config=body.config
    )
    db.commit()
    return DeviceDetail.model_validate(device)


@router.post("/devices/{device_id}/revoke", response_model=DeviceDetail)
def revoke_device(device_id: uuid.UUID, ctx: ManageDevices, request: Request, db: DB) -> DeviceDetail:
    device = _get_device(db, ctx.org_id, device_id)
    if device.enrollment_status != "revoked":
        device_service.decommission(
            db, request, device, actor_id=ctx.user.id, reason="revoked by administrator"
        )
        db.commit()
    return DeviceDetail.model_validate(device)


# ------------------------------------------------------------------------ enrollment tokens
@router.get("/enrollment-tokens", response_model=list[EnrollmentTokenOut])
def list_tokens(ctx: ManageDevices, db: DB) -> list[EnrollmentTokenOut]:
    rows = db.scalars(
        select(EnrollmentToken)
        .where(EnrollmentToken.organization_id == ctx.org_id)
        .order_by(EnrollmentToken.created_at.desc())
        .limit(50)
    ).all()
    return [_token_out(t) for t in rows]


@router.post("/enrollment-tokens", response_model=EnrollmentTokenCreated, status_code=201)
def create_token(
    body: EnrollmentTokenCreate, ctx: ManageDevices, request: Request, db: DB
) -> EnrollmentTokenCreated:
    token, raw = device_service.create_enrollment_token(
        db,
        request,
        org_id=ctx.org_id,
        user_id=ctx.user.id,
        label=body.label,
        device_type=body.device_type,
        max_uses=body.max_uses,
        expires_in_hours=body.expires_in_hours,
    )
    db.commit()
    return EnrollmentTokenCreated(**_token_out(token).model_dump(), token=raw)


@router.post("/enrollment-tokens/{token_id}/revoke", response_model=EnrollmentTokenOut)
def revoke_token(token_id: uuid.UUID, ctx: ManageDevices, request: Request, db: DB) -> EnrollmentTokenOut:
    token = device_service.revoke_enrollment_token(
        db, request, org_id=ctx.org_id, user_id=ctx.user.id, token_id=token_id
    )
    db.commit()
    return _token_out(token)
