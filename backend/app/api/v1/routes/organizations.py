from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.api.deps import DB, CurrentOrg, CurrentPrincipal, OrgContext, load_permissions, require
from app.models import OrganizationMember, Role
from app.schemas.organizations import (
    MemberAdd,
    MemberOut,
    MembershipOut,
    MemberUpdate,
    OrganizationCreate,
    OrganizationOut,
    OrganizationUpdate,
    RoleOut,
    RoleWithPermissions,
)
from app.services import accounts, audit
from app.services import organizations as org_service

router = APIRouter(prefix="/organizations", tags=["organizations"])


def _membership_out(db: DB, member: OrganizationMember) -> MembershipOut:
    return MembershipOut(
        organization=OrganizationOut.model_validate(member.organization),
        role=RoleOut.model_validate(member.role),
        permissions=sorted(load_permissions(db, member.role_id)),
        member_count=org_service.member_count(db, member.organization_id),
    )


def _member_out(member: OrganizationMember) -> MemberOut:
    return MemberOut(
        id=member.id,
        user_id=member.user_id,
        email=member.user.email,
        full_name=member.user.full_name,
        role=RoleOut.model_validate(member.role),
        status=member.status,
        joined_at=member.created_at,
    )


@router.get("", response_model=list[MembershipOut], summary="Organizations I belong to")
def list_my_organizations(principal: CurrentPrincipal, db: DB) -> list[MembershipOut]:
    members = db.scalars(
        select(OrganizationMember)
        .where(OrganizationMember.user_id == principal.user.id, OrganizationMember.status == "active")
        .order_by(OrganizationMember.created_at)
    ).all()
    return [_membership_out(db, m) for m in members]


@router.post("", response_model=MembershipOut, status_code=201)
def create_organization(
    body: OrganizationCreate, principal: CurrentPrincipal, request: Request, db: DB
) -> MembershipOut:
    accounts.require_verified(principal.user)
    member = org_service.create_organization(
        db,
        request,
        principal.user,
        name=body.name,
        slug=body.slug,
        description=body.description,
        industry=body.industry,
    )
    db.commit()
    return _membership_out(db, member)


@router.get("/roles", response_model=list[RoleWithPermissions], summary="System roles")
def list_roles(_: CurrentPrincipal, db: DB) -> list[RoleWithPermissions]:
    roles = db.scalars(select(Role).where(Role.organization_id.is_(None)).order_by(Role.rank.desc()))
    return [
        RoleWithPermissions(
            key=r.key,
            name=r.name,
            description=r.description,
            rank=r.rank,
            permissions=sorted(p.key for p in r.permissions),
        )
        for r in roles
    ]


@router.get("/{org_id}", response_model=MembershipOut)
def get_organization(ctx: CurrentOrg, db: DB) -> MembershipOut:
    return _membership_out(db, ctx.member)


@router.patch("/{org_id}", response_model=MembershipOut)
def update_organization(
    body: OrganizationUpdate,
    ctx: Annotated[OrgContext, Depends(require("org:update"))],
    request: Request,
    db: DB,
) -> MembershipOut:
    changes = body.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(ctx.organization, field, value)
    audit.record(
        db,
        "org.update",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="organization",
        target_id=ctx.org_id,
        details={"fields": sorted(changes)},
    )
    db.commit()
    return _membership_out(db, ctx.member)


@router.get("/{org_id}/members", response_model=list[MemberOut])
def list_members(ctx: Annotated[OrgContext, Depends(require("members:read"))], db: DB) -> list[MemberOut]:
    members = db.scalars(
        select(OrganizationMember)
        .options(joinedload(OrganizationMember.user))  # one query, not one per member
        .where(OrganizationMember.organization_id == ctx.org_id)
        .order_by(OrganizationMember.created_at)
    ).all()
    return [_member_out(m) for m in members]


@router.post("/{org_id}/members", response_model=MemberOut, status_code=201)
def add_member(
    body: MemberAdd, ctx: Annotated[OrgContext, Depends(require("members:manage"))], request: Request, db: DB
) -> MemberOut:
    member = org_service.add_member(db, request, ctx.member, email=body.email, role_key=body.role)
    db.commit()
    return _member_out(member)


@router.patch("/{org_id}/members/{member_id}", response_model=MemberOut)
def update_member(
    member_id: uuid.UUID,
    body: MemberUpdate,
    ctx: Annotated[OrgContext, Depends(require("members:manage"))],
    request: Request,
    db: DB,
) -> MemberOut:
    member = org_service.change_role(db, request, ctx.member, member_id, body.role)
    db.commit()
    db.refresh(member)
    return _member_out(member)


@router.delete("/{org_id}/members/{member_id}", status_code=204)
def remove_member(member_id: uuid.UUID, ctx: CurrentOrg, request: Request, db: DB) -> Response:
    # Members may always leave; removing someone else needs members:manage.
    if member_id != ctx.member.id:
        ctx.require("members:manage")
    org_service.remove_member(db, request, ctx.member, member_id)
    db.commit()
    return Response(status_code=204)
