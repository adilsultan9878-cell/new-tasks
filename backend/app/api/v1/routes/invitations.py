"""Invitations (Phase 10): invite by e-mail address, accept with or without an existing account."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from sqlalchemy import select

from app.api.deps import DB, CurrentPrincipal, OrgContext, require
from app.core.errors import not_found
from app.core.rate_limit import auth_rate_limit
from app.models import Invitation, Role, User
from app.schemas.auth import TokenBody
from app.schemas.organizations import (
    InvitationCreate,
    InvitationCreated,
    InvitationInfo,
    InvitationOut,
    MembershipOut,
    RoleOut,
)
from app.services import accounts, audit

org_router = APIRouter(prefix="/organizations/{org_id}/invitations", tags=["organizations"])
public_router = APIRouter(prefix="/invitations", tags=["organizations"])
ReadMembers = Annotated[OrgContext, Depends(require("members:read"))]
ManageMembers = Annotated[OrgContext, Depends(require("members:manage"))]


def _out(db: DB, rows: list[Invitation]) -> list[InvitationOut]:
    roles = {
        r.id: r
        for r in db.scalars(select(Role).where(Role.id.in_({r.role_id for r in rows} or {uuid.uuid4()})))
    }
    names = {
        u.id: u.full_name or u.email
        for u in db.scalars(
            select(User).where(User.id.in_({r.invited_by for r in rows if r.invited_by} or {uuid.uuid4()}))
        )
    }
    now = datetime.now(UTC)
    out = []
    for r in rows:
        expires = r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=UTC)
        out.append(
            InvitationOut(
                id=r.id,
                email=r.email,
                role=RoleOut.model_validate(roles[r.role_id]),
                invited_by_name=names.get(r.invited_by) if r.invited_by else None,
                emailed=r.emailed,
                created_at=r.created_at,
                expires_at=r.expires_at,
                status="pending" if expires > now else "expired",
            )
        )
    return out


@org_router.get("", response_model=list[InvitationOut])
def list_invitations(ctx: ReadMembers, db: DB) -> list[InvitationOut]:
    rows = db.scalars(
        select(Invitation)
        .where(
            Invitation.organization_id == ctx.org_id,
            Invitation.accepted_at.is_(None),
            Invitation.revoked_at.is_(None),
        )
        .order_by(Invitation.created_at.desc())
    ).all()
    return _out(db, list(rows))


@org_router.post("", response_model=InvitationCreated, status_code=status.HTTP_201_CREATED)
def create_invitation(
    body: InvitationCreate, ctx: ManageMembers, request: Request, db: DB, background: BackgroundTasks
) -> InvitationCreated:
    inv, link = accounts.invite(db, request, background, ctx.member, email=body.email, role_key=body.role)
    db.commit()
    return InvitationCreated(invitation=_out(db, [inv])[0], link=link)


@org_router.delete("/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invitation(invitation_id: uuid.UUID, ctx: ManageMembers, request: Request, db: DB) -> None:
    inv = db.scalar(
        select(Invitation).where(Invitation.organization_id == ctx.org_id, Invitation.id == invitation_id)
    )
    if inv is None or inv.accepted_at is not None or inv.revoked_at is not None:
        raise not_found("Invitation")
    inv.revoked_at = datetime.now(UTC)
    audit.record(
        db,
        "member.invite_revoke",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="invitation",
        target_id=inv.id,
        details={"email": inv.email},
    )
    db.commit()


@public_router.post("/lookup", response_model=InvitationInfo, dependencies=[Depends(auth_rate_limit)])
def lookup_invitation(body: TokenBody, db: DB) -> InvitationInfo:
    """What an invitation link is for (shown before signing in or up). The token stays in the body."""
    return InvitationInfo(**accounts.lookup(db, body.token))


@public_router.post("/accept", response_model=MembershipOut, dependencies=[Depends(auth_rate_limit)])
def accept_invitation(
    body: TokenBody, principal: CurrentPrincipal, request: Request, db: DB
) -> MembershipOut:
    from app.api.v1.routes.organizations import _membership_out

    member = accounts.accept(db, request, principal.user, body.token)
    db.commit()
    return _membership_out(db, member)
