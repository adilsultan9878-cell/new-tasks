"""Request dependencies: authentication, tenant resolution and permission checks.

Tenant isolation rule: every organization-scoped route resolves the organization *through the
caller's active membership*. A non-member gets the same 404 as a non-existent organization, so
organization IDs cannot be probed. The verified org/user IDs are then bound to the DB session,
which activates the PostgreSQL Row-Level Security policies as a second, independent layer.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, Path, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError, forbidden, not_found
from app.core.security import decode_access_token
from app.db.session import get_db, set_tenant_context
from app.models import Organization, OrganizationMember, Permission, RolePermission, User, UserSession
from app.services import audit

DB = Annotated[Session, Depends(get_db)]
_bearer = HTTPBearer(auto_error=False)

_UNAUTHENTICATED = AppError(
    status.HTTP_401_UNAUTHORIZED,
    "unauthorized",
    "Authentication required",
    headers={"WWW-Authenticate": "Bearer"},
)


@dataclass
class Principal:
    user: User
    session_id: uuid.UUID
    session_family: uuid.UUID


def get_principal(
    db: DB,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _UNAUTHENTICATED
    try:
        claims = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(claims["sub"])
        session_id = uuid.UUID(claims["sid"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise _UNAUTHENTICATED from None

    # The session row must still exist and not be revoked (logout / password change / reuse).
    # A rotated session is fine: its access token stays valid until it expires (max 15 min).
    session = db.get(UserSession, session_id)
    if (
        session is None
        or session.user_id != user_id
        or (session.revoked_at is not None and session.revoked_reason != "rotated")
    ):
        raise _UNAUTHENTICATED
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _UNAUTHENTICATED
    set_tenant_context(db, user_id=user.id)
    return Principal(user=user, session_id=session_id, session_family=session.family_id)


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


@dataclass
class OrgContext:
    organization: Organization
    member: OrganizationMember
    permissions: frozenset[str]
    user: User

    @property
    def org_id(self) -> uuid.UUID:
        return self.organization.id

    def require(self, permission: str) -> None:
        if permission not in self.permissions:
            raise forbidden()


def load_permissions(db: Session, role_id: uuid.UUID) -> frozenset[str]:
    rows = db.scalars(
        select(Permission.key)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role_id)
    )
    return frozenset(rows)


def get_org_context(
    db: DB,
    principal: CurrentPrincipal,
    org_id: Annotated[uuid.UUID, Path(description="Organization ID")],
) -> OrgContext:
    member = db.scalar(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == principal.user.id,
            OrganizationMember.status == "active",
        )
    )
    if member is None:
        raise not_found("Organization")
    set_tenant_context(db, org_id=org_id, user_id=principal.user.id)
    return OrgContext(
        organization=member.organization,
        member=member,
        permissions=load_permissions(db, member.role_id),
        user=principal.user,
    )


CurrentOrg = Annotated[OrgContext, Depends(get_org_context)]


def require(permission: str) -> Callable[[OrgContext], OrgContext]:
    """Dependency factory: ``ctx: Annotated[OrgContext, Depends(require("members:manage"))]``."""

    def _check(ctx: CurrentOrg, db: DB, request: Request) -> OrgContext:
        if permission not in ctx.permissions:
            # Record denials: repeated attempts are a useful insider-threat signal.
            audit.record(
                db,
                "authz.denied",
                request=request,
                actor_id=ctx.user.id,
                org_id=ctx.org_id,
                outcome="denied",
                details={"permission": permission, "path": request.url.path},
            )
            db.commit()
            raise forbidden()
        return ctx

    return _check
