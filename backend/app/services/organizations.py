"""Organizations and memberships. All writes are permission-checked by the API layer and
re-validated here for invariants (e.g. an organization always keeps at least one owner)."""

from __future__ import annotations

import re
import secrets
import uuid

from fastapi import Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError, forbidden, not_found
from app.db.session import set_tenant_context
from app.models import Notification, Organization, OrganizationMember, Role, User
from app.rbac.catalog import OWNER_ROLE
from app.services import audit

MAX_ORGS_PER_USER = 10


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:56].strip("-")
    return slug if len(slug) >= 3 else f"org-{slug}".strip("-")


def get_system_role(db: Session, key: str) -> Role:
    role = db.scalar(select(Role).where(Role.organization_id.is_(None), Role.key == key))
    if role is None:
        raise AppError(status.HTTP_400_BAD_REQUEST, "invalid_role", f"Unknown role '{key}'")
    return role


def create_organization(
    db: Session,
    request: Request,
    user: User,
    *,
    name: str,
    slug: str | None,
    description: str | None,
    industry: str | None,
) -> OrganizationMember:
    owned = db.scalar(
        select(func.count()).select_from(OrganizationMember).where(OrganizationMember.user_id == user.id)
    )
    if (owned or 0) >= MAX_ORGS_PER_USER:
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "org_limit",
            f"You can belong to at most {MAX_ORGS_PER_USER} organizations",
        )

    if slug:
        if db.scalar(select(Organization.id).where(Organization.slug == slug)):
            raise AppError(status.HTTP_409_CONFLICT, "slug_taken", "That organization URL is taken")
    else:
        base = slugify(name)
        slug = base
        while db.scalar(select(Organization.id).where(Organization.slug == slug)):
            slug = f"{base[:50]}-{secrets.token_hex(3)}"

    org = Organization(
        id=uuid.uuid4(),
        name=name,
        slug=slug,
        description=description,
        industry=industry,
        created_by=user.id,
        settings={},
    )
    db.add(org)
    db.flush()
    set_tenant_context(db, org_id=org.id)
    member = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=org.id,
        user_id=user.id,
        role_id=get_system_role(db, OWNER_ROLE).id,
        status="active",
    )
    db.add(member)
    audit.record(
        db,
        "org.create",
        request=request,
        actor_id=user.id,
        org_id=org.id,
        target_type="organization",
        target_id=org.id,
        details={"name": name, "slug": slug},
    )
    db.flush()
    db.refresh(member)
    return member


def member_count(db: Session, org_id: uuid.UUID) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(OrganizationMember)
            .where(OrganizationMember.organization_id == org_id, OrganizationMember.status == "active")
        )
        or 0
    )


def _owner_count(db: Session, org_id: uuid.UUID) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(OrganizationMember)
            .join(Role)
            .where(
                OrganizationMember.organization_id == org_id,
                Role.key == OWNER_ROLE,
                OrganizationMember.status == "active",
            )
        )
        or 0
    )


def _get_member(db: Session, org_id: uuid.UUID, member_id: uuid.UUID) -> OrganizationMember:
    member = db.scalar(
        select(OrganizationMember).where(
            OrganizationMember.id == member_id, OrganizationMember.organization_id == org_id
        )
    )
    if member is None:
        raise not_found("Member")
    return member


def _assert_can_assign(actor: OrganizationMember, target_role: Role) -> None:
    # Nobody can grant a role more privileged than their own; only owners can mint owners.
    if target_role.rank > actor.role.rank:
        raise forbidden("You cannot assign a role more privileged than your own")


def _assert_can_modify(actor: OrganizationMember, target: OrganizationMember) -> None:
    if target.role.rank > actor.role.rank:
        raise forbidden("You cannot modify a member with a more privileged role")


def add_member(
    db: Session, request: Request, actor: OrganizationMember, *, email: str, role_key: str
) -> OrganizationMember:
    role = get_system_role(db, role_key)
    _assert_can_assign(actor, role)
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if user is None or not user.is_active:
        # Email invitations need an email provider (planned); for now the user must be registered.
        raise AppError(
            status.HTTP_404_NOT_FOUND,
            "user_not_found",
            "No registered user with that email. Ask them to create an account first.",
        )
    exists = db.scalar(
        select(OrganizationMember.id).where(
            OrganizationMember.organization_id == actor.organization_id, OrganizationMember.user_id == user.id
        )
    )
    if exists:
        raise AppError(status.HTTP_409_CONFLICT, "already_member", "User is already a member")
    member = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=actor.organization_id,
        user_id=user.id,
        role_id=role.id,
        invited_by=actor.user_id,
    )
    db.add(member)
    org = db.get(Organization, actor.organization_id)
    db.add(
        Notification(
            id=uuid.uuid4(),
            user_id=user.id,
            organization_id=actor.organization_id,
            kind="membership",
            title=f"You were added to {org.name if org else 'an organization'}",
            body=f"Role: {role.name}",
            link="/",
            severity="info",
        )
    )
    audit.record(
        db,
        "member.add",
        request=request,
        actor_id=actor.user_id,
        org_id=actor.organization_id,
        target_type="user",
        target_id=user.id,
        details={"email": user.email, "role": role.key},
    )
    db.flush()
    db.refresh(member)
    return member


def change_role(
    db: Session, request: Request, actor: OrganizationMember, member_id: uuid.UUID, role_key: str
) -> OrganizationMember:
    member = _get_member(db, actor.organization_id, member_id)
    role = get_system_role(db, role_key)
    _assert_can_modify(actor, member)
    _assert_can_assign(actor, role)
    if (
        member.role.key == OWNER_ROLE
        and role.key != OWNER_ROLE
        and _owner_count(db, member.organization_id) <= 1
    ):
        raise AppError(
            status.HTTP_400_BAD_REQUEST, "last_owner", "An organization must keep at least one owner"
        )
    previous = member.role.key
    member.role_id = role.id
    db.flush()
    db.expire(member, ["role"])
    audit.record(
        db,
        "member.role_change",
        request=request,
        actor_id=actor.user_id,
        org_id=actor.organization_id,
        target_type="user",
        target_id=member.user_id,
        details={"from": previous, "to": role.key},
    )
    return member


def remove_member(db: Session, request: Request, actor: OrganizationMember, member_id: uuid.UUID) -> None:
    member = _get_member(db, actor.organization_id, member_id)
    if member.id != actor.id:
        _assert_can_modify(actor, member)
    if member.role.key == OWNER_ROLE and _owner_count(db, member.organization_id) <= 1:
        raise AppError(
            status.HTTP_400_BAD_REQUEST, "last_owner", "An organization must keep at least one owner"
        )
    audit.record(
        db,
        "member.remove" if member.id != actor.id else "member.leave",
        request=request,
        actor_id=actor.user_id,
        org_id=actor.organization_id,
        target_type="user",
        target_id=member.user_id,
    )
    db.delete(member)
