"""Shared helpers for the SOC services."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Notification, OrganizationMember, Permission, RolePermission, User


def now() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def actor(user: User | None) -> dict[str, Any]:
    if user is None:
        return {"actor_id": None, "actor": "system"}
    return {"actor_id": str(user.id), "actor": user.full_name or user.email}


def members_with(db: Session, org_id: uuid.UUID, permission: str) -> list[uuid.UUID]:
    """Active members whose role grants a permission (the database is authoritative)."""
    rows = db.scalars(
        select(OrganizationMember.user_id)
        .join(RolePermission, RolePermission.role_id == OrganizationMember.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.status == "active",
            Permission.key == permission,
        )
    ).all()
    return sorted(set(rows), key=str)


def notify(
    db: Session,
    org_id: uuid.UUID,
    user_ids: list[uuid.UUID],
    *,
    kind: str,
    title: str,
    body: str | None = None,
    link: str | None = None,
    severity: str = "info",
    exclude: uuid.UUID | None = None,
) -> int:
    sent = 0
    for user_id in user_ids:
        if user_id == exclude:
            continue
        db.add(
            Notification(
                id=uuid.uuid4(),
                user_id=user_id,
                organization_id=org_id,
                kind=kind,
                title=title[:200],
                body=body[:500] if body else None,
                link=link,
                severity=severity,
            )
        )
        sent += 1
    return sent
