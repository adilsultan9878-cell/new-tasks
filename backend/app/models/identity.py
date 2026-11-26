"""Identity & tenancy: users, organizations, memberships, RBAC, sessions, audit, notifications."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, Timestamps, UUIDPrimaryKey, in_values, utcnow

MEMBER_STATUSES = ("active", "suspended")
AUDIT_OUTCOMES = ("success", "failure", "denied")
ACTOR_TYPES = ("user", "system", "agent", "device")
SEVERITIES = ("info", "low", "medium", "high", "critical")


class User(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email"),)

    email: Mapped[str] = mapped_column(String(320))  # stored lower-cased
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(120))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    email_verified_at: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None]
    password_changed_at: Mapped[datetime | None]

    memberships: Mapped[list[OrganizationMember]] = relationship(
        back_populates="user", foreign_keys="OrganizationMember.user_id"
    )


class Organization(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "organizations"
    __table_args__ = (UniqueConstraint("slug"),)

    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(80))
    description: Mapped[str | None] = mapped_column(Text)
    industry: Mapped[str | None] = mapped_column(String(80))
    plan: Mapped[str] = mapped_column(String(32), default="free", server_default="free")
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    members: Mapped[list[OrganizationMember]] = relationship(back_populates="organization")


class Role(UUIDPrimaryKey, Timestamps, Base):
    """System roles have organization_id NULL; custom per-organization roles are reserved for later."""

    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("organization_id", "key"),)

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    key: Mapped[str] = mapped_column(String(48))
    name: Mapped[str] = mapped_column(String(80))
    description: Mapped[str | None] = mapped_column(Text)
    rank: Mapped[int] = mapped_column(Integer)  # higher rank = more privileged
    is_system: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())

    permissions: Mapped[list[Permission]] = relationship(secondary="role_permissions", lazy="selectin")


class Permission(UUIDPrimaryKey, Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("key"),)

    key: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )


class OrganizationMember(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "organization_members"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id"),
        CheckConstraint(in_values("status", MEMBER_STATUSES), name="status"),
        Index("ix_organization_members_user", "user_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"))
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    invited_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    organization: Mapped[Organization] = relationship(back_populates="members")
    user: Mapped[User] = relationship(back_populates="memberships", foreign_keys=[user_id])
    role: Mapped[Role] = relationship(lazy="joined")


class EmailToken(UUIDPrimaryKey, Base):
    """Single-use link token for password reset or e-mail verification. Only its SHA-256 is stored."""

    __tablename__ = "email_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash"),
        CheckConstraint(in_values("purpose", ("reset", "verify")), name="purpose"),
        Index("ix_email_tokens_user", "user_id", "purpose"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    purpose: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]


class Invitation(UUIDPrimaryKey, Base):
    """An invitation to join an organization, sent to an e-mail address (account optional)."""

    __tablename__ = "invitations"
    __table_args__ = (
        UniqueConstraint("token_hash"),
        Index("ix_invitations_org", "organization_id", "accepted_at"),
        Index("ix_invitations_email", "email"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    email: Mapped[str] = mapped_column(String(320))
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64))
    invited_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    emailed: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    accepted_at: Mapped[datetime | None]
    accepted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    revoked_at: Mapped[datetime | None]


class UserSession(UUIDPrimaryKey, Base):
    """A refresh-token session. Tokens rotate on every refresh; reuse revokes the whole family."""

    __tablename__ = "user_sessions"
    __table_args__ = (
        UniqueConstraint("token_hash"),
        Index("ix_user_sessions_user", "user_id"),
        Index("ix_user_sessions_family", "family_id"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    family_id: Mapped[uuid.UUID]
    token_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    replaced_by_id: Mapped[uuid.UUID | None]
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))


class AuditLog(UUIDPrimaryKey, Base):
    """Append-only security audit trail (UPDATE is blocked by a trigger on PostgreSQL)."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint(in_values("outcome", AUDIT_OUTCOMES), name="outcome"),
        CheckConstraint(in_values("actor_type", ACTOR_TYPES), name="actor_type"),
        Index("ix_audit_logs_org_created", "organization_id", "created_at"),
        Index("ix_audit_logs_actor_created", "actor_user_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_type: Mapped[str] = mapped_column(String(16), default="user")
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str | None] = mapped_column(String(48))
    target_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    request_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    actor: Mapped[User | None] = relationship(lazy="joined")


class Notification(UUIDPrimaryKey, Base):
    __tablename__ = "notifications"
    __table_args__ = (
        CheckConstraint(in_values("severity", SEVERITIES), name="severity"),
        Index("ix_notifications_user_created", "user_id", "created_at"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    kind: Mapped[str] = mapped_column(String(48))
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str | None] = mapped_column(Text)
    link: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    read_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
