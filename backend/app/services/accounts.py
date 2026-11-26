"""Phase 10 account flows: registration policy, password reset, e-mail verification, invitations.

Rules (tested in tests/test_accounts.py):

* Link tokens are 256-bit random values; only their SHA-256 is stored. They are single-use, expire
  (reset 30 min, verification 48 h, invitations 7 days) and a new reset link cancels older ones.
* "Forgot password" never reveals whether an address has an account: the same answer for every
  address, and the same "not configured" answer for every address when e-mail is off.
* A password reset ends every session of the account.
* An invitation is bound to an e-mail address: only an account with that address can accept it,
  and nobody can invite into a role above their own.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import BackgroundTasks, Request, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, not_found
from app.core.security import hash_password, hash_token, password_problems
from app.db.session import set_tenant_context
from app.models import EmailToken, Invitation, Notification, Organization, OrganizationMember, Role, User
from app.services import audit
from app.services import email as mail
from app.services.auth import normalize_email, revoke_all_for_user

EMAIL_OFF = AppError(
    status.HTTP_503_SERVICE_UNAVAILABLE,
    "email_disabled",
    "E-mail is not configured on this server — ask an administrator to reset your password",
)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def platform_is_empty(db: Session) -> bool:
    return db.scalar(select(User.id).limit(1)) is None


def policy(db: Session) -> dict[str, Any]:
    s = get_settings()
    return {
        "registration": s.effective_registration_mode,
        # A brand-new installation must be able to create its first (owner) account even when
        # sign-up is invite-only: nobody exists yet who could send an invitation.
        "first_account": platform_is_empty(db),
        "allowed_domains": s.allowed_email_domains if s.effective_registration_mode == "domains" else [],
        "password_reset": s.email_enabled,
        "email_verification": s.email_enabled,
        "email_verification_required": s.require_email_verification,
    }


# ------------------------------------------------------------------------ registration policy
def check_registration(db: Session, email: str, invitation_token: str | None) -> Invitation | None:
    """Raise if this address may not sign up. Returns the matching invitation, if one was used."""
    s = get_settings()
    email = normalize_email(email)
    invitation = None
    if invitation_token:
        invitation = _invitation_by_token(db, invitation_token)
        if invitation is None or invitation.email != email:
            raise AppError(
                status.HTTP_403_FORBIDDEN,
                "invalid_invitation",
                "This invitation is not valid for this address",
            )
    mode = s.effective_registration_mode
    if invitation is not None or mode == "open" or platform_is_empty(db):
        return invitation
    if mode == "domains" and email.rsplit("@", 1)[-1] in s.allowed_email_domains:
        return None
    message = (
        "Sign-up needs an invitation from an organization administrator"
        if mode == "invite_only"
        else f"Sign-up is limited to addresses at {', '.join(s.allowed_email_domains)}"
    )
    raise AppError(status.HTTP_403_FORBIDDEN, "registration_closed", message)


# ------------------------------------------------------------------------------- link tokens
def _issue(db: Session, user: User, purpose: str, ttl: timedelta) -> str:
    # Older unused links of the same kind stop working: only the newest one counts.
    db.execute(
        update(EmailToken)
        .where(EmailToken.user_id == user.id, EmailToken.purpose == purpose, EmailToken.used_at.is_(None))
        .values(used_at=_now())
    )
    raw = secrets.token_urlsafe(32)
    db.add(
        EmailToken(
            id=uuid.uuid4(),
            user_id=user.id,
            purpose=purpose,
            token_hash=hash_token(raw),
            created_at=_now(),
            expires_at=_now() + ttl,
        )
    )
    db.flush()
    return raw


def _consume(db: Session, raw: str, purpose: str) -> EmailToken:
    token = db.scalar(
        select(EmailToken).where(EmailToken.token_hash == hash_token(raw), EmailToken.purpose == purpose)
    )
    if token is None or token.used_at is not None or (_aware(token.expires_at) or _now()) <= _now():
        raise AppError(
            status.HTTP_400_BAD_REQUEST,
            "invalid_token",
            "This link is invalid or has expired — request a new one",
        )
    token.used_at = _now()
    return token


def _recent_mails(db: Session, user: User, purpose: str) -> int:
    since = _now() - timedelta(hours=1)
    return len(
        db.scalars(
            select(EmailToken.id).where(
                EmailToken.user_id == user.id, EmailToken.purpose == purpose, EmailToken.created_at >= since
            )
        ).all()
    )


# ---------------------------------------------------------------------------- password reset
def request_reset(db: Session, request: Request, background: BackgroundTasks, email: str) -> None:
    s = get_settings()
    if not s.email_enabled:
        raise EMAIL_OFF
    user = db.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None or not user.is_active or _recent_mails(db, user, "reset") >= s.rate_limit_email_per_hour:
        return  # same answer either way: no account enumeration
    raw = _issue(db, user, "reset", timedelta(minutes=s.password_reset_ttl_minutes))
    audit.record(
        db,
        "auth.password_reset_request",
        request=request,
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
    )
    mail.queue(
        background,
        mail.Email(
            to=user.email,
            subject="Reset your SENTINEL X password",
            text=(
                f"Hello {user.full_name},\n\n"
                f"Someone (hopefully you) asked to reset the password of this SENTINEL X account.\n"
                f"Open this link within {s.password_reset_ttl_minutes} minutes to choose a new one:\n\n"
                f"{mail.link('/reset-password', raw)}\n\n"
                "If it was not you, ignore this message: your password stays the same.\n"
                "Resetting the password signs out every device."
            ),
        ),
    )


def confirm_reset(db: Session, request: Request, raw: str, new_password: str) -> User:
    token = _consume(db, raw, "reset")
    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        raise AppError(status.HTTP_400_BAD_REQUEST, "invalid_token", "This link is invalid or has expired")
    problems = password_problems(new_password, user.email)
    if problems:
        token.used_at = None  # let them try again with a stronger password
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "weak_password",
            problems[0],
            details=[{"field": "password", "message": p} for p in problems],
        )
    user.password_hash = hash_password(new_password)
    user.password_changed_at = _now()
    user.failed_login_count = 0
    user.locked_until = None
    if user.email_verified_at is None:
        user.email_verified_at = _now()  # the link reached the inbox: the address is theirs
    revoke_all_for_user(db, user.id, "password_reset")
    audit.record(
        db, "auth.password_reset", request=request, actor_id=user.id, target_type="user", target_id=user.id
    )
    return user


# ------------------------------------------------------------------------ e-mail verification
def send_verification(
    db: Session, request: Request | None, background: BackgroundTasks | None, user: User
) -> bool:
    s = get_settings()
    if not s.email_enabled or user.email_verified_at is not None:
        return False
    if _recent_mails(db, user, "verify") >= s.rate_limit_email_per_hour:
        raise AppError(
            status.HTTP_429_TOO_MANY_REQUESTS, "rate_limited", "Too many e-mails — try again in an hour"
        )
    raw = _issue(db, user, "verify", timedelta(hours=s.email_verification_ttl_hours))
    mail.queue(
        background,
        mail.Email(
            to=user.email,
            subject="Confirm your e-mail address for SENTINEL X",
            text=(
                f"Hello {user.full_name},\n\nPlease confirm that this address belongs to you:\n\n"
                f"{mail.link('/verify-email', raw)}\n\n"
                f"The link works for {s.email_verification_ttl_hours} hours. If you did not create an account, ignore it."
            ),
        ),
    )
    return True


def confirm_verification(db: Session, request: Request, raw: str) -> User:
    token = _consume(db, raw, "verify")
    user = db.get(User, token.user_id)
    if user is None:
        raise AppError(status.HTTP_400_BAD_REQUEST, "invalid_token", "This link is invalid or has expired")
    user.email_verified_at = user.email_verified_at or _now()
    audit.record(
        db, "auth.email_verified", request=request, actor_id=user.id, target_type="user", target_id=user.id
    )
    return user


def require_verified(user: User) -> None:
    if get_settings().require_email_verification and user.email_verified_at is None:
        raise AppError(
            status.HTTP_403_FORBIDDEN,
            "email_not_verified",
            "Confirm your e-mail address first (see your inbox)",
        )


# -------------------------------------------------------------------------------- invitations
def _invitation_by_token(db: Session, raw: str) -> Invitation | None:
    inv = db.scalar(select(Invitation).where(Invitation.token_hash == hash_token(raw)))
    if inv is None or inv.accepted_at or inv.revoked_at or (_aware(inv.expires_at) or _now()) <= _now():
        return None
    return inv


def invite(
    db: Session,
    request: Request,
    background: BackgroundTasks,
    actor: OrganizationMember,
    *,
    email: str,
    role_key: str,
) -> tuple[Invitation, str | None]:
    """Returns the invitation and, when e-mail is off, the link for the inviter to pass on."""
    from app.services.organizations import _assert_can_assign, get_system_role

    s = get_settings()
    email = normalize_email(email)
    role = get_system_role(db, role_key)
    _assert_can_assign(actor, role)
    member = db.scalar(
        select(OrganizationMember.id)
        .join(User, User.id == OrganizationMember.user_id)
        .where(OrganizationMember.organization_id == actor.organization_id, User.email == email)
    )
    if member:
        raise AppError(status.HTTP_409_CONFLICT, "already_member", "That address already belongs to a member")
    db.execute(
        update(Invitation)
        .where(
            Invitation.organization_id == actor.organization_id,
            Invitation.email == email,
            Invitation.accepted_at.is_(None),
            Invitation.revoked_at.is_(None),
        )
        .values(revoked_at=_now())
    )
    raw = secrets.token_urlsafe(32)
    inv = Invitation(
        id=uuid.uuid4(),
        organization_id=actor.organization_id,
        email=email,
        role_id=role.id,
        token_hash=hash_token(raw),
        invited_by=actor.user_id,
        emailed=s.email_enabled,
        created_at=_now(),
        expires_at=_now() + timedelta(days=s.invitation_ttl_days),
    )
    db.add(inv)
    db.flush()
    org = db.get(Organization, actor.organization_id)
    inviter = db.get(User, actor.user_id)
    audit.record(
        db,
        "member.invite",
        request=request,
        actor_id=actor.user_id,
        org_id=actor.organization_id,
        target_type="invitation",
        target_id=inv.id,
        details={"email": email, "role": role.key, "emailed": inv.emailed},
    )
    link = mail.link("/invite", raw)
    if s.email_enabled:
        mail.queue(
            background,
            mail.Email(
                to=email,
                subject=f"You are invited to {org.name if org else 'an organization'} on SENTINEL X",
                text=(
                    f"{inviter.full_name if inviter else 'An administrator'} invited you to join "
                    f"{org.name if org else 'their organization'} on SENTINEL X as {role.name}.\n\n"
                    f"Accept within {s.invitation_ttl_days} days (you can create an account on the way):\n\n{link}\n\n"
                    "If you did not expect this, ignore the message."
                ),
            ),
        )
        return inv, None
    return inv, link


def lookup(db: Session, raw: str) -> dict[str, Any]:
    inv = _invitation_by_token(db, raw)
    if inv is None:
        raise not_found("Invitation")
    org = db.get(Organization, inv.organization_id)
    role = db.get(Role, inv.role_id)
    local, _, domain = inv.email.partition("@")
    return {
        "organization_name": org.name if org else "",
        "role": role.name if role else "",
        "email": inv.email,
        "email_hint": f"{local[:2]}{'•' * max(1, len(local) - 2)}@{domain}",
        "expires_at": inv.expires_at,
        "account_exists": db.scalar(select(User.id).where(User.email == inv.email)) is not None,
    }


def accept(db: Session, request: Request, user: User, raw: str) -> OrganizationMember:
    inv = _invitation_by_token(db, raw)
    if inv is None:
        raise not_found("Invitation")
    if inv.email != normalize_email(user.email):
        raise AppError(
            status.HTTP_403_FORBIDDEN,
            "wrong_account",
            f"This invitation is for {inv.email} — sign in with that account",
        )
    if inv.emailed and user.email_verified_at is None:
        user.email_verified_at = _now()  # the invitation link arrived in this inbox
    require_verified(user)
    # The valid, address-bound token is the authorization to enter this organization: bind it as
    # the tenant so Row-Level Security admits the membership, notification and audit rows.
    set_tenant_context(db, org_id=inv.organization_id, user_id=user.id)
    existing = db.scalar(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == inv.organization_id, OrganizationMember.user_id == user.id
        )
    )
    if existing is not None:
        raise AppError(
            status.HTTP_409_CONFLICT, "already_member", "You are already a member of this organization"
        )
    member = OrganizationMember(
        id=uuid.uuid4(),
        organization_id=inv.organization_id,
        user_id=user.id,
        role_id=inv.role_id,
        invited_by=inv.invited_by,
    )
    db.add(member)
    inv.accepted_at = _now()
    inv.accepted_by = user.id
    if inv.invited_by:
        db.add(
            Notification(
                id=uuid.uuid4(),
                user_id=inv.invited_by,
                organization_id=inv.organization_id,
                kind="membership",
                title=f"{user.full_name} accepted your invitation",
                body=user.email,
                link="/members",
                severity="info",
            )
        )
    audit.record(
        db,
        "member.invite_accept",
        request=request,
        actor_id=user.id,
        org_id=inv.organization_id,
        target_type="invitation",
        target_id=inv.id,
    )
    db.flush()
    db.refresh(member)
    return member
