"""Authentication: registration, login with lockout, rotating refresh sessions, logout."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import Request, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.rate_limit import client_ip
from app.core.security import (
    create_access_token,
    hash_password,
    hash_token,
    new_refresh_token,
    password_needs_rehash,
    password_problems,
    verify_password,
)
from app.models import User, UserSession
from app.services import audit

INVALID_CREDENTIALS = AppError(
    status.HTTP_401_UNAUTHORIZED, "invalid_credentials", "Invalid email or password"
)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    # SQLite returns naive datetimes; treat them as UTC.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def normalize_email(email: str) -> str:
    return email.strip().lower()


def register(db: Session, request: Request, *, email: str, password: str, full_name: str) -> User:
    settings = get_settings()
    if not settings.allow_registration:
        raise AppError(status.HTTP_403_FORBIDDEN, "registration_closed", "Registration is disabled")
    email = normalize_email(email)
    problems = password_problems(password, email)
    if problems:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "weak_password",
            problems[0],
            details=[{"field": "password", "message": p} for p in problems],
        )
    if db.scalar(select(User.id).where(User.email == email)):
        raise AppError(status.HTTP_409_CONFLICT, "email_taken", "An account with this email already exists")
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        full_name=full_name,
        password_changed_at=_now(),
    )
    db.add(user)
    db.flush()
    audit.record(
        db, "auth.register", request=request, actor_id=user.id, target_type="user", target_id=user.id
    )
    return user


def authenticate(db: Session, request: Request, *, email: str, password: str) -> User:
    settings = get_settings()
    email = normalize_email(email)
    user = db.scalar(select(User).where(User.email == email))
    now = _now()

    if user is not None and (locked := _aware(user.locked_until)) and locked > now:
        verify_password(password, None)  # keep timing uniform
        audit.record(
            db,
            "auth.login",
            request=request,
            actor_id=user.id,
            outcome="denied",
            target_type="user",
            target_id=user.id,
            details={"reason": "locked"},
        )
        db.commit()
        raise AppError(
            status.HTTP_423_LOCKED,
            "account_locked",
            "Too many failed attempts. The account is temporarily locked; try again later.",
        )

    if user is None or not verify_password(password, user.password_hash) or not user.is_active:
        if user is not None:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.max_failed_logins:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_login_count = 0
        audit.record(
            db,
            "auth.login",
            request=request,
            actor_id=user.id if user else None,
            outcome="failure",
            target_type="user",
            target_id=user.id if user else None,
            details={"email_hash": hash_token(email)[:16]},
        )
        db.commit()
        raise INVALID_CREDENTIALS

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    audit.record(db, "auth.login", request=request, actor_id=user.id, target_type="user", target_id=user.id)
    return user


def start_session(
    db: Session, request: Request, user: User, family_id: uuid.UUID | None = None
) -> tuple[UserSession, str]:
    settings = get_settings()
    raw = new_refresh_token()
    session = UserSession(
        id=uuid.uuid4(),
        user_id=user.id,
        family_id=family_id or uuid.uuid4(),
        token_hash=hash_token(raw),
        expires_at=_now() + timedelta(days=settings.refresh_token_ttl_days),
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
    )
    db.add(session)
    db.flush()
    return session, raw


def issue_tokens(session: UserSession) -> tuple[str, int]:
    return create_access_token(session.user_id, session.id)


def rotate(db: Session, request: Request, raw_token: str) -> tuple[User, UserSession, str]:
    """Exchange a refresh token for a new one. Re-use of a rotated token revokes the family."""
    current = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(raw_token)))
    invalid = AppError(status.HTTP_401_UNAUTHORIZED, "invalid_session", "Session expired; please sign in")
    if current is None:
        raise invalid
    now = _now()
    if current.revoked_at is not None:
        revoked_ago = (now - (_aware(current.revoked_at) or now)).total_seconds()
        family_alive = db.scalar(
            select(UserSession.id).where(
                UserSession.family_id == current.family_id, UserSession.revoked_at.is_(None)
            )
        )
        benign_race = (
            current.revoked_reason == "rotated"
            and revoked_ago <= get_settings().refresh_reuse_grace_seconds
            and family_alive is not None
        )
        if not benign_race:
            if current.revoked_reason == "rotated":
                # A token that was already exchanged is being replayed: assume theft.
                revoke_family(db, current.family_id, "reuse_detected")
                audit.record(
                    db,
                    "auth.refresh_reuse_detected",
                    request=request,
                    actor_id=current.user_id,
                    outcome="denied",
                    target_type="session",
                    target_id=current.family_id,
                )
                db.commit()
            raise invalid
    if (_aware(current.expires_at) or now) <= now:
        raise invalid
    user = db.get(User, current.user_id)
    if user is None or not user.is_active:
        raise invalid

    new_session, new_raw = start_session(db, request, user, family_id=current.family_id)
    if current.revoked_at is None:
        current.revoked_at = now
        current.revoked_reason = "rotated"
        current.replaced_by_id = new_session.id
    current.last_used_at = now
    return user, new_session, new_raw


def revoke_family(db: Session, family_id: uuid.UUID, reason: str) -> None:
    db.execute(
        update(UserSession)
        .where(UserSession.family_id == family_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=_now(), revoked_reason=reason)
    )


def revoke_all_for_user(
    db: Session, user_id: uuid.UUID, reason: str, except_family: uuid.UUID | None = None
) -> None:
    stmt = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_family is not None:
        stmt = stmt.where(UserSession.family_id != except_family)
    db.execute(stmt.values(revoked_at=_now(), revoked_reason=reason))


def logout(db: Session, request: Request, raw_token: str | None) -> None:
    if not raw_token:
        return
    current = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(raw_token)))
    if current is not None:
        revoke_family(db, current.family_id, "logout")
        audit.record(
            db,
            "auth.logout",
            request=request,
            actor_id=current.user_id,
            target_type="session",
            target_id=current.family_id,
        )


def change_password(
    db: Session, request: Request, user: User, session_family: uuid.UUID, current: str, new: str
) -> None:
    if not verify_password(current, user.password_hash):
        audit.record(
            db,
            "auth.password_change",
            request=request,
            actor_id=user.id,
            outcome="failure",
            target_type="user",
            target_id=user.id,
        )
        db.commit()
        raise AppError(status.HTTP_400_BAD_REQUEST, "invalid_password", "Current password is incorrect")
    problems = password_problems(new, user.email)
    if current == new:
        problems.insert(0, "New password must differ from the current password")
    if problems:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "weak_password",
            problems[0],
            details=[{"field": "new_password", "message": p} for p in problems],
        )
    user.password_hash = hash_password(new)
    user.password_changed_at = _now()
    # Sign out every other device; the current session family stays valid.
    revoke_all_for_user(db, user.id, "password_changed", except_family=session_family)
    audit.record(
        db, "auth.password_change", request=request, actor_id=user.id, target_type="user", target_id=user.id
    )
