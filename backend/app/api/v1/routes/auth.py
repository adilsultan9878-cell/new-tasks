from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response, status
from sqlalchemy import select

from app.api.deps import DB, CurrentPrincipal
from app.core.config import get_settings
from app.core.errors import AppError
from app.core.rate_limit import auth_rate_limit, enforce, refresh_rate_limit
from app.models import User, UserSession
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    SessionOut,
    TokenResponse,
    UpdateProfileRequest,
    UserOut,
)
from app.schemas.common import Message
from app.services import audit
from app.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["auth"])

CSRF_HEADER_VALUE = "sentinel-x"


def require_csrf_header(x_requested_with: Annotated[str | None, Header()] = None) -> None:
    """Cookie-authenticated endpoints demand a custom header. Browsers cannot attach it
    cross-origin without a CORS preflight, which only allowed origins pass."""
    if x_requested_with != CSRF_HEADER_VALUE:
        raise AppError(status.HTTP_403_FORBIDDEN, "csrf_failed", "Missing X-Requested-With header")


def user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        email_verified=user.email_verified_at is not None,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


def _set_refresh_cookie(response: Response, raw: str) -> None:
    s = get_settings()
    response.set_cookie(
        s.refresh_cookie_name,
        raw,
        max_age=s.refresh_token_ttl_days * 86400,
        httponly=True,
        secure=s.refresh_cookie_secure,
        samesite=s.refresh_cookie_samesite,
        domain=s.refresh_cookie_domain,
        path=f"{s.api_prefix}/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    s = get_settings()
    response.delete_cookie(
        s.refresh_cookie_name,
        path=f"{s.api_prefix}/auth",
        domain=s.refresh_cookie_domain,
        secure=s.refresh_cookie_secure,
        httponly=True,
        samesite=s.refresh_cookie_samesite,
    )


def _token_response(response: Response, user: User, session: UserSession, raw: str) -> TokenResponse:
    access, expires_in = auth_service.issue_tokens(session)
    _set_refresh_cookie(response, raw)
    return TokenResponse(access_token=access, expires_in=expires_in, user=user_out(user))


def _refresh_cookie(request: Request) -> str | None:
    return request.cookies.get(get_settings().refresh_cookie_name)


@router.post(
    "/register", response_model=TokenResponse, status_code=201, dependencies=[Depends(auth_rate_limit)]
)
def register(body: RegisterRequest, request: Request, response: Response, db: DB) -> TokenResponse:
    user = auth_service.register(
        db, request, email=body.email, password=body.password, full_name=body.full_name
    )
    user.last_login_at = datetime.now(UTC)
    session, raw = auth_service.start_session(db, request, user)
    db.commit()
    return _token_response(response, user, session, raw)


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(auth_rate_limit)])
def login(body: LoginRequest, request: Request, response: Response, db: DB) -> TokenResponse:
    # Per-account limit as well as per-IP, to slow distributed guessing against one user.
    enforce(request, "login-account", get_settings().rate_limit_auth_per_minute, extra_key=body.email.lower())
    user = auth_service.authenticate(db, request, email=body.email, password=body.password)
    session, raw = auth_service.start_session(db, request, user)
    db.commit()
    return _token_response(response, user, session, raw)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(require_csrf_header), Depends(refresh_rate_limit)],
)
def refresh(request: Request, response: Response, db: DB) -> TokenResponse:
    sx_refresh = _refresh_cookie(request)
    if not sx_refresh:
        raise AppError(status.HTTP_401_UNAUTHORIZED, "invalid_session", "No active session")
    try:
        user, session, raw = auth_service.rotate(db, request, sx_refresh)
    except AppError as exc:
        # The error envelope is a new response, so carry the cookie deletion over explicitly.
        scratch = Response()
        _clear_refresh_cookie(scratch)
        exc.headers = {**(exc.headers or {}), "set-cookie": scratch.headers["set-cookie"]}
        raise
    db.commit()
    return _token_response(response, user, session, raw)


@router.post("/logout", response_model=Message, dependencies=[Depends(require_csrf_header)])
def logout(request: Request, response: Response, db: DB) -> Message:
    auth_service.logout(db, request, _refresh_cookie(request))
    db.commit()
    _clear_refresh_cookie(response)
    return Message(message="Signed out")


@router.post("/logout-all", response_model=Message)
def logout_all(principal: CurrentPrincipal, request: Request, response: Response, db: DB) -> Message:
    auth_service.revoke_all_for_user(db, principal.user.id, "logout_all")
    audit.record(
        db,
        "auth.logout_all",
        request=request,
        actor_id=principal.user.id,
        target_type="user",
        target_id=principal.user.id,
    )
    db.commit()
    _clear_refresh_cookie(response)
    return Message(message="Signed out of all sessions")


@router.get("/me", response_model=UserOut)
def me(principal: CurrentPrincipal) -> UserOut:
    return user_out(principal.user)


@router.patch("/me", response_model=UserOut)
def update_me(body: UpdateProfileRequest, principal: CurrentPrincipal, request: Request, db: DB) -> UserOut:
    principal.user.full_name = body.full_name
    audit.record(
        db,
        "user.profile_update",
        request=request,
        actor_id=principal.user.id,
        target_type="user",
        target_id=principal.user.id,
    )
    db.commit()
    return user_out(principal.user)


@router.post("/change-password", response_model=Message, dependencies=[Depends(auth_rate_limit)])
def change_password(
    body: ChangePasswordRequest, principal: CurrentPrincipal, request: Request, db: DB
) -> Message:
    auth_service.change_password(
        db, request, principal.user, principal.session_family, body.current_password, body.new_password
    )
    db.commit()
    return Message(message="Password updated. Other sessions were signed out.")


@router.get("/sessions", response_model=list[SessionOut])
def sessions(principal: CurrentPrincipal, db: DB) -> list[SessionOut]:
    rows = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == principal.user.id, UserSession.revoked_at.is_(None))
        .order_by(UserSession.created_at.desc())
        .limit(50)
    ).all()
    now = datetime.now(UTC)
    out = []
    for row in rows:
        expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
        if expires <= now:
            continue
        item = SessionOut.model_validate(row)
        item.current = row.family_id == principal.session_family
        out.append(item)
    return out
