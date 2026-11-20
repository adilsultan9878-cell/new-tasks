"""WebSocket stream of organization events.

Protocol:
  1. client connects to /api/v1/ws (browser Origin must be an allowed console origin)
  2. client sends {"type": "auth", "token": "<access token>", "org_id": "<uuid>"} within 10 s
     (the token is never put in the URL, so it does not end up in proxy/access logs)
  3. server answers {"type": "ready"} and then pushes messages such as event.created,
     event.updated, alert.created, device.updated; a {"type": "ping"} keeps proxies alive
  4. every few minutes the server re-checks the session and membership; logout, removal from the
     organization or a password change closes the stream (code 4401/4403).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from app.api.deps import load_permissions
from app.core.config import get_settings
from app.core.security import decode_access_token
from app.db.session import get_sessionmaker, set_tenant_context
from app.models import OrganizationMember, User, UserSession
from app.services.realtime import hub

router = APIRouter(tags=["realtime"])
log = logging.getLogger("sentinel.ws")

CLOSE_UNAUTHENTICATED = 4401
CLOSE_FORBIDDEN = 4403
CLOSE_TIMEOUT = 4408


class Denied(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _origin_allowed(websocket: WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    if not origin:
        return True  # non-browser clients (they still need a valid token)
    origin = origin.rstrip("/")
    if origin in get_settings().cors_origins:
        return True
    host = websocket.headers.get("host", "")
    return urlsplit(origin).netloc == host


def _authorize(token: str, org_id: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    try:
        claims = decode_access_token(token)
        user_id = uuid.UUID(claims["sub"])
        session_id = uuid.UUID(claims["sid"])
    except (jwt.PyJWTError, ValueError, KeyError):
        raise Denied(CLOSE_UNAUTHENTICATED, "invalid token") from None
    with get_sessionmaker()() as db:
        session = db.get(UserSession, session_id)
        if session is None or session.user_id != user_id:
            raise Denied(CLOSE_UNAUTHENTICATED, "invalid session")
        family = session.family_id
    _check_access(user_id, family, org_id)
    return user_id, family


def _check_access(user_id: uuid.UUID, family_id: uuid.UUID, org_id: uuid.UUID) -> None:
    now = datetime.now(UTC)
    with get_sessionmaker()() as db:
        set_tenant_context(db, user_id=user_id)
        alive = db.scalars(
            select(UserSession.expires_at).where(
                UserSession.family_id == family_id, UserSession.revoked_at.is_(None)
            )
        ).all()
        if not any((e if e.tzinfo else e.replace(tzinfo=UTC)) > now for e in alive):
            raise Denied(CLOSE_UNAUTHENTICATED, "session ended")
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            raise Denied(CLOSE_UNAUTHENTICATED, "user inactive")
        member = db.scalar(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.user_id == user_id,
                OrganizationMember.status == "active",
            )
        )
        if member is None or "events:read" not in load_permissions(db, member.role_id):
            raise Denied(CLOSE_FORBIDDEN, "not a member")


@router.websocket("/ws")
async def stream(websocket: WebSocket) -> None:
    settings = get_settings()
    if not _origin_allowed(websocket):
        await websocket.close(code=CLOSE_FORBIDDEN, reason="origin not allowed")
        return
    await websocket.accept()
    try:
        hello = await asyncio.wait_for(websocket.receive_json(), timeout=settings.ws_auth_timeout_seconds)
        if not isinstance(hello, dict) or hello.get("type") != "auth":
            raise Denied(CLOSE_UNAUTHENTICATED, "expected auth message")
        org_id = uuid.UUID(str(hello.get("org_id")))
        user_id, family = await run_in_threadpool(_authorize, str(hello.get("token", "")), org_id)
    except TimeoutError:
        await websocket.close(code=CLOSE_TIMEOUT, reason="auth timeout")
        return
    except (ValueError, TypeError):
        await websocket.close(code=CLOSE_UNAUTHENTICATED, reason="malformed auth message")
        return
    except Denied as denied:
        await websocket.close(code=denied.code, reason=denied.reason)
        return
    except WebSocketDisconnect:
        return

    sub = hub.subscribe(org_id, user_id)
    await websocket.send_json({"type": "ready", "data": {"org_id": str(org_id)}})

    async def drain_client() -> None:
        # Consume (and ignore) client frames so disconnects are noticed promptly.
        while True:
            msg = await websocket.receive_text()
            if msg == '{"type":"ping"}':
                await websocket.send_json({"type": "pong"})

    reader = asyncio.create_task(drain_client())
    loop = asyncio.get_running_loop()
    next_check = loop.time() + settings.ws_revalidate_seconds
    try:
        while not reader.done():
            try:
                msg = await asyncio.wait_for(sub.queue.get(), timeout=settings.ws_ping_interval_seconds)
                await websocket.send_json(msg)
            except TimeoutError:
                await websocket.send_json({"type": "ping"})
            if loop.time() >= next_check:
                next_check = loop.time() + settings.ws_revalidate_seconds
                try:
                    await run_in_threadpool(_check_access, user_id, family, org_id)
                except Denied as denied:
                    await websocket.close(code=denied.code, reason=denied.reason)
                    return
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.unsubscribe(sub)
        reader.cancel()
        with contextlib.suppress(asyncio.CancelledError, WebSocketDisconnect, RuntimeError):
            await reader
