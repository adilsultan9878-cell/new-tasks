"""HTTP middleware: request IDs, access logging, security headers and a global rate limit."""

from __future__ import annotations

import logging
import re
import time
import uuid

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import get_settings
from app.core.logging import request_id_ctx
from app.core.rate_limit import client_ip, limiter

log = logging.getLogger("sentinel.http")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    # The API only returns JSON; the interactive docs need inline assets, so they are excluded.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


class SecurityHeadersMiddleware:
    """Outermost ASGI layer: every response carries the security headers.

    Some responses never reach the application middleware — CORS preflights answered by
    CORSMiddleware and 413s for oversized bodies refused before routing. Wrapping the whole stack
    covers them too (found by the OWASP ZAP scan in Phase 9).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        settings = get_settings()
        self.api_prefix = settings.api_prefix
        self.production = settings.environment == "production"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=list(message.get("headers", [])))
                for name, value in SECURITY_HEADERS.items():
                    if name == "Content-Security-Policy" and path in ("/docs", "/redoc"):
                        continue  # the interactive docs need inline assets
                    if name not in headers:
                        headers[name] = value
                if self.production:
                    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
                if path.startswith(self.api_prefix) and "cache-control" not in headers:
                    headers["Cache-Control"] = "no-store"
                message["headers"] = headers.raw
            await send(message)

        await self.app(scope, receive, send_with_headers)


def install_middleware(app: FastAPI) -> None:
    settings = get_settings()

    @app.middleware("http")
    async def request_context(request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        token = request_id_ctx.set(request_id)
        started = time.perf_counter()
        try:
            if settings.rate_limit_enabled and request.url.path.startswith(settings.api_prefix):
                allowed, retry = limiter.hit(
                    f"global:{client_ip(request)}", settings.rate_limit_default_per_minute
                )
                if not allowed:
                    response: Response = JSONResponse(
                        {
                            "error": {
                                "code": "rate_limited",
                                "message": "Too many requests",
                                "request_id": request_id,
                            }
                        },
                        status_code=429,
                        headers={"Retry-After": str(retry)},
                    )
                else:
                    response = await call_next(request)
            else:
                response = await call_next(request)

            response.headers["X-Request-ID"] = request_id  # security headers: SecurityHeadersMiddleware
            log.info(
                "request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "client": client_ip(request),
                },
            )
            return response
        finally:
            request_id_ctx.reset(token)
