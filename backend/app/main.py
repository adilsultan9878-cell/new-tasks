"""FastAPI application factory for SENTINEL X — AEGIS NEXUS."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1.health_alias import router as root_health_router
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging
from app.core.middleware import install_middleware

log = logging.getLogger("sentinel")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    import asyncio
    import contextlib

    from app.automation import signing, worker
    from app.services import sweeper

    settings = get_settings()
    if not settings.jwt_secret:
        log.warning(
            "JWT_SECRET is not set: using an ephemeral development secret "
            "(access tokens are invalidated on restart)"
        )
    log.info(
        "SENTINEL X API %s starting (env=%s, db=%s)",
        __version__,
        settings.environment,
        settings.database_url.split("://", 1)[0],
    )
    if signing.key_source() != "dedicated":
        log.warning(
            "AUTOMATION_SIGNING_KEY is not set: webhook secrets are derived from %s",
            "JWT_SECRET" if signing.key_source() == "jwt" else "an ephemeral key (they change on restart)",
        )
    tasks = [
        asyncio.create_task(sweeper.run_forever(), name="device-sweeper"),
        asyncio.create_task(worker.run_forever(), name="automation-worker"),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    docs_enabled = settings.environment != "production"
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Unified AI-assisted security operations platform (AEGIS ONE · NEXUS ZERO · SENTINEL X).",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
        max_body_size=settings.max_request_bytes,  # upload routes override it (app/core/limits.py)
    )
    install_error_handlers(app)
    install_middleware(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
        max_age=600,
    )
    app.include_router(root_health_router)
    app.include_router(api_router, prefix=settings.api_prefix)
    return app


app = create_app()
