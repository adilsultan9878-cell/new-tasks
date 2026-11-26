"""System health probes (database reachability, RLS posture, uptime)."""

from __future__ import annotations

import time
from functools import lru_cache

from sqlalchemy import text
from sqlalchemy.orm import Session

from app import __version__
from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.schemas.dashboard import DatabaseHealth, SystemHealth

STARTED_AT = time.monotonic()


@lru_cache
def _rls_posture_cached(dialect: str, bypass: bool) -> str:
    if dialect != "postgresql":
        return "not_supported"
    return "bypassed_by_role" if bypass else "enforced"


def database_health(db: Session) -> DatabaseHealth:
    dialect = db.get_bind().dialect.name
    try:
        started = time.perf_counter()
        db.execute(text("SELECT 1"))
        latency = round((time.perf_counter() - started) * 1000, 2)
        bypass = False
        if dialect == "postgresql":
            bypass = bool(
                db.scalar(text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user"))
            )
        return DatabaseHealth(
            status="ok",
            latency_ms=latency,
            engine=dialect,
            row_level_security=_rls_posture_cached(dialect, bypass),
        )
    except Exception:
        return DatabaseHealth(
            status="unavailable", latency_ms=None, engine=dialect, row_level_security="unknown"
        )


def system_health(db: Session) -> SystemHealth:
    database = database_health(db)
    return SystemHealth(
        api="ok",
        version=__version__,
        environment=get_settings().environment,
        database=database,
        realtime="available",  # WebSocket stream at /api/v1/ws
        rate_limiter=limiter.status(),
        uptime_seconds=int(time.monotonic() - STARTED_AT),
    )
