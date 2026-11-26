from __future__ import annotations

import hmac
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app import __version__
from app.api.deps import DB
from app.core.config import get_settings
from app.core.errors import not_found
from app.core.metrics import START, registry, render
from app.core.rate_limit import limiter
from app.services.health import database_health

router = APIRouter(tags=["health"])
metrics_router = APIRouter(include_in_schema=False)


@router.get("/health", summary="Liveness probe")
def liveness() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


def _jobs() -> dict[str, dict[str, object]]:
    """Background loops must keep running; a stale one means the API needs a restart."""
    s = get_settings()
    now = time.time()
    out: dict[str, dict[str, object]] = {}
    for job, interval in (
        ("sweeper", s.device_sweep_interval_seconds),
        ("automation", s.automation_tick_seconds),
    ):
        last = registry.job_runs.get(job)
        allowed = 3 * interval + 30
        if last is None:
            ok = now - START < allowed  # still starting up
            age = None
        else:
            age = round(now - last)
            ok = age < allowed
        out[job] = {"status": "ok" if ok else "stale", "seconds_since_last_run": age}
    return out


@router.get("/health/ready", summary="Readiness probe: database, background jobs, rate-limit store")
def readiness(db: DB) -> JSONResponse:
    database = database_health(db)
    jobs = _jobs()
    limiter_state = limiter.status()  # memory | redis | redis_unavailable (falls back, not fatal)
    ok = database.status == "ok" and all(j["status"] == "ok" for j in jobs.values())
    return JSONResponse(
        {
            "status": "ok" if ok else "degraded",
            "version": __version__,
            "database": database.model_dump(),
            "jobs": jobs,
            "rate_limiter": limiter_state,
        },
        status_code=200 if ok else 503,
    )


@metrics_router.get("/metrics")
def metrics(request: Request) -> PlainTextResponse:
    token = get_settings().metrics_token
    given = request.headers.get("authorization", "")
    if not token or not hmac.compare_digest(given.encode(), f"Bearer {token}".encode()):
        raise not_found("Page")  # invisible unless enabled and authorized
    return PlainTextResponse(render(), media_type="text/plain; version=0.0.4")
