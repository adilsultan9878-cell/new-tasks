from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app import __version__
from app.api.deps import DB
from app.services.health import database_health

router = APIRouter(tags=["health"])


@router.get("/health", summary="Liveness probe")
def liveness() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/health/ready", summary="Readiness probe (checks the database)")
def readiness(db: DB) -> JSONResponse:
    database = database_health(db)
    ok = database.status == "ok"
    return JSONResponse(
        {"status": "ok" if ok else "degraded", "version": __version__, "database": database.model_dump()},
        status_code=200 if ok else 503,
    )
