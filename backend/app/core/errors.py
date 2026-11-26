"""Consistent error envelope: {"error": {"code", "message", "request_id", "details?"}}."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm.exc import StaleDataError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import request_id_ctx

log = logging.getLogger("sentinel.errors")


class AppError(Exception):
    """Domain error with an HTTP status and a stable machine-readable code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers


def not_found(what: str = "Resource") -> AppError:
    # Used for both "missing" and "belongs to another tenant" so existence is never leaked.
    return AppError(status.HTTP_404_NOT_FOUND, "not_found", f"{what} not found")


def forbidden(message: str = "You do not have permission to perform this action") -> AppError:
    return AppError(status.HTTP_403_FORBIDDEN, "forbidden", message)


def _envelope(code: str, message: str, details: Any | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message, "request_id": request_id_ctx.get()}
    if details is not None:
        body["details"] = details
    return {"error": body}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            _envelope(exc.code, exc.message, exc.details),
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "method_not_allowed"}.get(
            exc.status_code, "http_error"
        )
        return JSONResponse(
            _envelope(code, str(exc.detail)),
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(p) for p in err.get("loc", ()) if p not in ("body", "query", "path")),
                "message": err.get("msg", "Invalid value"),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            _envelope("validation_error", "Request validation failed", details),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @app.exception_handler(StaleDataError)
    async def _stale(_: Request, exc: StaleDataError) -> JSONResponse:
        # Two requests changed the same record at once (e.g. one deleted it while the other
        # updated it). Not a server fault: the client should reload and try again.
        log.info("Concurrent modification: %s", exc)
        return JSONResponse(
            _envelope(
                "conflict", "This record was changed or deleted by another request — reload and try again"
            ),
            status_code=status.HTTP_409_CONFLICT,
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("Unhandled error: %s", exc.__class__.__name__)
        return JSONResponse(
            _envelope("internal_error", "An unexpected error occurred"),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
