from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import DB, OrgContext, require
from app.models import AuditLog
from app.schemas.audit import AuditLogOut
from app.schemas.common import Page

router = APIRouter(prefix="/organizations/{org_id}/audit-logs", tags=["audit"])


@router.get("", response_model=Page[AuditLogOut])
def list_audit_logs(
    ctx: Annotated[OrgContext, Depends(require("audit:read"))],
    db: DB,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    action: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_.]+$")] = None,
    outcome: Annotated[str | None, Query(pattern=r"^(success|failure|denied)$")] = None,
    since: datetime | None = None,
) -> Page[AuditLogOut]:
    filters = [AuditLog.organization_id == ctx.org_id]
    if action:
        filters.append(AuditLog.action.startswith(action))
    if outcome:
        filters.append(AuditLog.outcome == outcome)
    if since:
        filters.append(AuditLog.created_at >= since)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*filters)) or 0
    rows = db.scalars(
        select(AuditLog).where(*filters).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[AuditLogOut](
        items=[AuditLogOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )
