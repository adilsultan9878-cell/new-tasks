from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import DB, OrgContext, require
from app.schemas.dashboard import DashboardSummary
from app.services.dashboard import build_summary

router = APIRouter(prefix="/organizations/{org_id}/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(ctx: Annotated[OrgContext, Depends(require("dashboard:read"))], db: DB) -> DashboardSummary:
    return build_summary(db, ctx.org_id)
