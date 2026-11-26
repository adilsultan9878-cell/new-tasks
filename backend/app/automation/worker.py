"""Automation worker (lifespan task): schedules, approval expiry and webhook deliveries.

Visits organizations one at a time with that organization bound as the tenant, so PostgreSQL
Row-Level Security applies here too. Safe on several instances: due schedules and deliveries are
claimed with ``FOR UPDATE SKIP LOCKED`` and a schedule slot can only run once (unique dedupe key).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.automation import delivery, engine
from app.core.config import get_settings
from app.core.metrics import registry
from app.db.session import get_sessionmaker, set_tenant_context
from app.models import Organization
from app.soc.common import now

log = logging.getLogger("sentinel.automation")


def tick(db: Session | None = None, at: datetime | None = None) -> dict[str, int]:
    at = at or now()
    own = db is None
    db = db or get_sessionmaker()()
    totals = {"expired": 0, "scheduled": 0, "delivered": 0}
    try:
        for org_id in list(db.scalars(select(Organization.id))):
            set_tenant_context(db, org_id=org_id)
            try:
                totals["expired"] += engine.expire_stale(db, org_id)
                totals["scheduled"] += engine.run_due_schedules(db, org_id, at)
                db.commit()
                totals["delivered"] += delivery.deliver_due(db, org_id)  # now: includes rows queued above
                db.commit()
            except Exception:
                db.rollback()
                log.exception("automation tick failed for organization %s", org_id)
    finally:
        if own:
            db.close()
    return totals


async def run_forever() -> None:
    from starlette.concurrency import run_in_threadpool

    interval = get_settings().automation_tick_seconds
    while True:
        await asyncio.sleep(interval)
        try:
            await run_in_threadpool(tick)
            registry.job_ok("automation")
        except Exception:
            registry.job_failed("automation")
            log.exception("automation worker failed")
