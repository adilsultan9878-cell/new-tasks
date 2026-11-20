"""Background job: mark enrolled devices offline when they stop sending heartbeats.

Runs inside the API process (lifespan task). It visits organizations one at a time with that
organization bound as the tenant, so PostgreSQL Row-Level Security applies to the job as well.
Safe to run on several instances at once (the UPDATE is idempotent).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_sessionmaker, set_tenant_context
from app.models import Device, Organization, SecurityEvent
from app.services import realtime
from app.services.devices import device_summary

log = logging.getLogger("sentinel.sweeper")


def sweep_offline_devices(db: Session | None = None, now: datetime | None = None) -> int:
    settings = get_settings()
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(seconds=settings.device_offline_after_seconds)
    own_session = db is None
    db = db or get_sessionmaker()()
    marked = 0
    try:
        org_ids = list(db.scalars(select(Organization.id)))
        for org_id in org_ids:
            set_tenant_context(db, org_id=org_id)
            stale = db.scalars(
                select(Device).where(
                    Device.organization_id == org_id,
                    Device.enrollment_status == "enrolled",
                    Device.status.in_(("online", "degraded", "unknown")),
                    Device.last_seen_at < cutoff,
                )
            ).all()
            for device in stale:
                device.status = "offline"
                db.add(
                    SecurityEvent(
                        id=uuid.uuid4(),
                        organization_id=org_id,
                        device_id=device.id,
                        source="system",
                        category="agent",
                        event_type="agent.offline",
                        severity="low",
                        title=f"Device {device.name} stopped reporting",
                        description=(
                            f"No heartbeat for more than {settings.device_offline_after_seconds} seconds."
                        ),
                        raw={},
                        normalized={"device": {"id": str(device.id), "name": device.name}},
                        occurred_at=now,
                        ingested_at=now,
                    )
                )
                realtime.queue_broadcast(db, org_id, "device.updated", device_summary(device))
                marked += 1
            db.commit()
    finally:
        if own_session:
            db.close()
    if marked:
        log.info("marked %d device(s) offline", marked)
    return marked


async def run_forever() -> None:
    from starlette.concurrency import run_in_threadpool

    interval = get_settings().device_sweep_interval_seconds
    while True:
        await asyncio.sleep(interval)
        try:
            await run_in_threadpool(sweep_offline_devices)
        except Exception:
            log.exception("device sweep failed")
