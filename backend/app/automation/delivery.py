"""Signed outgoing webhooks: outbox rows, a dispatcher with retries, and an immediate test send.

* A step only *queues* a delivery (same transaction as the run). The dispatcher sends it after the
  transaction committed, so a rolled-back run never sends anything.
* Body: compact JSON with ``id``, ``type``, ``created_at``, ``simulated``, ``organization``,
  ``workflow``, ``run_id`` and ``data`` (the data-minimised trigger details — titles, severities,
  names and links; never raw event payloads, credentials or evidence).
* Headers: ``X-Sentinel-Event``, ``X-Sentinel-Delivery`` (stable across retries — receivers dedupe
  on it), ``X-Sentinel-Timestamp`` and ``X-Sentinel-Signature: v1=<hex>`` (see signing.py).
* 2xx = delivered. Timeouts, network errors, 408, 429 and 5xx are retried with back-off up to
  WEBHOOK_MAX_ATTEMPTS; other 4xx answers and refused targets are not retried.
* Redirects are not followed; the target is re-checked against the SSRF guard before every attempt.
* Response bodies are not stored, only the status code and timing.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.automation import signing, targets
from app.core.config import get_settings
from app.models import AutomationRun, AutomationWorkflow, Integration, Organization, WebhookDelivery
from app.services import realtime
from app.soc.common import now

log = logging.getLogger("sentinel.automation")
RETRY_DELAYS = (30, 120, 600, 1800, 7200, 21600, 43200, 86400)  # seconds after attempt n
_transport: httpx.BaseTransport | None = None  # tests inject httpx.MockTransport


def set_transport(transport: httpx.BaseTransport | None) -> None:
    global _transport
    _transport = transport


def secret_for(hook: Integration) -> str:
    return signing.derive_secret("webhook", hook.id, hook.secret_version)


def body_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


def enqueue(
    db: Session,
    hook: Integration,
    *,
    event_type: str,
    data: dict[str, Any],
    run: AutomationRun | None = None,
    workflow: AutomationWorkflow | None = None,
    simulated: bool = False,
) -> WebhookDelivery:
    org = db.scalar(select(Organization).where(Organization.id == hook.organization_id))
    delivery_id = uuid.uuid4()
    created = now()
    payload = {
        "id": str(delivery_id),
        "type": event_type,
        "created_at": created.isoformat(),
        "simulated": simulated,
        "organization": {"id": str(hook.organization_id), "name": org.name if org else None},
        "workflow": {"id": str(workflow.id), "name": workflow.name} if workflow else None,
        "run_id": str(run.id) if run else None,
        "data": data,
    }
    item = WebhookDelivery(
        id=delivery_id,
        organization_id=hook.organization_id,
        integration_id=hook.id,
        run_id=run.id if run else None,
        event_type=event_type[:64],
        payload=payload,
        status="pending",
        attempts=0,
        next_attempt_at=created,
        is_simulated=simulated,
        created_at=created,
    )
    db.add(item)
    db.flush()
    return item


def _retryable(code: int | None) -> bool:
    return code is None or code in (408, 425, 429) or code >= 500


def attempt(
    db: Session, item: WebhookDelivery, hook: Integration, *, at: datetime | None = None
) -> WebhookDelivery:
    """One delivery attempt. Updates the row and the webhook's health; never raises."""
    settings = get_settings()
    at = at or now()
    item.attempts += 1
    url = (hook.config or {}).get("url", "")
    code: int | None = None
    error: str | None = None
    retry = True
    started = time.monotonic()
    try:
        targets.check(url)
        body = body_bytes(item.payload)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"SentinelX-Webhooks/{__version__}",
            "X-Sentinel-Event": item.event_type,
            "X-Sentinel-Delivery": str(item.id),
            **signing.signed_headers(secret_for(hook), body),
        }
        with httpx.Client(
            transport=_transport, timeout=settings.webhook_timeout_seconds, follow_redirects=False
        ) as client:
            response = client.post(url, content=body, headers=headers)
        code = response.status_code
        if 200 <= code < 300:
            error = None
        elif 300 <= code < 400:
            error, retry = f"HTTP {code}: redirects are not followed — use the final URL", False
        else:
            error, retry = f"HTTP {code} {response.reason_phrase}".strip(), _retryable(code)
    except targets.TargetRefused as exc:
        error, retry = f"Refused: {exc}", False
    except httpx.TimeoutException:
        error = f"Timed out after {settings.webhook_timeout_seconds:g} s"
    except httpx.HTTPError as exc:
        error = f"Connection failed: {type(exc).__name__}"
    item.response_ms = int((time.monotonic() - started) * 1000)
    item.last_status_code = code
    item.last_error = error
    if error is None:
        item.status = "delivered"
        item.delivered_at = at
        item.next_attempt_at = None
        hook.failure_count = 0
        hook.last_error = None
        hook.last_sync_at = at
    else:
        hook.failure_count = (hook.failure_count or 0) + 1
        hook.last_error = error[:500]
        if retry and item.attempts < settings.webhook_max_attempts:
            delay = RETRY_DELAYS[min(item.attempts - 1, len(RETRY_DELAYS) - 1)]
            item.status = "pending"
            item.next_attempt_at = at + timedelta(seconds=delay)
        else:
            item.status = "failed"
            item.next_attempt_at = None
    db.flush()
    realtime.queue_broadcast(
        db,
        item.organization_id,
        "automation.delivery",
        {"id": str(item.id), "webhook_id": str(hook.id), "status": item.status, "code": code},
    )
    return item


def deliver_due(db: Session, org_id: uuid.UUID, *, at: datetime | None = None, limit: int = 25) -> int:
    """Send this organization's due deliveries (called by the worker with the tenant bound)."""
    from app.soc.actions import emergency_stop

    if not get_settings().automation_delivery_enabled:
        return 0
    org = db.scalar(select(Organization).where(Organization.id == org_id))
    if org is None or emergency_stop(org)["engaged"]:
        return 0  # held while the emergency stop is engaged
    at = at or now()
    q = (
        select(WebhookDelivery)
        .where(
            WebhookDelivery.organization_id == org_id,
            WebhookDelivery.status == "pending",
            WebhookDelivery.next_attempt_at <= at,
        )
        .order_by(WebhookDelivery.next_attempt_at)
        .limit(limit)
    )
    if db.get_bind().dialect.name == "postgresql":
        q = q.with_for_update(skip_locked=True)
    sent = 0
    for item in db.scalars(q).all():
        hook = db.get(Integration, item.integration_id)
        if hook is None:
            continue
        if hook.status != "active":
            item.status, item.last_error, item.next_attempt_at = "failed", "The webhook was disabled", None
            continue
        attempt(db, item, hook, at=at)
        sent += 1
    return sent
