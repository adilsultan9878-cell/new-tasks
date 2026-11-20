"""In-process real-time fan-out for WebSocket subscribers.

* Messages are queued on the SQLAlchemy session and only published **after the transaction
  commits**, so clients never see data that was rolled back.
* Publishing is thread-safe: request handlers run in a worker thread pool, subscribers live on
  the event loop; each subscription remembers its own loop.
* Scope: a single API instance (Render free tier). Multiple instances would need a shared bus
  (PostgreSQL LISTEN/NOTIFY or Redis) — the publish() interface stays the same.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session

log = logging.getLogger("sentinel.realtime")
_PENDING_KEY = "realtime_pending"
QUEUE_SIZE = 256


@dataclass(eq=False)
class Subscription:
    org_id: uuid.UUID
    user_id: uuid.UUID
    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue[dict[str, Any]] = field(default_factory=lambda: asyncio.Queue(QUEUE_SIZE))
    dropped: int = 0

    def offer(self, message: dict[str, Any]) -> None:
        """Runs on the subscriber's loop. Slow consumers lose the oldest messages, not the API."""
        if self.queue.full():
            try:
                self.queue.get_nowait()
                self.dropped += 1
            except asyncio.QueueEmpty:
                pass
        self.queue.put_nowait(message)


class Hub:
    def __init__(self) -> None:
        self._subs: dict[uuid.UUID, set[Subscription]] = defaultdict(set)
        self._lock = threading.Lock()

    def subscribe(self, org_id: uuid.UUID, user_id: uuid.UUID) -> Subscription:
        sub = Subscription(org_id=org_id, user_id=user_id, loop=asyncio.get_running_loop())
        with self._lock:
            self._subs[org_id].add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            subs = self._subs.get(sub.org_id)
            if subs is not None:
                subs.discard(sub)
                if not subs:
                    del self._subs[sub.org_id]

    def subscriber_count(self, org_id: uuid.UUID | None = None) -> int:
        with self._lock:
            if org_id is not None:
                return len(self._subs.get(org_id, ()))
            return sum(len(s) for s in self._subs.values())

    def publish(self, org_id: uuid.UUID, message: dict[str, Any]) -> None:
        with self._lock:
            targets = list(self._subs.get(org_id, ()))
        for sub in targets:
            try:
                sub.loop.call_soon_threadsafe(sub.offer, message)
            except RuntimeError:  # loop already closed
                self.unsubscribe(sub)


hub = Hub()


def message(kind: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"type": kind, "data": data, "ts": datetime.now(UTC).isoformat()}


def queue_broadcast(db: Session, org_id: uuid.UUID, kind: str, data: dict[str, Any]) -> None:
    """Publish ``kind`` to the organization's subscribers once the current transaction commits."""
    db.info.setdefault(_PENDING_KEY, []).append((org_id, message(kind, data)))


@event.listens_for(Session, "after_commit")
def _flush_after_commit(session: Session) -> None:
    pending = session.info.pop(_PENDING_KEY, None)
    for org_id, msg in pending or ():
        hub.publish(org_id, msg)


@event.listens_for(Session, "after_rollback")
def _discard_after_rollback(session: Session) -> None:
    session.info.pop(_PENDING_KEY, None)
