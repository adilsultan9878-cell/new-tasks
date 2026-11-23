"""Read-only, tenant-scoped tools — the only way Security Brain agents see data.

Guarantees, each enforced in code and covered by tests/test_brain.py:

* every query filters on the run's organization explicitly (PostgreSQL RLS is the second wall);
* tools return plain dictionaries, never ORM objects, so an agent has nothing it could modify;
* tools run with autoflush disabled and the run fails if the session gained pending changes;
* no tool inserts, updates, deletes, executes commands or makes network requests (a static
  check over this module and :mod:`app.brain.agents` fails the build otherwise);
* every call is recorded in the run trace with its arguments, row count and duration.
"""

from __future__ import annotations

import functools
import inspect
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    Alert,
    Device,
    Investigation,
    NetworkAsset,
    SecurityEvent,
    ThreatIndicator,
)

ACTIVE_ALERT_STATUSES = ("open", "acknowledged")

# Catalogue of tool names → descriptions, filled by the @tool decorator (shown in the Agent Center).
TOOLS: dict[str, str] = {}

F = TypeVar("F", bound=Callable[..., Any])


class ReadOnlyViolation(RuntimeError):
    """A tool call left pending writes in the session — the run is aborted."""


def tool(name: str, description: str) -> Callable[[F], F]:
    def decorate(fn: F) -> F:
        TOOLS[name] = description

        @functools.wraps(fn)
        def wrapper(self: Toolbox, *args: Any, **kwargs: Any) -> Any:
            return self._call(name, fn, args, kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate


def _aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def _iso(value: datetime | None) -> str | None:
    value = _aware(value)
    return value.isoformat() if value else None


def _arg(value: Any) -> Any:
    """JSON-safe, bounded rendering of a tool argument for the trace."""
    if value is None or isinstance(value, bool | int | float | str):
        return value[:200] if isinstance(value, str) else value
    if isinstance(value, uuid.UUID | datetime):
        return str(value)
    if isinstance(value, Iterable) and not isinstance(value, dict | bytes):
        items = list(value)
        return [_arg(v) for v in items[:10]] + ([f"… +{len(items) - 10}"] if len(items) > 10 else [])
    return str(value)[:200]


def _bind(fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Name every argument (positional ones too) for a readable trace."""
    bound = inspect.signature(fn).bind(None, *args, **kwargs).arguments
    return {k: v for k, v in bound.items() if k != "self"}


def _rows(result: Any) -> int:
    if result is None:
        return 0
    if isinstance(result, list | tuple):
        return len(result)
    return 1


# ------------------------------------------------------------------------------- snapshots
def _alert(a: Alert) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "title": a.title,
        "description": a.description,
        "severity": a.severity,
        "status": a.status,
        "detection_rule": a.detection_rule,
        "event_id": str(a.event_id) if a.event_id else None,
        "created_at": _iso(a.created_at),
        "is_simulated": a.is_simulated,
    }


def _event(e: SecurityEvent) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "device_id": str(e.device_id) if e.device_id else None,
        "category": e.category,
        "event_type": e.event_type,
        "severity": e.severity,
        "title": e.title,
        "occurrence_count": e.occurrence_count,
        "occurred_at": _iso(e.occurred_at),
        "last_occurred_at": _iso(e.last_occurred_at),
        "observables": dict((e.normalized or {}).get("observables") or {}),
        "is_simulated": e.is_simulated,
    }


def _device(d: Device) -> dict[str, Any]:
    telemetry = dict(d.telemetry or {})
    return {
        "id": str(d.id),
        "name": d.name,
        "hostname": d.hostname,
        "ip_address": d.ip_address,
        "os": d.os,
        "status": d.status,
        "enrollment_status": d.enrollment_status,
        "health_score": d.health_score,
        "last_seen_at": _iso(d.last_seen_at),
        "credential_rotated_at": _iso(d.credential_rotated_at),
        "telemetry": telemetry,
        "is_simulated": d.is_simulated,
    }


def _asset(a: NetworkAsset) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "device_id": str(a.device_id) if a.device_id else None,
        "ip_address": a.ip_address,
        "hostname": a.hostname,
        "open_ports": [p for p in (a.open_ports or []) if isinstance(p, int)],
        "services": [s for s in (a.services or []) if isinstance(s, dict)],
        "in_authorized_scope": a.in_authorized_scope,
        "source": a.source,
    }


def _indicator(i: ThreatIndicator) -> dict[str, Any]:
    return {
        "id": str(i.id),
        "type": i.indicator_type,
        "value": i.value,
        "verdict": i.verdict,
        "confidence": i.confidence,
        "source": i.source,
    }


@dataclass
class Toolbox:
    db: Session
    org_id: uuid.UUID
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    trace: list[dict[str, Any]] = field(default_factory=list)
    agent: str = "orchestrator"

    # ------------------------------------------------------------------------- machinery
    def _pending(self) -> tuple[set[int], set[int], set[int]]:
        return (
            {id(o) for o in self.db.new},
            {id(o) for o in self.db.dirty},
            {id(o) for o in self.db.deleted},
        )

    def _call(self, name: str, fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        before = self._pending()
        started = time.perf_counter()
        with self.db.no_autoflush:
            result = fn(self, *args, **kwargs)
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        after = self._pending()
        if any(a - b for a, b in zip(after, before, strict=True)):
            raise ReadOnlyViolation(f"tool {name!r} left pending changes in the session")
        self.trace.append(
            {
                "seq": len(self.trace) + 1,
                "agent": self.agent,
                "tool": name,
                "args": {k: _arg(v) for k, v in _bind(fn, args, kwargs).items()},
                "rows": _rows(result),
                "duration_ms": elapsed,
            }
        )
        return result

    def since(self, days: float = 0, hours: float = 0) -> datetime:
        return self.now - timedelta(days=days, hours=hours)

    # ----------------------------------------------------------------------------- alerts
    @tool("alerts.get", "Read one alert of this organization")
    def get_alert(self, alert_id: uuid.UUID) -> dict[str, Any] | None:
        row = self.db.scalar(select(Alert).where(Alert.id == alert_id, Alert.organization_id == self.org_id))
        return _alert(row) if row else None

    @tool("alerts.for_device", "Alerts raised on a device's events since a point in time")
    def alerts_for_device(
        self, device_id: uuid.UUID, since: datetime, active_only: bool = False
    ) -> list[dict[str, Any]]:
        query = (
            select(Alert)
            .join(SecurityEvent, SecurityEvent.id == Alert.event_id)
            .where(
                Alert.organization_id == self.org_id,
                SecurityEvent.organization_id == self.org_id,
                SecurityEvent.device_id == device_id,
                Alert.created_at >= since,
            )
            .order_by(Alert.created_at.desc())
            .limit(200)
        )
        if active_only:
            query = query.where(Alert.status.in_(ACTIVE_ALERT_STATUSES))
        return [_alert(a) for a in self.db.scalars(query)]

    @tool("alerts.active_summary", "Counts of open/acknowledged alerts by severity, and stale open alerts")
    def active_alert_summary(self, stale_after_hours: int = 24) -> dict[str, Any]:
        rows = self.db.execute(
            select(Alert.severity, func.count())
            .where(Alert.organization_id == self.org_id, Alert.status.in_(ACTIVE_ALERT_STATUSES))
            .group_by(Alert.severity)
        ).all()
        stale = self.db.scalars(
            select(Alert)
            .where(
                Alert.organization_id == self.org_id,
                Alert.status == "open",
                Alert.created_at < self.since(hours=stale_after_hours),
            )
            .order_by(Alert.created_at)
            .limit(50)
        ).all()
        return {"by_severity": {sev: int(n) for sev, n in rows}, "stale_open": [_alert(a) for a in stale]}

    # ----------------------------------------------------------------------------- events
    @tool("events.get", "Read one security event of this organization")
    def get_event(self, event_id: uuid.UUID) -> dict[str, Any] | None:
        row = self.db.scalar(
            select(SecurityEvent).where(
                SecurityEvent.id == event_id, SecurityEvent.organization_id == self.org_id
            )
        )
        return _event(row) if row else None

    @tool("events.recent", "Recent security events (optionally for one device), newest first")
    def recent_events(
        self, since: datetime, device_id: uuid.UUID | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        query = select(SecurityEvent).where(
            SecurityEvent.organization_id == self.org_id,
            func.coalesce(SecurityEvent.last_occurred_at, SecurityEvent.occurred_at) >= since,
        )
        if device_id is not None:
            query = query.where(SecurityEvent.device_id == device_id)
        query = query.order_by(SecurityEvent.occurred_at.desc()).limit(min(limit, 500))
        return [_event(e) for e in self.db.scalars(query)]

    @tool("events.volume", "Number of event occurrences in a window (optionally per device / severity)")
    def event_volume(
        self,
        since: datetime,
        until: datetime | None = None,
        device_id: uuid.UUID | None = None,
        severities: Iterable[str] | None = None,
    ) -> int:
        seen = func.coalesce(SecurityEvent.last_occurred_at, SecurityEvent.occurred_at)
        query = select(func.coalesce(func.sum(SecurityEvent.occurrence_count), 0)).where(
            SecurityEvent.organization_id == self.org_id, seen >= since
        )
        if until is not None:
            query = query.where(seen < until)
        if device_id is not None:
            query = query.where(SecurityEvent.device_id == device_id)
        if severities is not None:
            query = query.where(SecurityEvent.severity.in_(list(severities)))
        return int(self.db.scalar(query) or 0)

    # ---------------------------------------------------------------------------- devices
    @tool("devices.get", "Read one device of this organization (status, health, telemetry)")
    def get_device(self, device_id: uuid.UUID) -> dict[str, Any] | None:
        row = self.db.scalar(
            select(Device).where(Device.id == device_id, Device.organization_id == self.org_id)
        )
        return _device(row) if row else None

    @tool("devices.fleet", "Enrolled devices grouped by status")
    def fleet(self) -> list[dict[str, Any]]:
        rows = self.db.scalars(
            select(Device)
            .where(Device.organization_id == self.org_id, Device.enrollment_status == "enrolled")
            .order_by(Device.name)
            .limit(2000)
        ).all()
        return [_device(d) for d in rows]

    # ---------------------------------------------------------------------------- network
    @tool("network.asset_for_device", "The network asset linked to a device (by device or IP)")
    def asset_for_device(self, device_id: uuid.UUID, ip_address: str | None) -> dict[str, Any] | None:
        row = self.db.scalar(
            select(NetworkAsset).where(
                NetworkAsset.organization_id == self.org_id, NetworkAsset.device_id == device_id
            )
        )
        if row is None and ip_address:
            row = self.db.scalar(
                select(NetworkAsset).where(
                    NetworkAsset.organization_id == self.org_id, NetworkAsset.ip_address == ip_address
                )
            )
        return _asset(row) if row else None

    @tool("network.assets", "Network assets in the inventory (imported scans and agents)")
    def assets(self, limit: int = 1000) -> list[dict[str, Any]]:
        rows = self.db.scalars(
            select(NetworkAsset)
            .where(NetworkAsset.organization_id == self.org_id)
            .order_by(NetworkAsset.ip_address)
            .limit(min(limit, 2000))
        ).all()
        return [_asset(a) for a in rows]

    # ------------------------------------------------------------------------------ intel
    @tool("intel.match_indicators", "Watchlist indicators rated suspicious/malicious matching given values")
    def match_indicators(self, values: Iterable[str]) -> list[dict[str, Any]]:
        wanted = sorted({str(v).strip().lower() for v in values if str(v).strip()})[:500]
        if not wanted:
            return []
        rows = self.db.scalars(
            select(ThreatIndicator).where(
                ThreatIndicator.organization_id == self.org_id,
                ThreatIndicator.verdict.in_(("suspicious", "malicious")),
                func.lower(ThreatIndicator.value).in_(wanted),
            )
        ).all()
        return [_indicator(i) for i in rows]

    @tool(
        "intel.recent_investigations", "Completed investigations with a given verdict since a point in time"
    )
    def recent_investigations(self, since: datetime, verdicts: Iterable[str]) -> list[dict[str, Any]]:
        rows = self.db.scalars(
            select(Investigation)
            .where(
                Investigation.organization_id == self.org_id,
                Investigation.verdict.in_(list(verdicts)),
                Investigation.created_at >= since,
            )
            .order_by(Investigation.created_at.desc())
            .limit(50)
        ).all()
        return [
            {
                "id": str(i.id),
                "subject_type": i.subject_type,
                "subject": i.subject[:200],
                "verdict": i.verdict,
                "risk_score": i.risk_score,
                "created_at": _iso(i.created_at),
            }
            for i in rows
        ]
