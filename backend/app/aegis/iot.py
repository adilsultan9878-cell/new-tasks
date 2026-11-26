"""IoT sensors: readings from enrolled hubs, threshold rules, and LED/buzzer actuator state.

Hubs (ESP32, Raspberry Pi, the MQTT bridge) authenticate with their device credential. A sensor
is registered the first time its hub reports it. Readings outside a sensor's thresholds raise an
``iot.threshold_breach`` event (high/critical events become alerts) and switch on the actuators
listed in the sensor's rules. The hub learns the desired actuator state from the response — it is
state, never a command, and only "led" and "buzzer" exist.
"""

from __future__ import annotations

import math
import uuid
from datetime import timedelta
from typing import Any

from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models import Device, Sensor, SensorReading, User
from app.schemas.events import EventIn
from app.services import audit, realtime
from app.services import events as event_service
from app.soc.common import actor, aware, now

ACTUATORS = ("led", "buzzer")
MAX_SENSORS_PER_DEVICE = 64
SEVERITIES = ("low", "medium", "high", "critical")


def breached(sensor: Sensor, value: float) -> str | None:
    t = sensor.thresholds or {}
    if isinstance(t.get("max"), int | float) and value > t["max"]:
        return f"above {t['max']}{sensor.unit or ''}"
    if isinstance(t.get("min"), int | float) and value < t["min"]:
        return f"below {t['min']}{sensor.unit or ''}"
    return None


def sensor_summary(sensor: Sensor) -> dict[str, Any]:
    return {
        "id": str(sensor.id),
        "name": sensor.name,
        "last_value": sensor.last_value,
        "in_breach": sensor.in_breach,
    }


def _sensor(
    db: Session, device: Device, key: str, sensor_type: str, unit: str | None, simulated: bool
) -> Sensor:
    sensor = db.scalar(
        select(Sensor).where(
            Sensor.organization_id == device.organization_id,
            Sensor.device_id == device.id,
            Sensor.sensor_key == key,
        )
    )
    if sensor is not None:
        return sensor
    count = len(
        db.scalars(
            select(Sensor.id).where(
                Sensor.organization_id == device.organization_id, Sensor.device_id == device.id
            )
        ).all()
    )
    if count >= MAX_SENSORS_PER_DEVICE:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "too_many_sensors",
            f"A hub can report at most {MAX_SENSORS_PER_DEVICE} sensors",
        )
    sensor = Sensor(
        id=uuid.uuid4(),
        organization_id=device.organization_id,
        device_id=device.id,
        sensor_key=key,
        name=key.replace("_", " ").replace("-", " ").title(),
        sensor_type=sensor_type,
        unit=unit,
        status="online",
        thresholds={},
        actuator_rules=[],
        is_simulated=simulated or device.is_simulated,
    )
    db.add(sensor)
    db.flush()
    return sensor


def actuator_state(
    db: Session, device: Device, sensors: list[Sensor] | None = None
) -> dict[str, dict[str, Any]]:
    """Desired state of the hub's actuators: a manual override wins until it expires, else the rules.

    Pass the device's sensors when listing many hubs, so the state needs no query per hub.
    """
    if sensors is None:
        sensors = list(
            db.scalars(
                select(Sensor).where(
                    Sensor.organization_id == device.organization_id, Sensor.device_id == device.id
                )
            )
        )
    overrides = (device.attributes or {}).get("actuators") or {}
    state: dict[str, dict[str, Any]] = {}
    for name in ACTUATORS:
        triggered = [s.name for s in sensors if s.in_breach and name in (s.actuator_rules or [])]
        o = overrides.get(name)
        until = aware(_parse(o.get("until"))) if o else None
        if o and until and until > now():
            state[name] = {
                "on": o["state"] == "on",
                "source": "manual",
                "until": o["until"],
                "by": o.get("actor"),
            }
        else:
            state[name] = {
                "on": bool(triggered),
                "source": "rule" if triggered else "idle",
                "because": triggered,
            }
    return state


def _parse(value: str | None):  # type: ignore[no-untyped-def]
    from datetime import datetime

    return datetime.fromisoformat(value) if value else None


def ingest(
    db: Session, device: Device, readings: list[dict[str, Any]], *, simulated: bool = False
) -> dict[str, Any]:
    accepted, breaches = 0, 0
    events: list[EventIn] = []
    for r in readings:
        value = float(r["value"])
        if not math.isfinite(value):
            continue
        sensor = _sensor(
            db, device, r["sensor_key"], r.get("sensor_type") or "generic", r.get("unit"), simulated
        )
        at = r.get("recorded_at") or now()
        db.add(
            SensorReading(
                id=uuid.uuid4(),
                organization_id=device.organization_id,
                sensor_id=sensor.id,
                value=value,
                recorded_at=at,
            )
        )
        sensor.last_value = value
        sensor.last_reading_at = at
        sensor.status = "online"
        accepted += 1
        reason = breached(sensor, value)
        severity = (sensor.thresholds or {}).get("severity") or "high"
        if reason and not sensor.in_breach:
            sensor.in_breach = True
            breaches += 1
            events.append(
                EventIn(
                    event_type="iot.threshold_breach",
                    category="iot",
                    severity=severity if severity in SEVERITIES else "high",
                    title=f"{sensor.name} on {device.name} is {reason} ({value:g}{sensor.unit or ''})",
                    dedup_key=f"sensor:{sensor.id}:breach",
                    raw={
                        "sensor_id": str(sensor.id),
                        "sensor": sensor.name,
                        "value": value,
                        "thresholds": sensor.thresholds,
                    },
                )
            )
        elif not reason and sensor.in_breach:
            sensor.in_breach = False
            events.append(
                EventIn(
                    event_type="iot.threshold_recovered",
                    category="iot",
                    severity="info",
                    title=f"{sensor.name} on {device.name} is back within limits ({value:g}{sensor.unit or ''})",
                    dedup_key=f"sensor:{sensor.id}:recovered",
                    raw={"sensor_id": str(sensor.id), "sensor": sensor.name, "value": value},
                )
            )
        realtime.queue_broadcast(db, device.organization_id, "sensor.updated", sensor_summary(sensor))
    db.flush()
    if events:
        event_service.ingest(
            db,
            device.organization_id,
            events,
            source="sensor",
            device=device,
            simulated=simulated or device.is_simulated,
        )
    return {
        "accepted": accepted,
        "breaches": breaches,
        "actuators": {k: v["on"] for k, v in actuator_state(db, device).items()},
    }


def set_override(
    db: Session, request: Request, device: Device, *, user: User, actuator: str, state: str, minutes: int
) -> dict[str, dict[str, Any]]:
    if actuator not in ACTUATORS:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown_actuator", "Only 'led' and 'buzzer' exist"
        )
    overrides = dict((device.attributes or {}).get("actuators") or {})
    if state == "auto":
        overrides.pop(actuator, None)
    else:
        overrides[actuator] = {
            "state": state,
            "until": (now() + timedelta(minutes=minutes)).isoformat(),
            **actor(user),
        }
    device.attributes = {**(device.attributes or {}), "actuators": overrides}
    audit.record(
        db,
        "iot.actuator_override",
        request=request,
        actor_id=user.id,
        org_id=device.organization_id,
        target_type="device",
        target_id=device.id,
        details={"actuator": actuator, "state": state, "minutes": minutes if state != "auto" else None},
    )
    realtime.queue_broadcast(db, device.organization_id, "sensor.updated", {"device_id": str(device.id)})
    return actuator_state(db, device)
