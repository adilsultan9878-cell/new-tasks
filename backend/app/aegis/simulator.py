"""Hardware simulator: a clearly labelled sensor hub and camera for trying AEGIS ONE without hardware.

Every record it creates carries ``is_simulated = true``: it is excluded from Command Center metrics
and labelled "Simulated" everywhere in the console. The simulated hub has no credential, so nothing
can impersonate it. ``clear`` removes everything the simulator created.
"""

from __future__ import annotations

import math
import random
import uuid
from datetime import timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.aegis import iot, vision
from app.models import (
    AgentRun,
    Alert,
    AutomationRun,
    Camera,
    Device,
    SecurityEvent,
    Sensor,
    SensorReading,
    User,
    WebhookDelivery,
)
from app.services import audit, realtime
from app.soc.common import now

HUB_NAME = "Simulated sensor hub"
SENSORS = (
    # key, type, unit, thresholds, actuator rules, baseline, amplitude
    ("server_room_temp", "temperature", "°C", {"max": 35, "severity": "high"}, ["led"], 24.0, 2.0),
    ("server_room_gas", "gas", "ppm", {"max": 300, "severity": "critical"}, ["buzzer", "led"], 120.0, 25.0),
    ("rack_door", "door", "open", {"max": 0.5, "severity": "medium"}, [], 0.0, 0.0),
)


def _hub(db: Session, org_id: uuid.UUID) -> Device:
    hub = db.scalar(
        select(Device).where(
            Device.organization_id == org_id, Device.is_simulated.is_(True), Device.name == HUB_NAME
        )
    )
    if hub is None:
        hub = Device(
            id=uuid.uuid4(),
            organization_id=org_id,
            name=HUB_NAME,
            device_type="sensor_hub",
            hostname="sim-hub",
            os="simulator",
            status="online",
            enrollment_status="enrolled",
            credential_hash=None,
            health_score=100,
            location={},
            tags=["simulated"],
            attributes={},
            telemetry={},
            config={},
            is_simulated=True,
        )
        db.add(hub)
        db.flush()
    hub.last_seen_at = now()
    hub.status = "online"
    return hub


# Simulated rooms and machines for the Digital Twin: name, (x, y, w, h) on the 100 x 60 m floor.
SIM_AREAS = (
    ("Server room", 4.0, 4.0, 30.0, 22.0),
    ("Office", 40.0, 4.0, 56.0, 30.0),
    ("Reception", 4.0, 34.0, 30.0, 22.0),
)
SIM_DEVICES = (
    # name, type, ip, status, health, risk, (x, y), area
    ("sim-db-01", "server", "10.20.0.11", "degraded", 54, 67, (12.0, 12.0), "Server room"),
    ("sim-ws-07", "workstation", "10.20.0.57", "online", 92, 18, (60.0, 16.0), "Office"),
    ("sim-nas-01", "server", "10.20.0.12", "offline", None, 31, (24.0, 16.0), "Server room"),
)


def _twin_layout(db: Session, org_id: uuid.UUID, hub: Device) -> None:
    from app.models import Organization

    org = db.get(Organization, org_id)
    assert org is not None
    twin = dict((org.settings or {}).get("twin") or {})
    existing = list(twin.get("areas") or [])
    if not any(a.get("simulated") for a in existing):
        existing += [
            {"id": str(uuid.uuid4()), "name": n, "x": x, "y": y, "w": w, "h": h, "simulated": True}
            for n, x, y, w, h in SIM_AREAS
        ]
        org.settings = {**(org.settings or {}), "twin": {**twin, "areas": existing}}
    for name, kind, ip, status_, health, risk, (x, y), area in SIM_DEVICES:
        device = db.scalar(
            select(Device).where(
                Device.organization_id == org_id, Device.is_simulated.is_(True), Device.name == name
            )
        )
        if device is None:
            device = Device(
                id=uuid.uuid4(),
                organization_id=org_id,
                name=name,
                device_type=kind,
                hostname=name,
                os="simulator",
                enrollment_status="enrolled",
                credential_hash=None,
                tags=["simulated"],
                attributes={},
                telemetry={},
                config={},
                is_simulated=True,
            )
            db.add(device)
        device.ip_address, device.status, device.health_score, device.risk_score = ip, status_, health, risk
        device.last_seen_at = now() if status_ != "offline" else now() - timedelta(hours=3)
        device.location = {"x": x, "y": y, "area": area}
    hub.ip_address = "10.20.0.40"
    hub.location = {"x": 26.0, "y": 8.0, "area": "Server room"}
    db.flush()


def run(db: Session, request: Request, *, org_id: uuid.UUID, user: User) -> dict[str, Any]:
    hub = _hub(db, org_id)
    _twin_layout(db, org_id, hub)
    rng = random.Random(42)  # noqa: S311 — deterministic demo data, not security-relevant
    start = now() - timedelta(hours=2)
    readings: list[dict[str, Any]] = []
    for key, kind, unit, thresholds, rules, base, amp in SENSORS:
        sensor = iot._sensor(db, hub, key, kind, unit, True)
        sensor.thresholds = thresholds
        sensor.actuator_rules = rules
        sensor.in_breach = False
        for i in range(60):  # one reading every two minutes, quietly within limits
            value = base + amp * math.sin(i / 6) + rng.uniform(-amp / 4, amp / 4) if amp else 0.0
            db.add(
                SensorReading(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    sensor_id=sensor.id,
                    value=round(value, 2),
                    recorded_at=start + timedelta(minutes=2 * i),
                )
            )
        readings.append({"sensor_key": key, "sensor_type": kind, "unit": unit, "value": base})
    # The latest readings: the gas level spikes and the rack door opens.
    readings[1]["value"] = 412.0
    readings[2]["value"] = 1.0
    outcome = iot.ingest(db, hub, readings, simulated=True)

    camera = vision.get_or_register(db, hub, "lobby_camera", "Simulated lobby camera", simulated=True)
    camera.detection_enabled = True
    camera.zones = [{"name": "Server room door", "x": 0.6, "y": 0.2, "w": 0.3, "h": 0.6}]
    seen = vision.ingest(
        db,
        hub,
        camera_key="lobby_camera",
        name=None,
        simulated=True,
        snapshot=None,
        detections=[
            {"type": "motion"},
            {"type": "person", "confidence": 0.82, "objects": 1},
            {"type": "zone_intrusion", "zone": "Server room door", "confidence": 0.82, "objects": 1},
        ],
    )
    audit.record(
        db,
        "simulator.run",
        request=request,
        actor_id=user.id,
        org_id=org_id,
        target_type="device",
        target_id=hub.id,
        details={"readings": len(SENSORS) * 61, "breaches": outcome["breaches"]},
    )
    realtime.queue_broadcast(db, org_id, "device.updated", {"id": str(hub.id), "status": "online"})
    return {
        "hub_id": str(hub.id),
        "sensors": len(SENSORS),
        "readings": len(SENSORS) * 61,
        "breaches": outcome["breaches"],
        "detections": seen["accepted"],
        "actuators": outcome["actuators"],
    }


def clear(db: Session, request: Request, *, org_id: uuid.UUID, user: User) -> dict[str, int]:
    alert_ids = db.scalars(
        select(Alert.id).where(Alert.organization_id == org_id, Alert.is_simulated.is_(True))
    ).all()
    if alert_ids:
        db.execute(
            delete(AgentRun).where(
                AgentRun.organization_id == org_id,
                AgentRun.subject_type == "alert",
                AgentRun.subject_id.in_(alert_ids),
            )
        )
    counts = {
        "alerts": db.execute(
            delete(Alert).where(Alert.organization_id == org_id, Alert.is_simulated.is_(True))
        ).rowcount,
        "events": db.execute(
            delete(SecurityEvent).where(
                SecurityEvent.organization_id == org_id, SecurityEvent.is_simulated.is_(True)
            )
        ).rowcount,
        "sensors": db.execute(
            delete(Sensor).where(Sensor.organization_id == org_id, Sensor.is_simulated.is_(True))
        ).rowcount,
        "cameras": db.execute(
            delete(Camera).where(Camera.organization_id == org_id, Camera.is_simulated.is_(True))
        ).rowcount,
        "devices": db.execute(
            delete(Device).where(Device.organization_id == org_id, Device.is_simulated.is_(True))
        ).rowcount,
        # Automation that a simulated alert started (only when a workflow opted in to simulator data).
        "webhook_deliveries": db.execute(
            delete(WebhookDelivery).where(
                WebhookDelivery.organization_id == org_id, WebhookDelivery.is_simulated.is_(True)
            )
        ).rowcount,
        "automation_runs": db.execute(
            delete(AutomationRun).where(
                AutomationRun.organization_id == org_id, AutomationRun.is_simulated.is_(True)
            )
        ).rowcount,
    }
    from app.models import Organization

    org = db.get(Organization, org_id)
    if org is not None:
        twin = dict((org.settings or {}).get("twin") or {})
        if twin.get("areas"):
            twin["areas"] = [a for a in twin["areas"] if not a.get("simulated")]
            org.settings = {**(org.settings or {}), "twin": twin}
    audit.record(
        db,
        "simulator.clear",
        request=request,
        actor_id=user.id,
        org_id=org_id,
        target_type="organization",
        target_id=org_id,
        details=counts,
    )
    realtime.queue_broadcast(db, org_id, "device.updated", {"cleared": True})
    return counts
