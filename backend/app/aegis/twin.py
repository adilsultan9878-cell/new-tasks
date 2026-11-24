"""Digital Twin (Phase 7): one read model of the organization's physical security posture.

Everything comes from existing records — devices and their health and risk, open alerts and
incidents on each device, attached sensors and cameras, and network segments derived from device
addresses. Only the floor layout is new: areas (rooms) live in the organization's settings and a
device's position in its ``location``. Devices without a position are laid out automatically by the
console and marked as such.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import defaultdict
from typing import Any

from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models import Alert, Camera, Device, Incident, Organization, SecurityEvent, Sensor, User
from app.models.identity import SEVERITIES
from app.services import audit, realtime
from app.soc.common import now

FLOOR = {"width": 100.0, "depth": 60.0}  # metres
ACTIVE_ALERTS = ("open", "acknowledged")


def areas(org: Organization) -> list[dict[str, Any]]:
    return list(((org.settings or {}).get("twin") or {}).get("areas") or [])


def _segment(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 64}", strict=False))


def _position(device: Device) -> dict[str, Any] | None:
    loc = device.location or {}
    x, y = loc.get("x"), loc.get("y")
    if isinstance(x, int | float) and isinstance(y, int | float):
        return {"x": float(x), "y": float(y), "area": loc.get("area")}
    return None


def snapshot(db: Session, org: Organization, *, include_simulated: bool = True) -> dict[str, Any]:
    org_id = org.id
    filters = [Device.organization_id == org_id, Device.enrollment_status == "enrolled"]
    if not include_simulated:
        filters.append(Device.is_simulated.is_(False))
    devices = db.scalars(select(Device).where(*filters).order_by(Device.name)).all()
    ids = [d.id for d in devices] or [uuid.uuid4()]

    alerts: dict[uuid.UUID, list[str]] = defaultdict(list)
    for device_id, severity in db.execute(
        select(SecurityEvent.device_id, Alert.severity)
        .join(SecurityEvent, SecurityEvent.id == Alert.event_id)
        .where(
            Alert.organization_id == org_id, Alert.status.in_(ACTIVE_ALERTS), SecurityEvent.device_id.in_(ids)
        )
    ):
        alerts[device_id].append(severity)

    incidents: dict[uuid.UUID, dict[uuid.UUID, dict[str, Any]]] = defaultdict(dict)
    for device_id, inc in db.execute(
        select(SecurityEvent.device_id, Incident)
        .join(Alert, Alert.incident_id == Incident.id)
        .join(SecurityEvent, SecurityEvent.id == Alert.event_id)
        .where(
            Incident.organization_id == org_id, Incident.status != "closed", SecurityEvent.device_id.in_(ids)
        )
    ):
        incidents[device_id][inc.id] = {
            "id": str(inc.id),
            "reference": inc.reference,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
        }

    sensors: dict[uuid.UUID, list[dict[str, Any]]] = defaultdict(list)
    for s in db.scalars(
        select(Sensor)
        .where(Sensor.organization_id == org_id, Sensor.device_id.in_(ids))
        .order_by(Sensor.name)
    ):
        sensors[s.device_id].append(
            {
                "id": str(s.id),
                "name": s.name,
                "sensor_type": s.sensor_type,
                "unit": s.unit,
                "last_value": s.last_value,
                "in_breach": s.in_breach,
            }
        )
    cameras: dict[uuid.UUID, list[dict[str, Any]]] = defaultdict(list)
    for c in db.scalars(
        select(Camera)
        .where(Camera.organization_id == org_id, Camera.device_id.in_(ids))
        .order_by(Camera.name)
    ):
        cameras[c.device_id].append(
            {
                "id": str(c.id),
                "name": c.name,
                "detection_enabled": c.detection_enabled,
                "zones": len(c.zones or []),
                "last_event_at": c.last_event_at.isoformat() if c.last_event_at else None,
            }
        )

    segments: dict[str, list[str]] = defaultdict(list)
    out_devices = []
    for d in devices:
        sev = alerts.get(d.id, [])
        seg = _segment(d.ip_address)
        if seg:
            segments[seg].append(str(d.id))
        out_devices.append(
            {
                "id": str(d.id),
                "name": d.name,
                "device_type": d.device_type,
                "status": d.status,
                "health_score": d.health_score,
                "risk_score": d.risk_score,
                "ip_address": d.ip_address,
                "segment": seg,
                "is_simulated": d.is_simulated,
                "position": _position(d),
                "open_alerts": len(sev),
                "max_alert_severity": max(sev, key=SEVERITIES.index) if sev else None,
                "open_incidents": list(incidents.get(d.id, {}).values()),
                "sensors": sensors.get(d.id, []),
                "cameras": cameras.get(d.id, []),
            }
        )
    return {
        "generated_at": now().isoformat(),
        "floor": FLOOR,
        "areas": areas(org),
        "devices": out_devices,
        "segments": [{"cidr": k, "device_ids": v} for k, v in sorted(segments.items()) if len(v) > 1],
        "stats": {
            "devices": len(out_devices),
            "online": sum(1 for d in out_devices if d["status"] == "online"),
            "degraded": sum(1 for d in out_devices if d["status"] == "degraded"),
            "offline": sum(1 for d in out_devices if d["status"] == "offline"),
            "open_alerts": sum(d["open_alerts"] for d in out_devices),
            "open_incidents": len({i["id"] for d in out_devices for i in d["open_incidents"]}),
            "sensors_in_breach": sum(1 for d in out_devices for s in d["sensors"] if s["in_breach"]),
            "simulated": sum(1 for d in out_devices if d["is_simulated"]),
            "placed": sum(1 for d in out_devices if d["position"]),
        },
    }


def save_layout(
    db: Session,
    request: Request,
    org: Organization,
    *,
    user: User,
    new_areas: list[dict[str, Any]] | None,
    positions: list[dict[str, Any]],
) -> None:
    if new_areas is not None:
        # The submitted list replaces the layout. Whether an area came from the simulator is decided
        # here from the stored record, never taken from the client.
        simulated_ids = {a["id"] for a in areas(org) if a.get("simulated")}
        cleaned = []
        for a in new_areas:
            area_id = a.get("id") or str(uuid.uuid4())
            cleaned.append(
                {
                    "id": area_id,
                    "name": a["name"],
                    "x": a["x"],
                    "y": a["y"],
                    "w": a["w"],
                    "h": a["h"],
                    "simulated": area_id in simulated_ids,
                }
            )
        twin = {**((org.settings or {}).get("twin") or {}), "areas": cleaned}
        org.settings = {**(org.settings or {}), "twin": twin}
    if positions:
        wanted = {uuid.UUID(str(p["device_id"])) for p in positions}
        found = {
            d.id: d
            for d in db.scalars(select(Device).where(Device.organization_id == org.id, Device.id.in_(wanted)))
        }
        if len(found) != len(wanted):
            raise AppError(status.HTTP_404_NOT_FOUND, "not_found", "Device not found")
        for p in positions:
            device = found[uuid.UUID(str(p["device_id"]))]
            device.location = {**(device.location or {}), "x": p["x"], "y": p["y"], "area": p.get("area")}
    audit.record(
        db,
        "twin.layout_update",
        request=request,
        actor_id=user.id,
        org_id=org.id,
        target_type="organization",
        target_id=org.id,
        details={"areas": len(new_areas) if new_areas is not None else None, "positions": len(positions)},
    )
    realtime.queue_broadcast(db, org.id, "twin.updated", {"by": str(user.id)})
