"""Privacy-first computer vision: detections from the on-site camera agent.

The agent runs motion and person detection locally and sends *detections*, never video. Nothing
identifies a person. A new camera starts with detection off until a manager enables it; snapshots
are accepted only while privacy mode is off, must be JPEG or PNG, expire after the camera's
retention period and can be deleted at any time.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from datetime import timedelta
from typing import Any

from fastapi import status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.models import Camera, CameraSnapshot, Device
from app.schemas.events import EventIn
from app.services import events as event_service
from app.services import realtime
from app.soc.common import now

DETECTION_SEVERITY = {"motion": "info", "person": "low", "zone_intrusion": "high"}
MAX_CAMERAS_PER_DEVICE = 16


def camera_config(camera: Camera) -> dict[str, Any]:
    return {
        "camera_id": str(camera.id),
        "detection_enabled": camera.detection_enabled,
        "zones": camera.zones or [],
        "snapshots": not camera.privacy_mode,
        "blur_people": camera.blur_people,
        "cooldown_seconds": get_settings().vision_event_cooldown_seconds,
    }


def camera_summary(camera: Camera) -> dict[str, Any]:
    return {
        "id": str(camera.id),
        "name": camera.name,
        "status": camera.status,
        "last_event_at": camera.last_event_at.isoformat() if camera.last_event_at else None,
    }


def get_or_register(
    db: Session, device: Device, key: str, name: str | None, simulated: bool = False
) -> Camera:
    camera = db.scalar(
        select(Camera).where(
            Camera.organization_id == device.organization_id,
            Camera.device_id == device.id,
            Camera.camera_key == key,
        )
    )
    if camera is None:
        count = len(
            db.scalars(
                select(Camera.id).where(
                    Camera.organization_id == device.organization_id, Camera.device_id == device.id
                )
            ).all()
        )
        if count >= MAX_CAMERAS_PER_DEVICE:
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "too_many_cameras",
                f"A device can run at most {MAX_CAMERAS_PER_DEVICE} cameras",
            )
        camera = Camera(
            id=uuid.uuid4(),
            organization_id=device.organization_id,
            device_id=device.id,
            camera_key=key,
            name=name or key.replace("_", " ").replace("-", " ").title(),
            status="online",
            privacy_mode=True,
            detection_enabled=False,
            blur_people=True,
            retention_days=7,
            zones=[],
            is_simulated=simulated or device.is_simulated,
        )
        db.add(camera)
        db.flush()
    camera.status = "online"
    camera.last_frame_at = now()
    return camera


def _image(data: str | None) -> tuple[bytes, str] | None:
    if not data:
        return None
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_snapshot", "Snapshot is not valid base64"
        ) from None
    if len(raw) > get_settings().camera_snapshot_max_bytes:
        raise AppError(status.HTTP_413_CONTENT_TOO_LARGE, "snapshot_too_large", "Snapshot is too large")
    if raw.startswith(b"\xff\xd8\xff"):
        return raw, "image/jpeg"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return raw, "image/png"
    raise AppError(
        status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_snapshot", "Snapshots must be JPEG or PNG images"
    )


def ingest(
    db: Session,
    device: Device,
    *,
    camera_key: str,
    name: str | None,
    detections: list[dict[str, Any]],
    snapshot: str | None,
    simulated: bool = False,
) -> dict[str, Any]:
    camera = get_or_register(db, device, camera_key, name, simulated)
    result: dict[str, Any] = {"accepted": 0, "snapshot_stored": False, "config": camera_config(camera)}
    if not camera.detection_enabled:
        result["ignored"] = "Detection is off for this camera — enable it in the console"
        return result
    image = _image(snapshot)
    events: list[EventIn] = []
    for d in detections:
        kind = d["type"]
        zone = d.get("zone")
        if kind == "zone_intrusion":
            title = f"Person in restricted zone '{zone}' ({camera.name})"
        elif kind == "person":
            title = f"Person detected ({camera.name})"
        else:
            title = f"Motion detected ({camera.name})"
        events.append(
            EventIn(
                event_type=f"vision.{kind}",
                category="vision",
                severity=DETECTION_SEVERITY[kind],
                title=title,
                dedup_key=f"camera:{camera.id}:{kind}:{zone or ''}",
                raw={
                    "camera_id": str(camera.id),
                    "camera": camera.name,
                    "zone": zone,
                    "confidence": d.get("confidence"),
                    "objects": d.get("objects"),
                },
            )
        )
    if events:
        event_service.ingest(
            db,
            device.organization_id,
            events,
            source="camera",
            device=device,
            simulated=simulated or camera.is_simulated,
        )
        camera.last_event_at = now()
        result["accepted"] = len(events)
    if image is not None:
        if camera.privacy_mode:
            result["snapshot_discarded"] = "privacy mode is on"
        else:
            data, content_type = image
            db.add(
                CameraSnapshot(
                    id=uuid.uuid4(),
                    organization_id=camera.organization_id,
                    camera_id=camera.id,
                    event_type=max(
                        (d["type"] for d in detections), key=list(DETECTION_SEVERITY).index, default="motion"
                    ),
                    content_type=content_type,
                    data=data,
                    captured_at=now(),
                    expires_at=now() + timedelta(days=camera.retention_days),
                )
            )
            result["snapshot_stored"] = True
    realtime.queue_broadcast(db, camera.organization_id, "camera.updated", camera_summary(camera))
    return result
