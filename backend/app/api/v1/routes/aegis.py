"""AEGIS ONE console API (Phase 6): sensors, actuators, cameras, snapshots and the simulator."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import delete, func, select

from app.aegis import iot as iot_service
from app.aegis import simulator
from app.api.deps import DB, OrgContext, require
from app.core.errors import not_found
from app.models import Camera, CameraSnapshot, Device, Sensor, SensorReading
from app.schemas.aegis import (
    ActuatorOverride,
    CameraOut,
    CameraUpdate,
    HubOut,
    ReadingPoint,
    SensorOut,
    SensorUpdate,
    SimulatorResult,
    SnapshotOut,
)
from app.services import audit, realtime

router = APIRouter(prefix="/organizations/{org_id}", tags=["aegis-one"])
Read = Annotated[OrgContext, Depends(require("devices:read"))]
Manage = Annotated[OrgContext, Depends(require("devices:manage"))]


def _device_names(db: DB, org_id: uuid.UUID, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return dict(
        db.execute(
            select(Device.id, Device.name).where(Device.organization_id == org_id, Device.id.in_(wanted))
        ).all()
    )


def _sensors_out(db: DB, org_id: uuid.UUID, rows: list[Sensor]) -> list[SensorOut]:
    names = _device_names(db, org_id, {r.device_id for r in rows})
    out = []
    for r in rows:
        item = SensorOut.model_validate(r)
        item.device_name = names.get(r.device_id) if r.device_id else None
        out.append(item)
    return out


def _cameras_out(db: DB, org_id: uuid.UUID, rows: list[Camera]) -> list[CameraOut]:
    names = _device_names(db, org_id, {r.device_id for r in rows})
    counts = dict(
        db.execute(
            select(CameraSnapshot.camera_id, func.count())
            .where(
                CameraSnapshot.organization_id == org_id,
                CameraSnapshot.camera_id.in_([r.id for r in rows] or [uuid.uuid4()]),
            )
            .group_by(CameraSnapshot.camera_id)
        ).all()
    )
    out = []
    for r in rows:
        item = CameraOut.model_validate(r)
        item.device_name = names.get(r.device_id) if r.device_id else None
        item.snapshot_count = int(counts.get(r.id, 0))
        out.append(item)
    return out


def _get(db: DB, model, org_id: uuid.UUID, row_id: uuid.UUID, what: str):  # type: ignore[no-untyped-def]
    row = db.scalar(select(model).where(model.id == row_id, model.organization_id == org_id))
    if row is None:
        raise not_found(what)
    return row


# ---------------------------------------------------------------------------------- sensors
@router.get("/sensors", response_model=list[SensorOut])
def list_sensors(ctx: Read, db: DB) -> list[SensorOut]:
    rows = db.scalars(select(Sensor).where(Sensor.organization_id == ctx.org_id).order_by(Sensor.name)).all()
    return _sensors_out(db, ctx.org_id, list(rows))


@router.patch("/sensors/{sensor_id}", response_model=SensorOut)
def update_sensor(
    sensor_id: uuid.UUID, body: SensorUpdate, ctx: Manage, request: Request, db: DB
) -> SensorOut:
    sensor: Sensor = _get(db, Sensor, ctx.org_id, sensor_id, "Sensor")
    changes = body.model_dump(exclude_unset=True)
    if "name" in changes:
        sensor.name = changes["name"]
    if "unit" in changes:
        sensor.unit = changes["unit"]
    if body.thresholds is not None:
        sensor.thresholds = body.thresholds.model_dump(exclude_none=True)
        if sensor.last_value is not None:  # re-evaluate the latest value against the new limits
            sensor.in_breach = iot_service.breached(sensor, sensor.last_value) is not None
    if body.actuator_rules is not None:
        sensor.actuator_rules = sorted(set(body.actuator_rules))
    audit.record(
        db,
        "iot.sensor_update",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="sensor",
        target_id=sensor.id,
        details={k: (v if k != "thresholds" else sensor.thresholds) for k, v in changes.items()},
    )
    realtime.queue_broadcast(db, ctx.org_id, "sensor.updated", iot_service.sensor_summary(sensor))
    db.commit()
    return _sensors_out(db, ctx.org_id, [sensor])[0]


@router.get("/sensors/{sensor_id}/readings", response_model=list[ReadingPoint])
def sensor_readings(
    sensor_id: uuid.UUID, ctx: Read, db: DB, hours: Annotated[int, Query(ge=1, le=168)] = 24
) -> list[ReadingPoint]:
    sensor: Sensor = _get(db, Sensor, ctx.org_id, sensor_id, "Sensor")
    rows = db.execute(
        select(SensorReading.recorded_at, SensorReading.value)
        .where(
            SensorReading.organization_id == ctx.org_id,
            SensorReading.sensor_id == sensor.id,
            SensorReading.recorded_at >= datetime.now(UTC) - timedelta(hours=hours),
        )
        .order_by(SensorReading.recorded_at)
    ).all()
    step = max(1, len(rows) // 300)  # at most ~300 points: average each bucket
    points = []
    for i in range(0, len(rows), step):
        bucket = rows[i : i + step]
        points.append(ReadingPoint(t=bucket[-1][0], v=round(sum(v for _, v in bucket) / len(bucket), 3)))
    return points


@router.get("/hubs", response_model=list[HubOut])
def list_hubs(ctx: Read, db: DB) -> list[HubOut]:
    counts = dict(
        db.execute(
            select(Sensor.device_id, func.count())
            .where(Sensor.organization_id == ctx.org_id)
            .group_by(Sensor.device_id)
        ).all()
    )
    devices = db.scalars(
        select(Device).where(
            Device.organization_id == ctx.org_id, Device.id.in_([d for d in counts if d] or [uuid.uuid4()])
        )
    ).all()
    return [
        HubOut(
            device_id=d.id,
            name=d.name,
            status=d.status,
            is_simulated=d.is_simulated,
            sensor_count=int(counts.get(d.id, 0)),
            actuators=iot_service.actuator_state(db, d),
        )
        for d in sorted(devices, key=lambda d: d.name)
    ]


@router.post("/devices/{device_id}/actuators", response_model=HubOut)
def override_actuator(
    device_id: uuid.UUID, body: ActuatorOverride, ctx: Manage, request: Request, db: DB
) -> HubOut:
    device: Device = _get(db, Device, ctx.org_id, device_id, "Device")
    state = iot_service.set_override(
        db, request, device, user=ctx.user, actuator=body.actuator, state=body.state, minutes=body.minutes
    )
    db.commit()
    count = (
        db.scalar(
            select(func.count())
            .select_from(Sensor)
            .where(Sensor.organization_id == ctx.org_id, Sensor.device_id == device.id)
        )
        or 0
    )
    return HubOut(
        device_id=device.id,
        name=device.name,
        status=device.status,
        is_simulated=device.is_simulated,
        sensor_count=count,
        actuators=state,
    )


# ---------------------------------------------------------------------------------- cameras
@router.get("/cameras", response_model=list[CameraOut])
def list_cameras(ctx: Read, db: DB) -> list[CameraOut]:
    rows = db.scalars(select(Camera).where(Camera.organization_id == ctx.org_id).order_by(Camera.name)).all()
    return _cameras_out(db, ctx.org_id, list(rows))


@router.patch("/cameras/{camera_id}", response_model=CameraOut)
def update_camera(
    camera_id: uuid.UUID, body: CameraUpdate, ctx: Manage, request: Request, db: DB
) -> CameraOut:
    camera: Camera = _get(db, Camera, ctx.org_id, camera_id, "Camera")
    changes = body.model_dump(exclude_unset=True)
    for field in ("name", "detection_enabled", "blur_people", "retention_days"):
        if field in changes and changes[field] is not None:
            setattr(camera, field, changes[field])
    if body.zones is not None:
        camera.zones = [z.model_dump() for z in body.zones]
    purged = 0
    if body.privacy_mode is not None:
        camera.privacy_mode = body.privacy_mode
        if body.privacy_mode:  # privacy mode on: stored snapshots are deleted at once
            purged = db.execute(
                delete(CameraSnapshot).where(
                    CameraSnapshot.organization_id == ctx.org_id, CameraSnapshot.camera_id == camera.id
                )
            ).rowcount
    audit.record(
        db,
        "vision.camera_update",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="camera",
        target_id=camera.id,
        details={"fields": sorted(changes), "snapshots_purged": purged},
    )
    realtime.queue_broadcast(db, ctx.org_id, "camera.updated", {"id": str(camera.id)})
    db.commit()
    return _cameras_out(db, ctx.org_id, [camera])[0]


@router.get("/cameras/{camera_id}/snapshots", response_model=list[SnapshotOut])
def list_snapshots(camera_id: uuid.UUID, ctx: Manage, db: DB) -> list[SnapshotOut]:
    camera: Camera = _get(db, Camera, ctx.org_id, camera_id, "Camera")
    rows = db.scalars(
        select(CameraSnapshot)
        .where(
            CameraSnapshot.organization_id == ctx.org_id,
            CameraSnapshot.camera_id == camera.id,
            CameraSnapshot.expires_at > datetime.now(UTC),
        )
        .order_by(CameraSnapshot.captured_at.desc())
        .limit(50)
    ).all()
    return [SnapshotOut.model_validate(r) for r in rows]


@router.get("/snapshots/{snapshot_id}/image", response_class=Response)
def snapshot_image(snapshot_id: uuid.UUID, ctx: Manage, request: Request, db: DB) -> Response:
    snap: CameraSnapshot = _get(db, CameraSnapshot, ctx.org_id, snapshot_id, "Snapshot")
    audit.record(
        db,
        "vision.snapshot_view",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="snapshot",
        target_id=snap.id,
    )
    db.commit()
    return Response(
        content=snap.data,
        media_type=snap.content_type,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@router.delete("/snapshots/{snapshot_id}", status_code=204)
def delete_snapshot(snapshot_id: uuid.UUID, ctx: Manage, request: Request, db: DB) -> Response:
    snap: CameraSnapshot = _get(db, CameraSnapshot, ctx.org_id, snapshot_id, "Snapshot")
    db.delete(snap)
    audit.record(
        db,
        "vision.snapshot_delete",
        request=request,
        actor_id=ctx.user.id,
        org_id=ctx.org_id,
        target_type="snapshot",
        target_id=snapshot_id,
    )
    db.commit()
    return Response(status_code=204)


# -------------------------------------------------------------------------------- simulator
@router.post("/simulator/run", response_model=SimulatorResult, status_code=201)
def run_simulator(ctx: Manage, request: Request, db: DB) -> SimulatorResult:
    result = simulator.run(db, request, org_id=ctx.org_id, user=ctx.user)
    db.commit()
    return SimulatorResult(**result)


@router.delete("/simulator", response_model=dict[str, int])
def clear_simulator(ctx: Manage, request: Request, db: DB) -> dict[str, int]:
    counts = simulator.clear(db, request, org_id=ctx.org_id, user=ctx.user)
    db.commit()
    return counts
