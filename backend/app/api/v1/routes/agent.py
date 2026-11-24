"""Agent protocol (machine-to-machine). Authenticated with a per-device credential, not a user
session. The responses carry configuration only — never commands."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.aegis import iot as iot_service
from app.aegis import vision as vision_service
from app.api.deps import DB
from app.core.config import get_settings
from app.core.rate_limit import auth_rate_limit, enforce
from app.models import Device
from app.schemas.aegis import CameraConfig, DetectionBatch, DetectionResult, ReadingBatch, ReadingResult
from app.schemas.devices import (
    AgentConfig,
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    RotateResponse,
)
from app.schemas.events import EventBatch, IngestResult, RejectedEvent
from app.services import devices as device_service
from app.services import events as event_service

router = APIRouter(prefix="/agent", tags=["agent"])
_bearer = HTTPBearer(auto_error=False)


def current_device(
    request: Request,
    db: DB,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Device:
    if credentials is None:
        raise device_service.INVALID_DEVICE
    device = device_service.authenticate_device(db, credentials.credentials)
    enforce(request, "agent", get_settings().rate_limit_agent_per_minute, extra_key=str(device.id))
    return device


CurrentDevice = Annotated[Device, Depends(current_device)]


@router.post(
    "/enroll", response_model=EnrollResponse, status_code=201, dependencies=[Depends(auth_rate_limit)]
)
def enroll(body: EnrollRequest, request: Request, db: DB) -> EnrollResponse:
    device, token = device_service.enroll(db, request, body.enrollment_token, body.device)
    db.commit()
    return EnrollResponse(
        device_id=device.id,
        organization_id=device.organization_id,
        device_token=token,
        config=AgentConfig.model_validate(device.config),
        config_version=device.config_version,
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(body: HeartbeatRequest, device: CurrentDevice, db: DB) -> HeartbeatResponse:
    device_service.heartbeat(db, device, body)
    db.commit()
    return HeartbeatResponse(
        status=device.status,
        config=AgentConfig.model_validate(device.config),
        config_version=device.config_version,
        server_time=datetime.now(UTC),
    )


@router.post("/events", response_model=IngestResult)
def submit_events(body: EventBatch, device: CurrentDevice, db: DB) -> IngestResult:
    outcome = event_service.ingest(db, device.organization_id, body.events, source="agent", device=device)
    device.last_seen_at = datetime.now(UTC)
    db.commit()
    return IngestResult(
        accepted=outcome.accepted,
        deduplicated=outcome.deduplicated,
        rejected=[RejectedEvent(**r) for r in outcome.rejected],
        alerts_created=len(outcome.alerts),
        event_ids=outcome.event_ids,
    )


@router.post("/credentials/rotate", response_model=RotateResponse)
def rotate(device: CurrentDevice, request: Request, db: DB) -> RotateResponse:
    token = device_service.rotate_credential(db, request, device)
    db.commit()
    return RotateResponse(device_token=token)


@router.post("/unenroll", status_code=204)
def unenroll(device: CurrentDevice, request: Request, db: DB) -> Response:
    device_service.decommission(db, request, device, actor_id=None, reason="agent uninstalled")
    db.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ AEGIS ONE (Phase 6) — hubs
@router.post("/sensors/readings", response_model=ReadingResult)
def sensor_readings(body: ReadingBatch, device: CurrentDevice, db: DB) -> ReadingResult:
    """Readings from a hub (ESP32, Raspberry Pi, MQTT bridge). The response carries the desired
    LED/buzzer state — state, not a command."""
    outcome = iot_service.ingest(
        db, device, [r.model_dump() for r in body.readings], simulated=body.simulated
    )
    device.last_seen_at = datetime.now(UTC)
    db.commit()
    return ReadingResult(**outcome)


@router.post("/vision/detections", response_model=DetectionResult)
def vision_detections(body: DetectionBatch, device: CurrentDevice, db: DB) -> DetectionResult:
    """Detections from the on-site camera agent (never video). Returns the camera's settings."""
    outcome = vision_service.ingest(
        db,
        device,
        camera_key=body.camera_key,
        name=body.name,
        detections=[d.model_dump() for d in body.detections],
        snapshot=body.snapshot_base64,
        simulated=body.simulated,
    )
    device.last_seen_at = datetime.now(UTC)
    db.commit()
    return DetectionResult(**outcome)


@router.get("/vision/config", response_model=CameraConfig)
def vision_config(
    device: CurrentDevice,
    db: DB,
    camera_key: Annotated[str, Query(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")],
    name: Annotated[str | None, Query(max_length=120)] = None,
) -> CameraConfig:
    camera = vision_service.get_or_register(db, device, camera_key, name)
    db.commit()
    return CameraConfig(**vision_service.camera_config(camera))
