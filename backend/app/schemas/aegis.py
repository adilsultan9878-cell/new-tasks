from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.common import APIModel

KEY = r"^[a-z0-9][a-z0-9_-]{0,63}$"
Actuator = Literal["led", "buzzer"]


# ------------------------------------------------------------------------------ agent side
class ReadingIn(BaseModel):
    sensor_key: str = Field(pattern=KEY)
    sensor_type: str = Field(default="generic", pattern=r"^[a-z_]{1,48}$")
    unit: str | None = Field(default=None, max_length=16)
    value: float
    recorded_at: datetime | None = None

    @field_validator("recorded_at")
    @classmethod
    def _recent(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        value = value if value.tzinfo else value.replace(tzinfo=UTC)
        current = datetime.now(UTC)
        if value > current + timedelta(minutes=5) or value < current - timedelta(days=1):
            raise ValueError("recorded_at must be within the last 24 hours")
        return value


class ReadingBatch(BaseModel):
    readings: list[ReadingIn] = Field(min_length=1, max_length=100)
    simulated: bool = False


class ReadingResult(APIModel):
    accepted: int
    breaches: int
    actuators: dict[str, bool]


class DetectionIn(BaseModel):
    type: Literal["motion", "person", "zone_intrusion"]
    zone: str | None = Field(default=None, max_length=80)
    confidence: float | None = Field(default=None, ge=0, le=1)
    objects: int | None = Field(default=None, ge=0, le=100)

    @model_validator(mode="after")
    def _zone(self) -> DetectionIn:
        if self.type == "zone_intrusion" and not self.zone:
            raise ValueError("zone_intrusion needs the zone name")
        return self


class DetectionBatch(BaseModel):
    camera_key: str = Field(pattern=KEY)
    name: str | None = Field(default=None, max_length=120)
    detections: list[DetectionIn] = Field(default_factory=list, max_length=20)
    snapshot_base64: str | None = Field(default=None, max_length=7_000_000)
    simulated: bool = False


class CameraConfig(APIModel):
    camera_id: uuid.UUID
    detection_enabled: bool
    zones: list[dict[str, Any]]
    snapshots: bool
    blur_people: bool
    cooldown_seconds: int


class DetectionResult(APIModel):
    accepted: int
    snapshot_stored: bool
    snapshot_discarded: str | None = None
    ignored: str | None = None
    config: CameraConfig


# -------------------------------------------------------------------------------- console
class Thresholds(BaseModel):
    min: float | None = None
    max: float | None = None
    severity: Literal["low", "medium", "high", "critical"] = "high"

    @model_validator(mode="after")
    def _order(self) -> Thresholds:
        if self.min is not None and self.max is not None and self.min >= self.max:
            raise ValueError("min must be lower than max")
        return self


class SensorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    unit: str | None = Field(default=None, max_length=16)
    thresholds: Thresholds | None = None
    actuator_rules: list[Actuator] | None = Field(default=None, max_length=2)


class SensorOut(APIModel):
    id: uuid.UUID
    device_id: uuid.UUID | None
    device_name: str | None = None
    sensor_key: str | None
    name: str
    sensor_type: str
    unit: str | None
    status: str
    thresholds: dict[str, Any]
    actuator_rules: list[str]
    in_breach: bool
    last_value: float | None
    last_reading_at: datetime | None
    is_simulated: bool


class ReadingPoint(APIModel):
    t: datetime
    v: float


class Zone(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    x: float = Field(ge=0, le=1)
    y: float = Field(ge=0, le=1)
    w: float = Field(gt=0, le=1)
    h: float = Field(gt=0, le=1)

    @model_validator(mode="after")
    def _inside(self) -> Zone:
        if self.x + self.w > 1.0001 or self.y + self.h > 1.0001:
            raise ValueError("zone must lie inside the frame")
        return self


class CameraUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    detection_enabled: bool | None = None
    privacy_mode: bool | None = None
    blur_people: bool | None = None
    retention_days: int | None = Field(default=None, ge=1, le=90)
    zones: list[Zone] | None = Field(default=None, max_length=8)


class CameraOut(APIModel):
    id: uuid.UUID
    device_id: uuid.UUID | None
    device_name: str | None = None
    camera_key: str | None
    name: str
    status: str
    detection_enabled: bool
    privacy_mode: bool
    blur_people: bool
    retention_days: int
    zones: list[dict[str, Any]]
    last_frame_at: datetime | None
    last_event_at: datetime | None
    snapshot_count: int = 0
    is_simulated: bool


class SnapshotOut(APIModel):
    id: uuid.UUID
    camera_id: uuid.UUID
    event_type: str
    content_type: str
    captured_at: datetime
    expires_at: datetime


class ActuatorOverride(BaseModel):
    actuator: Actuator
    state: Literal["on", "off", "auto"]
    minutes: int = Field(default=15, ge=1, le=240)


class HubOut(APIModel):
    device_id: uuid.UUID
    name: str
    status: str
    is_simulated: bool
    sensor_count: int
    actuators: dict[str, dict[str, Any]]


class SimulatorResult(APIModel):
    hub_id: uuid.UUID
    sensors: int
    readings: int
    breaches: int
    detections: int
    actuators: dict[str, bool]


# ---------------------------------------------------------------------- Digital Twin (Phase 7)
FLOOR_W, FLOOR_D = 100.0, 60.0


class TwinArea(BaseModel):
    id: str | None = Field(default=None, max_length=64)
    name: str = Field(min_length=1, max_length=60)
    x: float = Field(ge=0, le=FLOOR_W)
    y: float = Field(ge=0, le=FLOOR_D)
    w: float = Field(gt=0, le=FLOOR_W)
    h: float = Field(gt=0, le=FLOOR_D)

    @model_validator(mode="after")
    def _inside(self) -> TwinArea:
        if self.x + self.w > FLOOR_W + 0.001 or self.y + self.h > FLOOR_D + 0.001:
            raise ValueError("area must lie on the floor")
        return self


class TwinPosition(BaseModel):
    device_id: uuid.UUID
    x: float = Field(ge=0, le=FLOOR_W)
    y: float = Field(ge=0, le=FLOOR_D)
    area: str | None = Field(default=None, max_length=60)


class TwinLayout(BaseModel):
    areas: list[TwinArea] | None = Field(default=None, max_length=30)
    positions: list[TwinPosition] = Field(default_factory=list, max_length=500)
