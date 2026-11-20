"""Device, enrollment and agent-protocol schemas.

The agent-facing models are deliberately strict: sizes are bounded and the configuration the
server sends back is an allow-list (``AgentConfig`` forbids unknown keys). There is no field that
could carry a command for the agent to execute.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.operations import DEVICE_TYPES
from app.schemas.auth import _clean_name
from app.schemas.common import APIModel

COLLECTORS = ("system", "network", "ports")
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
_SAFE_TEXT_RE = re.compile(r"^[\w .,:;()/+@#\-]*$")


def _check_ip(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    return str(ipaddress.ip_address(value))


def _check_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = " ".join(value.split())
    if not _SAFE_TEXT_RE.match(value):
        raise ValueError("contains unsupported characters")
    return value


# --------------------------------------------------------------------------- agent configuration
class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpu_percent: int = Field(default=90, ge=50, le=100)
    memory_percent: int = Field(default=90, ge=50, le=100)
    disk_percent: int = Field(default=90, ge=50, le=100)


class AgentConfig(BaseModel):
    """Everything the cloud may change on an agent. Unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")

    heartbeat_interval_seconds: int = Field(default=60, ge=15, le=3600)
    collectors: list[Literal["system", "network", "ports"]] = Field(default_factory=lambda: list(COLLECTORS))
    thresholds: Thresholds = Field(default_factory=Thresholds)

    @field_validator("collectors")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        return sorted(set(value))


# ------------------------------------------------------------------------------ enrollment tokens
class EnrollmentTokenCreate(APIModel):
    label: str = Field(min_length=1, max_length=120)
    device_type: str = "workstation"
    max_uses: int = Field(default=1, ge=1, le=100)
    expires_in_hours: int = Field(default=24, ge=1, le=168)

    _l = field_validator("label")(_clean_name)

    @field_validator("device_type")
    @classmethod
    def _type(cls, value: str) -> str:
        if value not in DEVICE_TYPES:
            raise ValueError(f"must be one of: {', '.join(DEVICE_TYPES)}")
        return value


class EnrollmentTokenOut(APIModel):
    id: uuid.UUID
    label: str
    device_type: str
    max_uses: int
    use_count: int
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    state: Literal["active", "expired", "exhausted", "revoked"]


class EnrollmentTokenCreated(EnrollmentTokenOut):
    token: str  # shown exactly once


# --------------------------------------------------------------------------------- agent protocol
class DeviceFacts(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str | None = Field(default=None, max_length=120)
    hostname: str = Field(min_length=1, max_length=255)
    os: str | None = Field(default=None, max_length=80)
    agent_version: str = Field(min_length=1, max_length=32, pattern=r"^[0-9A-Za-z.+-]+$")
    ip_address: str | None = None
    mac_address: str | None = None

    _t = field_validator("name", "hostname", "os")(_check_text)
    _ip = field_validator("ip_address")(_check_ip)

    @field_validator("mac_address")
    @classmethod
    def _mac(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        if not _MAC_RE.match(value):
            raise ValueError("invalid MAC address")
        return value.lower().replace("-", ":")


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enrollment_token: str = Field(min_length=10, max_length=300)
    device: DeviceFacts


class EnrollResponse(APIModel):
    device_id: uuid.UUID
    organization_id: uuid.UUID
    device_token: str
    config: AgentConfig
    config_version: int


class InterfaceInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(max_length=64)
    addresses: list[str] = Field(default_factory=list, max_length=8)


class Telemetry(BaseModel):
    """Approved, read-only system telemetry. Bounded so a client cannot bloat the database."""

    model_config = ConfigDict(extra="ignore")

    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)
    disk_percent: float | None = Field(default=None, ge=0, le=100)
    uptime_seconds: int | None = Field(default=None, ge=0)
    process_count: int | None = Field(default=None, ge=0, le=1_000_000)
    listening_ports: list[int] | None = Field(default=None, max_length=512)
    interfaces: list[InterfaceInfo] | None = Field(default=None, max_length=32)

    @field_validator("listening_ports")
    @classmethod
    def _ports(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        if any(p < 0 or p > 65535 for p in value):
            raise ValueError("port out of range")
        return sorted(set(value))


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent_version: str = Field(min_length=1, max_length=32, pattern=r"^[0-9A-Za-z.+-]+$")
    config_version: int | None = None
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=80)
    ip_address: str | None = None
    telemetry: Telemetry = Field(default_factory=Telemetry)

    _t = field_validator("hostname", "os")(_check_text)
    _ip = field_validator("ip_address")(_check_ip)


class HeartbeatResponse(APIModel):
    status: str
    config: AgentConfig
    config_version: int
    server_time: datetime


class RotateResponse(APIModel):
    device_token: str


# ------------------------------------------------------------------------------- console views
class DeviceOut(APIModel):
    id: uuid.UUID
    name: str
    device_type: str
    hostname: str | None
    os: str | None
    ip_address: str | None
    mac_address: str | None
    status: str
    enrollment_status: str
    health_score: int | None
    agent_version: str | None
    enrolled_at: datetime | None
    last_seen_at: datetime | None
    is_simulated: bool
    created_at: datetime


class DeviceDetail(DeviceOut):
    telemetry: dict[str, Any]
    config: dict[str, Any]
    config_version: int
    credential_rotated_at: datetime | None


class DeviceUpdate(APIModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    config: AgentConfig | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, value: str | None) -> str | None:
        return _clean_name(value) if value is not None else None
