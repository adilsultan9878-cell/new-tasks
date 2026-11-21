"""Device enrollment, authentication, heartbeats and lifecycle."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, not_found
from app.core.security import (
    DEVICE_TOKEN_PREFIX,
    ENROLLMENT_TOKEN_PREFIX,
    make_scoped_token,
    parse_scoped_token,
    secret_matches,
)
from app.db.session import set_tenant_context
from app.models import Device, EnrollmentToken, SecurityEvent
from app.schemas.devices import AgentConfig, DeviceFacts, HeartbeatRequest
from app.services import audit, realtime

INVALID_ENROLLMENT = AppError(
    status.HTTP_401_UNAUTHORIZED,
    "invalid_enrollment_token",
    "Enrollment token is invalid, expired or used up",
)
INVALID_DEVICE = AppError(
    status.HTTP_401_UNAUTHORIZED,
    "invalid_device_credential",
    "Device credential is invalid or the device was revoked",
    headers={"WWW-Authenticate": "Bearer"},
)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


def token_state(token: EnrollmentToken, now: datetime | None = None) -> str:
    now = now or _now()
    if token.revoked_at is not None:
        return "revoked"
    if token.use_count >= token.max_uses:
        return "exhausted"
    if (_aware(token.expires_at) or now) <= now:
        return "expired"
    return "active"


def default_config() -> dict[str, Any]:
    cfg = AgentConfig(heartbeat_interval_seconds=get_settings().agent_default_heartbeat_seconds)
    return cfg.model_dump()


def device_summary(device: Device) -> dict[str, Any]:
    """Compact payload for real-time broadcasts."""
    return {
        "id": str(device.id),
        "name": device.name,
        "status": device.status,
        "enrollment_status": device.enrollment_status,
        "health_score": device.health_score,
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
    }


# ------------------------------------------------------------------------------ enrollment tokens
def create_enrollment_token(
    db: Session,
    request: Request,
    *,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    label: str,
    device_type: str,
    max_uses: int,
    expires_in_hours: int,
) -> tuple[EnrollmentToken, str]:
    hours = min(expires_in_hours, get_settings().enrollment_token_max_hours)
    token_id = uuid.uuid4()
    raw, secret_hash = make_scoped_token(ENROLLMENT_TOKEN_PREFIX, org_id, token_id)
    token = EnrollmentToken(
        id=token_id,
        organization_id=org_id,
        label=label,
        token_hash=secret_hash,
        device_type=device_type,
        max_uses=max_uses,
        expires_at=_now() + timedelta(hours=hours),
        created_by=user_id,
    )
    db.add(token)
    audit.record(
        db,
        "device.enrollment_token_create",
        request=request,
        actor_id=user_id,
        org_id=org_id,
        target_type="enrollment_token",
        target_id=token_id,
        details={"label": label, "max_uses": max_uses, "expires_in_hours": hours},
    )
    db.flush()
    return token, raw


def revoke_enrollment_token(
    db: Session, request: Request, *, org_id: uuid.UUID, user_id: uuid.UUID, token_id: uuid.UUID
) -> EnrollmentToken:
    token = db.scalar(
        select(EnrollmentToken).where(
            EnrollmentToken.id == token_id, EnrollmentToken.organization_id == org_id
        )
    )
    if token is None:
        raise not_found("Enrollment token")
    if token.revoked_at is None:
        token.revoked_at = _now()
        audit.record(
            db,
            "device.enrollment_token_revoke",
            request=request,
            actor_id=user_id,
            org_id=org_id,
            target_type="enrollment_token",
            target_id=token_id,
        )
    return token


def enroll(db: Session, request: Request, raw_token: str, facts: DeviceFacts) -> tuple[Device, str]:
    parsed = parse_scoped_token(ENROLLMENT_TOKEN_PREFIX, raw_token)
    if parsed is None:
        raise INVALID_ENROLLMENT
    org_id, token_id, secret = parsed
    set_tenant_context(db, org_id=org_id)
    token = db.scalar(
        select(EnrollmentToken)
        .where(EnrollmentToken.id == token_id, EnrollmentToken.organization_id == org_id)
        .with_for_update()
    )
    if token is None or not secret_matches(secret, token.token_hash) or token_state(token) != "active":
        if token is not None:
            audit.record(
                db,
                "device.enroll",
                request=request,
                org_id=org_id,
                actor_type="device",
                outcome="denied",
                target_type="enrollment_token",
                target_id=token_id,
                details={"reason": token_state(token), "hostname": facts.hostname},
            )
            db.commit()
        raise INVALID_ENROLLMENT

    now = _now()
    device_id = uuid.uuid4()
    device_token, credential_hash = make_scoped_token(DEVICE_TOKEN_PREFIX, org_id, device_id)
    device = Device(
        id=device_id,
        organization_id=org_id,
        name=facts.name or facts.hostname,
        device_type=token.device_type,
        hostname=facts.hostname,
        os=facts.os,
        ip_address=facts.ip_address,
        mac_address=facts.mac_address,
        agent_version=facts.agent_version,
        status="online",
        enrollment_status="enrolled",
        credential_hash=credential_hash,
        credential_rotated_at=now,
        enrolled_at=now,
        last_seen_at=now,
        location={},
        tags=[],
        attributes={"enrollment_token_id": str(token.id)},
        telemetry={},
        config=default_config(),
        config_version=1,
    )
    db.add(device)
    token.use_count += 1
    token.last_used_at = now
    audit.record(
        db,
        "device.enroll",
        request=request,
        org_id=org_id,
        actor_type="device",
        target_type="device",
        target_id=device_id,
        details={"hostname": facts.hostname, "token": token.label},
    )
    db.add(
        SecurityEvent(
            id=uuid.uuid4(),
            organization_id=org_id,
            device_id=device_id,
            source="system",
            category="agent",
            event_type="agent.enrolled",
            severity="info",
            title=f"Device {device.name} enrolled",
            raw={},
            normalized={"device": {"id": str(device_id), "name": device.name}},
            occurred_at=now,
            ingested_at=now,
        )
    )
    db.flush()
    realtime.queue_broadcast(db, org_id, "device.updated", device_summary(device))
    return device, device_token


# --------------------------------------------------------------------------------- device auth
def authenticate_device(db: Session, raw_token: str) -> Device:
    parsed = parse_scoped_token(DEVICE_TOKEN_PREFIX, raw_token)
    if parsed is None:
        raise INVALID_DEVICE
    org_id, device_id, secret = parsed
    set_tenant_context(db, org_id=org_id)
    device = db.scalar(select(Device).where(Device.id == device_id, Device.organization_id == org_id))
    if (
        device is None
        or device.enrollment_status != "enrolled"
        or not secret_matches(secret, device.credential_hash)
    ):
        raise INVALID_DEVICE
    return device


def compute_health(telemetry: dict[str, Any], config: dict[str, Any]) -> int:
    """Transparent, deterministic health score (0-100) from the latest telemetry."""
    thresholds = {**AgentConfig().thresholds.model_dump(), **(config.get("thresholds") or {})}
    score = 100
    for key, weight in (("cpu_percent", 20), ("memory_percent", 20), ("disk_percent", 30)):
        value = telemetry.get(key)
        if value is None:
            continue
        limit = thresholds.get(key, 90)
        if value >= limit:
            score -= weight
        elif value >= limit - 10:
            score -= weight // 2
    return max(0, min(100, score))


def heartbeat(db: Session, device: Device, body: HeartbeatRequest) -> Device:
    previous = device.status
    telemetry = body.telemetry.model_dump(exclude_none=True)
    device.telemetry = {**telemetry, "reported_at": _now().isoformat()}
    device.agent_version = body.agent_version
    device.last_seen_at = _now()
    if body.hostname:
        device.hostname = body.hostname
    if body.os:
        device.os = body.os
    if body.ip_address:
        device.ip_address = body.ip_address
    device.health_score = compute_health(telemetry, device.config or {})
    from app.services.network import record_agent_ports

    record_agent_ports(
        db, device.organization_id, device.id, device.ip_address, telemetry.get("listening_ports")
    )
    device.status = "degraded" if device.health_score < 60 else "online"
    if previous == "offline":
        db.add(
            SecurityEvent(
                id=uuid.uuid4(),
                organization_id=device.organization_id,
                device_id=device.id,
                source="system",
                category="agent",
                event_type="agent.reconnected",
                severity="info",
                title=f"Device {device.name} is reporting again",
                raw={},
                normalized={"device": {"id": str(device.id), "name": device.name}},
            )
        )
    realtime.queue_broadcast(db, device.organization_id, "device.updated", device_summary(device))
    return device


def rotate_credential(db: Session, request: Request, device: Device) -> str:
    token, credential_hash = make_scoped_token(DEVICE_TOKEN_PREFIX, device.organization_id, device.id)
    device.credential_hash = credential_hash
    device.credential_rotated_at = _now()
    audit.record(
        db,
        "device.credential_rotate",
        request=request,
        org_id=device.organization_id,
        actor_type="device",
        target_type="device",
        target_id=device.id,
    )
    return token


def decommission(
    db: Session, request: Request, device: Device, *, actor_id: uuid.UUID | None, reason: str
) -> Device:
    """Revoke a device: its credential stops working immediately and it leaves live metrics."""
    device.enrollment_status = "revoked"
    device.status = "decommissioned"
    device.credential_hash = None
    audit.record(
        db,
        "device.revoke" if actor_id else "device.unenroll",
        request=request,
        actor_id=actor_id,
        actor_type="user" if actor_id else "device",
        org_id=device.organization_id,
        target_type="device",
        target_id=device.id,
        details={"name": device.name, "reason": reason},
    )
    realtime.queue_broadcast(db, device.organization_id, "device.updated", device_summary(device))
    return device


def update_device(
    db: Session,
    request: Request,
    device: Device,
    *,
    actor_id: uuid.UUID,
    name: str | None,
    config: AgentConfig | None,
) -> Device:
    changed: list[str] = []
    if name is not None and name != device.name:
        device.name = name
        changed.append("name")
    if config is not None:
        new_cfg = config.model_dump()
        if new_cfg != device.config:
            device.config = new_cfg
            device.config_version += 1
            changed.append("config")
    if changed:
        audit.record(
            db,
            "device.update",
            request=request,
            actor_id=actor_id,
            org_id=device.organization_id,
            target_type="device",
            target_id=device.id,
            details={"fields": changed, "config_version": device.config_version},
        )
        realtime.queue_broadcast(db, device.organization_id, "device.updated", device_summary(device))
    return device
