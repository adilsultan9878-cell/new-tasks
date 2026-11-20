from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.schemas.common import APIModel


class AuditActor(APIModel):
    id: uuid.UUID
    email: str
    full_name: str


class AuditLogOut(APIModel):
    id: uuid.UUID
    action: str
    outcome: str
    actor_type: str
    actor: AuditActor | None
    target_type: str | None
    target_id: str | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    details: dict[str, Any]
    created_at: datetime


class NotificationOut(APIModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    kind: str
    title: str
    body: str | None
    link: str | None
    severity: str
    read_at: datetime | None
    created_at: datetime


class NotificationList(APIModel):
    items: list[NotificationOut]
    unread: int
