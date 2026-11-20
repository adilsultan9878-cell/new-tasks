"""Audit trail writer. Every security-relevant action is recorded, including failures/denials."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.logging import request_id_ctx
from app.core.rate_limit import client_ip
from app.models import AuditLog


def record(
    db: Session,
    action: str,
    *,
    request: Request | None = None,
    actor_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | uuid.UUID | None = None,
    outcome: str = "success",
    actor_type: str = "user",
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        id=uuid.uuid4(),
        organization_id=org_id,
        actor_user_id=actor_id,
        actor_type=actor_type,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        outcome=outcome,
        ip_address=client_ip(request) if request else None,
        user_agent=(request.headers.get("user-agent") or "")[:255] or None if request else None,
        request_id=request_id_ctx.get(),
        details=details or {},
    )
    db.add(entry)
    return entry
