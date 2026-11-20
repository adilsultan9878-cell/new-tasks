from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter
from sqlalchemy import func, select, update

from app.api.deps import DB, CurrentPrincipal
from app.core.errors import not_found
from app.models import Notification
from app.schemas.audit import NotificationList, NotificationOut
from app.schemas.common import Message

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=NotificationList)
def list_notifications(principal: CurrentPrincipal, db: DB) -> NotificationList:
    mine = Notification.user_id == principal.user.id
    rows = db.scalars(select(Notification).where(mine).order_by(Notification.created_at.desc()).limit(50))
    unread = (
        db.scalar(select(func.count()).select_from(Notification).where(mine, Notification.read_at.is_(None)))
        or 0
    )
    return NotificationList(items=[NotificationOut.model_validate(r) for r in rows], unread=unread)


@router.post("/{notification_id}/read", response_model=NotificationOut)
def mark_read(notification_id: uuid.UUID, principal: CurrentPrincipal, db: DB) -> NotificationOut:
    row = db.scalar(
        select(Notification).where(
            Notification.id == notification_id, Notification.user_id == principal.user.id
        )
    )
    if row is None:
        raise not_found("Notification")
    row.read_at = row.read_at or datetime.now(UTC)
    db.commit()
    return NotificationOut.model_validate(row)


@router.post("/read-all", response_model=Message)
def mark_all_read(principal: CurrentPrincipal, db: DB) -> Message:
    db.execute(
        update(Notification)
        .where(Notification.user_id == principal.user.id, Notification.read_at.is_(None))
        .values(read_at=datetime.now(UTC))
    )
    db.commit()
    return Message(message="All notifications marked as read")
