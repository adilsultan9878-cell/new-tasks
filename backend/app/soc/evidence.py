"""Evidence vault: SHA-256 integrity and an append-only chain of custody.

Files and notes are stored as immutable bytes (PostgreSQL trigger), hashed on the server and,
when the browser sent its own hash, checked against it. "External" evidence registers the hash
of material kept elsewhere (disk images, for example). Every access is a custody entry.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import uuid
from typing import Any

from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, not_found
from app.models import Evidence, EvidenceBlob, Incident, User
from app.services import audit, realtime
from app.soc import incidents as incident_service
from app.soc.common import actor, now

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _custody(action: str, user: User | None, **extra: Any) -> dict[str, Any]:
    return {"at": now().isoformat(), "action": action, **actor(user), **extra}


def _add_custody(item: Evidence, entry: dict[str, Any]) -> None:
    item.chain_of_custody = [*(item.chain_of_custody or []), entry]


def summary(item: Evidence) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "incident_id": str(item.incident_id) if item.incident_id else None,
        "sha256": item.sha256,
    }


def get(db: Session, org_id: uuid.UUID, evidence_id: uuid.UUID) -> Evidence:
    item = db.scalar(select(Evidence).where(Evidence.id == evidence_id, Evidence.organization_id == org_id))
    if item is None:
        raise not_found("Evidence")
    return item


def add(
    db: Session,
    request: Request,
    incident: Incident,
    *,
    user: User,
    kind: str,
    title: str,
    description: str | None,
    filename: str | None,
    content_type: str | None,
    content_base64: str | None,
    note: str | None,
    sha256: str | None,
    size_bytes: int | None,
) -> Evidence:
    data: bytes | None = None
    if kind == "file":
        if not content_base64:
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "missing_content", "Attach the file to store"
            )
        try:
            data = base64.b64decode(content_base64, validate=True)
        except (binascii.Error, ValueError):
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_content", "File content is not valid base64"
            ) from None
    elif kind == "note":
        if not note or not note.strip():
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT, "missing_content", "Write the note to store"
            )
        data = note.encode("utf-8")
        filename, content_type = filename or "note.txt", "text/plain; charset=utf-8"
    limit = get_settings().evidence_max_bytes
    if data is not None:
        if len(data) > limit:
            raise AppError(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "too_large",
                f"Evidence files are limited to {limit // 1_000_000} MB; register larger material as external",
            )
        digest = hashlib.sha256(data).hexdigest()
        if sha256 and sha256.lower() != digest:
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "hash_mismatch",
                "The SHA-256 computed by your browser does not match the uploaded bytes",
            )
        sha256, size_bytes = digest, len(data)
    else:  # external: only the hash is registered
        if not sha256 or not SHA256_RE.match(sha256.lower()):
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "invalid_hash",
                "Give the SHA-256 of the external evidence",
            )
        sha256 = sha256.lower()
    item = Evidence(
        id=uuid.uuid4(),
        organization_id=incident.organization_id,
        incident_id=incident.id,
        evidence_type=kind,
        title=title,
        filename=(filename or None) and filename[:255],
        content_type=(content_type or "application/octet-stream")[:120] if kind != "external" else None,
        description=description,
        storage_uri="db://evidence_blobs" if data is not None else None,
        sha256=sha256,
        size_bytes=size_bytes,
        collected_by=user.id,
        collected_at=now(),
        chain_of_custody=[
            _custody(
                "collected", user, sha256=sha256, note="stored" if data is not None else "hash registered"
            )
        ],
    )
    db.add(item)
    db.flush()
    if data is not None:
        db.add(
            EvidenceBlob(
                evidence_id=item.id, organization_id=item.organization_id, data=data, created_at=now()
            )
        )
    incident_service.append(
        incident,
        incident_service.entry(
            "evidence", f"Evidence added: {title} (SHA-256 {sha256[:12]}…)", user, evidence_id=str(item.id)
        ),
    )
    audit.record(
        db,
        "evidence.add",
        request=request,
        actor_id=user.id,
        org_id=item.organization_id,
        target_type="evidence",
        target_id=item.id,
        details={"kind": kind, "sha256": sha256, "size": size_bytes, "incident": incident.reference},
    )
    realtime.queue_broadcast(db, item.organization_id, "incident.updated", incident_service.summary(incident))
    return item


def _blob(db: Session, item: Evidence) -> EvidenceBlob:
    blob = db.scalar(
        select(EvidenceBlob).where(
            EvidenceBlob.evidence_id == item.id, EvidenceBlob.organization_id == item.organization_id
        )
    )
    if blob is None:
        raise AppError(
            status.HTTP_409_CONFLICT, "not_stored", "Only the hash of this evidence is registered here"
        )
    return blob


def download(db: Session, request: Request, item: Evidence, *, user: User) -> bytes:
    data = _blob(db, item).data
    _add_custody(item, _custody("downloaded", user))
    audit.record(
        db,
        "evidence.download",
        request=request,
        actor_id=user.id,
        org_id=item.organization_id,
        target_type="evidence",
        target_id=item.id,
        details={"sha256": item.sha256},
    )
    return data


def verify(db: Session, request: Request, item: Evidence, *, user: User) -> dict[str, Any]:
    digest = hashlib.sha256(_blob(db, item).data).hexdigest()
    intact = digest == item.sha256
    _add_custody(item, _custody("verified", user, result="match" if intact else "MISMATCH", sha256=digest))
    audit.record(
        db,
        "evidence.verify",
        request=request,
        actor_id=user.id,
        org_id=item.organization_id,
        target_type="evidence",
        target_id=item.id,
        outcome="success" if intact else "failure",
        details={"expected": item.sha256, "actual": digest},
    )
    return {"intact": intact, "expected": item.sha256, "actual": digest}
