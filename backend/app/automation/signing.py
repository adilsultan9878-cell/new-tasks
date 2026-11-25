"""Webhook signing secrets and HMAC signatures.

Secrets are *derived*, not stored: ``secret = whsec_ + base64url(HMAC-SHA256(master, label))`` with
``label = "<kind>:<object id>:<version>"``. Rotating bumps the version. A copy of the database
therefore holds no usable secret; the master key lives only in the environment.

Signature (outgoing and incoming): ``X-Sentinel-Signature: v1=<hex HMAC-SHA256(secret, "<ts>.<body>")>``
with ``X-Sentinel-Timestamp: <unix seconds>``. The secret string itself (UTF-8) is the HMAC key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time
import uuid

from app.core.config import _PLACEHOLDER_SECRETS, get_settings

log = logging.getLogger("sentinel.automation")
SIGNATURE_HEADER = "X-Sentinel-Signature"
TIMESTAMP_HEADER = "X-Sentinel-Timestamp"
PREFIX = "whsec_"


def key_source() -> str:
    """Where the master key comes from: dedicated | jwt (derived) | ephemeral (dev, changes on restart)."""
    settings = get_settings()
    if settings.automation_signing_key:
        return "dedicated"
    if settings.jwt_secret and settings.jwt_secret not in _PLACEHOLDER_SECRETS:
        return "jwt"
    return "ephemeral"


def _master() -> bytes:
    settings = get_settings()
    if settings.automation_signing_key:
        return settings.automation_signing_key.encode()
    # Domain-separated so the JWT secret itself is never used as a webhook key.
    return hmac.new(
        settings.effective_jwt_secret.encode(), b"sentinel-x/automation/v1", hashlib.sha256
    ).digest()


def derive_secret(kind: str, object_id: uuid.UUID, version: int) -> str:
    digest = hmac.new(_master(), f"{kind}:{object_id}:{version}".encode(), hashlib.sha256).digest()
    return PREFIX + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode(), str(timestamp).encode() + b"." + body, hashlib.sha256)
    return "v1=" + mac.hexdigest()


def signed_headers(secret: str, body: bytes, now: float | None = None) -> dict[str, str]:
    ts = int(now if now is not None else time.time())
    return {TIMESTAMP_HEADER: str(ts), SIGNATURE_HEADER: sign(secret, ts, body)}


def verify(
    secret: str, timestamp: str | None, signature: str | None, body: bytes, now: float | None = None
) -> str | None:
    """Return None when valid, otherwise a short reason (never which part of the secret was wrong)."""
    if not timestamp or not signature:
        return "missing signature headers"
    try:
        ts = int(timestamp)
    except ValueError:
        return "invalid timestamp"
    current = now if now is not None else time.time()
    if abs(current - ts) > get_settings().signature_tolerance_seconds:
        return "timestamp outside the allowed window"
    expected = sign(secret, ts, body)
    # Accept several space/comma separated signatures (lets senders sign with old and new secret).
    candidates = [c.strip() for c in signature.replace(",", " ").split() if c.strip()]
    if not any(hmac.compare_digest(expected, c) for c in candidates):
        return "signature mismatch"
    return None
