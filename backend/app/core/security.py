"""Password hashing (Argon2id), JWT access tokens and opaque refresh tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings

_hasher = PasswordHasher()  # Argon2id with library-recommended parameters
# Pre-computed hash used to equalise timing when the account does not exist.
_DUMMY_HASH = _hasher.hash("sentinel-x-timing-equaliser")

COMMON_PASSWORDS = {
    "password1234",
    "123456789012",
    "qwertyuiop12",
    "letmein12345",
    "administrator",
    "welcome12345",
    "iloveyou1234",
    "passw0rd1234",
    "password123!",
    "sentinelx123",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, email: str | None = None) -> list[str]:
    """Length-first policy (NIST SP 800-63B style) with a small blocklist."""
    settings = get_settings()
    problems: list[str] = []
    if len(password) < settings.password_min_length:
        problems.append(f"Password must be at least {settings.password_min_length} characters")
    if len(password) > 128:
        problems.append("Password must be at most 128 characters")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("Password is too common")
    if email and email.split("@")[0].lower() in password.lower() and len(email.split("@")[0]) >= 4:
        problems.append("Password must not contain your email name")
    if len(set(password)) < 5:
        problems.append("Password is too repetitive")
    return problems


def create_access_token(user_id: uuid.UUID, session_id: uuid.UUID) -> tuple[str, int]:
    settings = get_settings()
    now = datetime.now(UTC)
    ttl = timedelta(minutes=settings.access_token_ttl_minutes)
    claims: dict[str, Any] = {
        "sub": str(user_id),
        "sid": str(session_id),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "jti": secrets.token_hex(8),
        "typ": "access",
    }
    token = jwt.encode(claims, settings.effective_jwt_secret, algorithm=settings.jwt_algorithm)
    return token, int(ttl.total_seconds())


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    claims = jwt.decode(
        token,
        settings.effective_jwt_secret,
        algorithms=[settings.jwt_algorithm],  # never trust the token's own alg header
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "sid", "typ"]},
    )
    if claims.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return claims


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Refresh tokens are high-entropy, so a fast hash is appropriate; only the hash is stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- Device & enrollment credentials ------------------------------------------------------------
# Format: <prefix>.<organization uuid hex>.<record uuid hex>.<secret>
# The IDs are not secret; they let the API resolve the tenant before looking the record up, so
# Row-Level Security stays in force. Only SHA-256 of the high-entropy secret is stored.
DEVICE_TOKEN_PREFIX = "sxd"
ENROLLMENT_TOKEN_PREFIX = "sxe"


def make_scoped_token(prefix: str, org_id: uuid.UUID, record_id: uuid.UUID) -> tuple[str, str]:
    """Return (token, sha256_of_secret)."""
    secret = secrets.token_urlsafe(32)
    return f"{prefix}.{org_id.hex}.{record_id.hex}.{secret}", hash_token(secret)


def parse_scoped_token(prefix: str, token: str) -> tuple[uuid.UUID, uuid.UUID, str] | None:
    parts = token.strip().split(".")
    if len(parts) != 4 or parts[0] != prefix or not (20 <= len(parts[3]) <= 128):
        return None
    try:
        return uuid.UUID(hex=parts[1]), uuid.UUID(hex=parts[2]), parts[3]
    except ValueError:
        return None


def secret_matches(secret: str, stored_hash: str | None) -> bool:
    if not stored_hash:
        return False
    return hmac.compare_digest(hash_token(secret), stored_hash)
