"""Request body limits (Phase 9 hardening).

Every request body is capped before it is read into memory: ``MAX_REQUEST_BYTES`` (1 MB) by default,
and a route-specific limit for the few routes that accept uploads. Bodies above the limit get
``413`` without being buffered.
"""

from __future__ import annotations

import math

from app.core.config import get_settings

_JSON_OVERHEAD = 262_144  # room for the JSON envelope and other fields


def base64_upload(raw_bytes: int) -> int:
    """Body limit for a JSON request carrying ``raw_bytes`` of base64-encoded data."""
    return max(get_settings().max_request_bytes, math.ceil(raw_bytes * 4 / 3) + _JSON_OVERHEAD)


def default() -> int:
    return get_settings().max_request_bytes


def evidence() -> int:
    return base64_upload(get_settings().evidence_max_bytes)


def camera_snapshot() -> int:
    return base64_upload(get_settings().camera_snapshot_max_bytes)


def scan_import() -> int:
    # Nmap XML (max 5 MB) inside a JSON string: escaping quotes can grow it, so allow headroom.
    return max(default(), 12_000_000)


def agent_events() -> int:
    s = get_settings()
    return max(default(), s.ingest_max_events_per_batch * (s.ingest_max_raw_bytes + 8_192) + _JSON_OVERHEAD)


def inbound_hook() -> int:
    return get_settings().inbound_hook_max_bytes
