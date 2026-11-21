"""Outbound HTTP for intelligence providers, restricted to an allow-list of hosts."""

from __future__ import annotations

import threading
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.config import get_settings

STATIC_HOSTS = {
    "services.nvd.nist.gov",
    "www.cisa.gov",
    "data.iana.org",
    "urlhaus-api.abuse.ch",
    "mb-api.abuse.ch",
    "api.abuseipdb.com",
    "www.virustotal.com",
    "cloudflare-dns.com",
}
MAX_BYTES = 8_000_000


class IntelUnavailable(Exception):
    """The source could not be consulted (offline, blocked, timeout, error, not configured)."""


class _Allowlist:
    def __init__(self) -> None:
        self._dynamic: set[str] = set()
        self._lock = threading.Lock()

    def allow(self, host: str) -> None:
        with self._lock:
            self._dynamic.add(host.lower())

    def __contains__(self, host: str) -> bool:
        host = host.lower()
        with self._lock:
            return host in STATIC_HOSTS or host in self._dynamic


allowlist = _Allowlist()
_transport: httpx.BaseTransport | None = None  # tests inject httpx.MockTransport here


def set_transport(transport: httpx.BaseTransport | None) -> None:
    global _transport
    _transport = transport


def request_json(
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    accept_status: tuple[int, ...] = (200,),
) -> tuple[int, Any]:
    settings = get_settings()
    if settings.intel_offline:
        raise IntelUnavailable("outbound intelligence lookups are disabled (INTEL_OFFLINE)")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.hostname not in allowlist:
        # Defence against SSRF: the subject of an investigation can never become a request target.
        raise IntelUnavailable(f"host not allowed for intelligence lookups: {parts.hostname}")

    try:
        with httpx.Client(
            timeout=settings.intel_http_timeout_seconds,
            follow_redirects=False,
            transport=_transport,
            headers={"User-Agent": "sentinel-x-nexus-zero/0.3", "Accept": "application/json"},
        ) as client:
            resp = client.request(method, url, params=params, data=data, headers=headers)
    except httpx.HTTPError as exc:
        raise IntelUnavailable(f"{parts.hostname} unreachable: {exc.__class__.__name__}") from None
    if len(resp.content) > MAX_BYTES:
        raise IntelUnavailable(f"{parts.hostname} response too large")
    if resp.status_code not in accept_status:
        raise IntelUnavailable(f"{parts.hostname} answered HTTP {resp.status_code}")
    try:
        body = resp.json()
    except ValueError:
        raise IntelUnavailable(f"{parts.hostname} returned non-JSON") from None
    return resp.status_code, body
