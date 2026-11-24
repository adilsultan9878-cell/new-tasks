"""Minimal HTTPS client for the agent protocol (standard library only)."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from sentinel_agent import __version__

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class AgentError(Exception):
    """Base error."""


class AuthError(AgentError):
    """The credential was rejected (revoked device, bad/expired enrollment token)."""


class RateLimited(AgentError):
    def __init__(self, retry_after: float) -> None:
        super().__init__(f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


class TransportError(AgentError):
    """Network problem or server error: safe to retry later."""


class RequestRejected(AgentError):
    """The server refused the payload (validation error). Retrying will not help."""


def normalize_server_url(url: str, allow_http: bool = False) -> str:
    url = url.strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError("server URL must look like https://api.example.com")
    if parts.scheme == "http" and parts.hostname not in LOCAL_HOSTS and not allow_http:
        raise ValueError("refusing plain HTTP to a remote server; use https:// (or --allow-http in a lab)")
    if not url.endswith("/api/v1"):
        url += "/api/v1"
    return url


class AgentClient:
    def __init__(self, base_url: str, device_token: str | None = None, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.device_token = device_token
        self.timeout = timeout
        self._ssl = ssl.create_default_context()  # certificate verification always on

    def _request(
        self,
        path: str,
        body: dict[str, Any] | None,
        auth: bool = True,
        method: str = "POST",
        query: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        data = json.dumps(body or {}).encode("utf-8") if method == "POST" else None
        if query:
            path = f"{path}?{urllib.parse.urlencode(query)}"
        headers = {"Content-Type": "application/json", "User-Agent": f"sentinel-x-agent/{__version__}"}
        if auth and self.device_token:
            headers["Authorization"] = f"Bearer {self.device_token}"
        # base_url passed normalize_server_url(): only http(s) schemes can reach this point.
        req = urllib.request.Request(  # noqa: S310
            f"{self.base_url}/agent{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl) as resp:  # noqa: S310
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            detail = _error_message(exc)
            if exc.code == 401:
                raise AuthError(detail) from None
            if exc.code == 429:
                raise RateLimited(float(exc.headers.get("Retry-After") or 30)) from None
            if exc.code in (400, 404, 413, 422):
                raise RequestRejected(f"{exc.code}: {detail}") from None
            raise TransportError(f"server error {exc.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            raise TransportError(f"cannot reach server: {exc}") from None

    def enroll(self, enrollment_token: str, facts: dict[str, Any]) -> dict[str, Any]:
        result = self._request("/enroll", {"enrollment_token": enrollment_token, "device": facts}, auth=False)
        assert result is not None
        return result

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self._request("/heartbeat", payload)
        assert result is not None
        return result

    def send_events(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        result = self._request("/events", {"events": events})
        assert result is not None
        return result

    def rotate_credentials(self) -> str:
        result = self._request("/credentials/rotate", {})
        assert result is not None
        return str(result["device_token"])

    def unenroll(self) -> None:
        self._request("/unenroll", {})

    # AEGIS ONE (Phase 6): sensor hubs and cameras
    def send_readings(self, readings: list[dict[str, Any]], simulated: bool = False) -> dict[str, Any]:
        result = self._request("/sensors/readings", {"readings": readings, "simulated": simulated})
        assert result is not None
        return result

    def vision_config(self, camera_key: str, name: str | None = None) -> dict[str, Any]:
        query = {"camera_key": camera_key, **({"name": name} if name else {})}
        result = self._request("/vision/config", None, method="GET", query=query)
        assert result is not None
        return result

    def send_detections(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = self._request("/vision/detections", payload)
        assert result is not None
        return result


def _error_message(exc: urllib.error.HTTPError) -> str:
    try:
        payload = json.loads(exc.read() or b"{}")
        return str(payload.get("error", {}).get("message") or exc.reason)
    except (ValueError, AttributeError):
        return str(exc.reason)
