"""In-process sliding-window rate limiter.

Good enough for a single backend instance (local, Render free tier). For horizontally scaled
deployments swap the storage for Redis — the interface stays the same.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import Request, status

from app.core.config import get_settings
from app.core.errors import AppError


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: float = 60.0) -> tuple[bool, int]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] >= window_seconds:
                bucket.popleft()
            if len(bucket) >= limit:
                return False, max(1, int(window_seconds - (now - bucket[0])) + 1)
            bucket.append(now)
            if len(self._hits) > 50_000:  # crude memory guard
                self._evict(now, window_seconds)
            return True, 0

    def _evict(self, now: float, window: float) -> None:
        for key in [k for k, b in self._hits.items() if not b or now - b[-1] >= window]:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    # Uvicorn's --proxy-headers (enabled in production) already resolves X-Forwarded-For
    # from trusted proxies into request.client, so we never parse the header ourselves.
    return request.client.host if request.client else "unknown"


def enforce(request: Request, bucket: str, limit: int, extra_key: str = "") -> None:
    if not get_settings().rate_limit_enabled:
        return
    allowed, retry_after = limiter.hit(f"{bucket}:{client_ip(request)}:{extra_key}", limit)
    if not allowed:
        raise AppError(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many requests. Please slow down and try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )


def auth_rate_limit(request: Request) -> None:
    """Strict limit for credential-bearing endpoints (login, register, password change)."""
    enforce(request, f"auth:{request.url.path}", get_settings().rate_limit_auth_per_minute)


def refresh_rate_limit(request: Request) -> None:
    enforce(request, "auth:refresh", get_settings().rate_limit_refresh_per_minute)
