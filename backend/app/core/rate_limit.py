"""Sliding-window rate limiting: Redis when REDIS_URL is set, in-process otherwise.

* **In-process** (default): exact per instance; enough for one API instance (local, Render free).
* **Redis** (Phase 9): one shared window for every API instance. Each hit is a single atomic Lua
  script (prune, count, add, expire) timed by the Redis server clock, so instances with drifting
  clocks agree. Keys are SHA-256 hashes: client addresses and e-mail addresses never reach Redis.
* If Redis is unreachable the limiter falls back to the in-process window (per-instance limits,
  never "no limits") and logs it at most once a minute; it retries Redis on every call.
"""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Any

from fastapi import Request, status

from app.core.config import get_settings
from app.core.errors import AppError

log = logging.getLogger("sentinel.ratelimit")
KEY_PREFIX = "sx:rl:"

_SLIDING_WINDOW_LUA = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
if redis.call('ZCARD', KEYS[1]) < limit then
    redis.call('ZADD', KEYS[1], now, ARGV[3])
    redis.call('PEXPIRE', KEYS[1], window)
    return {1, 0}
end
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
return {0, tonumber(oldest[2]) + window - now}
"""


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


class RedisLimiter:
    def __init__(self, url: str) -> None:
        import redis  # optional dependency path: only imported when REDIS_URL is set

        self.url = url
        self._client = redis.Redis.from_url(
            url, socket_timeout=0.5, socket_connect_timeout=0.5, health_check_interval=30
        )
        self._script: Any = self._client.register_script(_SLIDING_WINDOW_LUA)

    @staticmethod
    def storage_key(key: str) -> str:
        return KEY_PREFIX + hashlib.sha256(key.encode()).hexdigest()[:40]

    def hit(self, key: str, limit: int, window_seconds: float = 60.0) -> tuple[bool, int]:
        allowed, retry_ms = self._script(
            keys=[self.storage_key(key)], args=[int(window_seconds * 1000), limit, uuid.uuid4().hex]
        )
        if int(allowed):
            return True, 0
        return False, max(1, math.ceil(int(retry_ms) / 1000))

    def ping(self) -> bool:
        return bool(self._client.ping())

    def reset(self) -> None:
        keys = list(self._client.scan_iter(match=KEY_PREFIX + "*", count=500))
        if keys:
            self._client.delete(*keys)


class Limiter:
    """The limiter the application uses: Redis when configured, with an in-process fallback."""

    def __init__(self) -> None:
        self.memory = SlidingWindowLimiter()
        self._redis: RedisLimiter | None = None
        self._lock = threading.Lock()
        self._last_warning = 0.0
        self.fallbacks = 0  # hits served by the in-process window because Redis failed

    def _backend(self) -> RedisLimiter | None:
        url = get_settings().redis_url
        if not url:
            return None
        with self._lock:
            if self._redis is None or self._redis.url != url:
                self._redis = RedisLimiter(url)
            return self._redis

    def _warn(self, exc: Exception) -> None:
        now = time.monotonic()
        if now - self._last_warning > 60:
            self._last_warning = now
            log.warning("Redis rate limiter unavailable (%s): using per-instance limits", type(exc).__name__)

    def hit(self, key: str, limit: int, window_seconds: float = 60.0) -> tuple[bool, int]:
        backend = self._backend()
        if backend is not None:
            try:
                return backend.hit(key, limit, window_seconds)
            except Exception as exc:  # connection refused, timeout, auth, ... never take the API down
                self.fallbacks += 1
                self._warn(exc)
        return self.memory.hit(key, limit, window_seconds)

    def status(self) -> str:
        """memory | redis | redis_unavailable (shown on the system status page)."""
        backend = self._backend()
        if backend is None:
            return "memory"
        try:
            return "redis" if backend.ping() else "redis_unavailable"
        except Exception:
            return "redis_unavailable"

    def reset(self) -> None:
        self.memory.reset()
        backend = self._backend()
        if backend is not None:
            try:
                backend.reset()
            except Exception as exc:
                self._warn(exc)


limiter = Limiter()


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
