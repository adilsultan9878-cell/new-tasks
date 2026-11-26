"""Phase 9: rate limiting shared through Redis (several API instances, one budget).

Runs against a real Redis: TEST_REDIS_URL (CI service), or a throwaway ``redis-server`` started
here when the binary is installed. Skipped otherwise.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time

import pytest

from app.core.config import get_settings
from app.core.rate_limit import KEY_PREFIX, Limiter, RedisLimiter


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def redis_url():
    url = os.environ.get("TEST_REDIS_URL")
    if url:
        yield url
        return
    binary = shutil.which("redis-server")
    if not binary:
        pytest.skip("no Redis available (set TEST_REDIS_URL or install redis-server)")
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603 - fixed argv
        [binary, "--port", str(port), "--save", "", "--appendonly", "no", "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"redis://127.0.0.1:{port}/15"
    for _ in range(50):
        try:
            if RedisLimiter(url).ping():
                break
        except Exception:
            time.sleep(0.1)
    yield url
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture
def use_redis(redis_url, monkeypatch):
    monkeypatch.setattr(get_settings(), "redis_url", redis_url)
    RedisLimiter(redis_url).reset()
    yield redis_url
    RedisLimiter(redis_url).reset()


def test_two_instances_share_one_budget(use_redis):
    api_1, api_2 = Limiter(), Limiter()  # two API processes behind a load balancer
    results = [api_1.hit("login:203.0.113.5", 5)[0] for _ in range(3)]
    results += [api_2.hit("login:203.0.113.5", 5)[0] for _ in range(3)]
    assert results == [True, True, True, True, True, False]
    allowed, retry = api_1.hit("login:203.0.113.5", 5)
    assert not allowed and 1 <= retry <= 60
    assert api_1.hit("login:198.51.100.7", 5)[0] is True  # other keys are independent
    assert api_1.status() == "redis" and api_1.fallbacks == 0


def test_window_slides_and_keys_are_hashed(use_redis):
    import redis

    lim = Limiter()
    assert [lim.hit("ip:203.0.113.9", 2, window_seconds=1)[0] for _ in range(3)] == [True, True, False]
    time.sleep(1.1)
    assert lim.hit("ip:203.0.113.9", 2, window_seconds=1)[0] is True
    keys = [k.decode() for k in redis.Redis.from_url(use_redis).scan_iter(match="*")]
    assert keys and all(k.startswith(KEY_PREFIX) for k in keys)
    assert not any("203.0.113.9" in k for k in keys)  # no client address stored in Redis
    ttl = redis.Redis.from_url(use_redis).pttl(keys[0])
    assert 0 < ttl <= 1000  # expires with the window


def test_redis_outage_falls_back_to_per_instance_limits(monkeypatch):
    monkeypatch.setattr(get_settings(), "redis_url", f"redis://127.0.0.1:{_free_port()}/0")  # nothing listens
    lim = Limiter()
    assert [lim.hit("k", 2)[0] for _ in range(3)] == [True, True, False]  # still limited, never unlimited
    assert lim.fallbacks == 3 and lim.status() == "redis_unavailable"


def test_the_api_enforces_limits_through_redis(use_redis, client, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_limit_auth_per_minute", 3)
    body = {"email": "nobody@example.com", "password": "Wrong-Password-123"}
    codes = [client.post("/api/v1/auth/login", json=body).status_code for _ in range(4)]
    assert codes[:3] == [401, 401, 401] and codes[3] == 429
    # A second API instance (fresh in-process state) sees the same budget through Redis.
    from app.core import rate_limit

    monkeypatch.setattr(rate_limit, "limiter", Limiter())
    assert client.post("/api/v1/auth/login", json=body).status_code == 429
    health = client.get("/api/v1/health/ready")
    assert health.status_code in (200, 503)
