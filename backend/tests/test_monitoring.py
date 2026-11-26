"""Phase 10 monitoring: /metrics, readiness with background jobs, production settings guards."""

from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from app.core import metrics
from app.core.config import Settings, get_settings

TOKEN = "metrics-token-for-tests-0123456789"


def test_metrics_are_hidden_unless_enabled_and_authorized(client, fleet, monkeypatch):
    assert client.get("/metrics").status_code == 404  # METRICS_TOKEN not set
    monkeypatch.setattr(get_settings(), "metrics_token", TOKEN)
    assert client.get("/metrics").status_code == 404
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 404
    fleet.owner.get(f"/api/v1/organizations/{fleet.org_id}/events")
    resp = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert (
        'sentinel_http_requests_total{method="GET",route="/api/v1/organizations/{org_id}/events",status="2xx"}'
        in body
    )
    assert "sentinel_http_request_duration_seconds_bucket" in body and "sentinel_build_info" in body
    assert fleet.org_id not in body and fleet.owner.email not in body  # templates only, no IDs or people


def test_readiness_reports_jobs_and_fails_when_a_loop_dies(client, monkeypatch):
    ready = client.get("/api/v1/health/ready").json()
    assert ready["status"] == "ok" and set(ready["jobs"]) == {"sweeper", "automation"}
    assert ready["rate_limiter"] == "memory" and ready["database"]["status"] == "ok"
    monkeypatch.setattr(metrics, "START", time.time() - 3600)
    monkeypatch.setattr("app.api.v1.routes.health.START", time.time() - 3600)
    monkeypatch.setitem(metrics.registry.job_runs, "sweeper", time.time() - 3600)
    monkeypatch.setitem(metrics.registry.job_runs, "automation", time.time())
    stale = client.get("/api/v1/health/ready")
    assert stale.status_code == 503 and stale.json()["jobs"]["sweeper"]["status"] == "stale"
    assert stale.json()["jobs"]["automation"]["status"] == "ok"


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"email_backend": "console"}, "EMAIL_BACKEND=console"),
        ({"public_app_url": "http://console.example.com"}, "PUBLIC_APP_URL"),
        ({"metrics_token": "short"}, "METRICS_TOKEN"),
    ],
)
def test_production_refuses_unsafe_settings(extra, message):
    base = {
        "environment": "production",
        "jwt_secret": "p" * 48,
        "database_url": "postgresql://u:p@db.example.com/sentinel",
        "refresh_cookie_secure": True,
        "public_app_url": "https://console.example.com",
        "cors_origins": ["https://console.example.com"],
    }
    Settings(**base)  # the baseline is valid
    with pytest.raises(ValidationError, match=message):
        Settings(**{**base, **extra})


def test_email_and_registration_settings_need_their_companions():
    with pytest.raises(ValidationError, match="SMTP_HOST"):
        Settings(email_backend="smtp")
    with pytest.raises(ValidationError, match="ALLOWED_EMAIL_DOMAINS"):
        Settings(registration_mode="domains")
    assert Settings(
        registration_mode="domains", allowed_email_domains="@Blue.example, red.example"
    ).allowed_email_domains == [
        "blue.example",
        "red.example",
    ]
