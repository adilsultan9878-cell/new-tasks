def test_liveness(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_readiness_checks_database(client):
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["database"]["status"] == "ok"
    assert body["database"]["row_level_security"] in {"enforced", "not_supported"}


def test_security_headers_and_request_id(client):
    resp = client.get("/api/v1/health")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["cache-control"] == "no-store"
    assert len(resp.headers["x-request-id"]) >= 8


def test_request_id_is_propagated_when_valid(client):
    resp = client.get("/api/v1/health", headers={"X-Request-ID": "trace-abc-12345"})
    assert resp.headers["x-request-id"] == "trace-abc-12345"
    resp = client.get("/api/v1/health", headers={"X-Request-ID": "bad id\nwith newline"})
    assert resp.headers["x-request-id"] != "bad id\nwith newline"


def test_cors_allows_configured_origin_only(client):
    ok = client.options(
        "/api/v1/auth/login",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    evil = client.options(
        "/api/v1/auth/login",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in evil.headers


def test_unknown_route_uses_error_envelope(client):
    resp = client.get("/api/v1/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
