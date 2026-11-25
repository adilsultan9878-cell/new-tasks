"""Phase 9 security sweep: every route of the OpenAPI document, checked automatically.

New routes are covered without editing this file:

* no route answers 2xx without credentials, except an explicit public allow-list;
* a member of another organization gets 404 on every route of an organization they do not belong
  to, and never a 2xx when they put that organization's record IDs into their own URLs;
* forged, expired, wrong-audience or refresh tokens are rejected everywhere;
* responses carry security headers, errors carry no stack traces, and oversized bodies are refused
  before they are read.
"""

from __future__ import annotations

import base64
import json
import re
import time
import uuid
from typing import Any

import jwt
import pytest

from app.core.config import get_settings
from app.main import app
from tests.conftest import Fleet, make_client

API = get_settings().api_prefix
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PARAM_RE = re.compile(r"\{([a-z_]+)\}")

# Routes that may answer 2xx without any credential (everything else must not).
PUBLIC_2XX = {
    ("GET", f"{API}/health"),
    ("GET", f"{API}/health/ready"),
    ("POST", f"{API}/auth/logout"),  # idempotent: clears the cookie even when there is none
}
# Routes authenticated by something other than a user session; they must still refuse anonymous calls.
NON_USER_AUTH = {f"{API}/agent/", f"{API}/hooks/"}


def _routes() -> list[tuple[str, str]]:
    spec = app.openapi()
    return [
        (m.upper(), p)
        for p, ops in spec["paths"].items()
        for m in ops
        if m in ("get", "post", "put", "patch", "delete")
    ]


def _call(client, method: str, path: str, headers: dict[str, str] | None = None, body: Any = None):
    kwargs: dict[str, Any] = {"headers": headers or {}}
    if method in ("POST", "PUT", "PATCH"):
        kwargs["json"] = body if body is not None else {}
    return client.request(method, path, **kwargs)


def _fill(path: str, values: dict[str, str], default: str) -> str:
    return PARAM_RE.sub(lambda m: values.get(m.group(1), default), path)


# ---------------------------------------------------------------------------------- authn sweep
def test_every_route_refuses_anonymous_callers():
    client = make_client()
    leaks = []
    checked = 0
    for method, path in _routes():
        url = _fill(path, {"cve_id": "CVE-2024-3094"}, str(uuid.uuid4()))
        resp = _call(client, method, url)
        checked += 1
        if 200 <= resp.status_code < 300 and (method, path) not in PUBLIC_2XX:
            leaks.append(f"{method} {path} -> {resp.status_code}")
        if not any(path.startswith(p) for p in NON_USER_AUTH) and (method, path) not in PUBLIC_2XX:
            if path.startswith(f"{API}/auth/") and method == "POST":
                continue  # credential-taking endpoints answer 401/422 on their own terms
            assert resp.status_code == 401, f"{method} {path} -> {resp.status_code} (expected 401)"
    assert not leaks, leaks
    assert checked >= 120  # the sweep really covers the whole API


# ---------------------------------------------------------------------------------- tenant sweep
def _seed_rich_org(fleet: Fleet, account_factory) -> None:
    """Give organization A at least one record of (almost) every kind."""
    o = lambda p="": f"/api/v1/organizations/{fleet.org_id}{p}"  # noqa: E731
    owner = fleet.owner
    analyst = account_factory("analyst-a")
    assert owner.post(o("/members"), json={"email": analyst.email, "role": "analyst"}).status_code == 201
    token = fleet.enroll("ws-a")["device_token"]
    fleet.device_post(token, "/heartbeat", {"agent_version": "0.3.0"})
    assert owner.post(o("/simulator/run")).status_code == 201
    for title in ("Admin login at 3am", "USB storage mounted"):
        owner.post(
            o("/events"),
            json={
                "event_type": "policy.violation",
                "category": "policy",
                "severity": "critical",
                "title": title,
            },
        )
    alerts = owner.get(o("/alerts")).json()
    inc = owner.post(
        o("/incidents"), json={"title": "Tenant A incident", "alert_ids": [alerts[0]["id"]]}
    ).json()
    owner.post(o(f"/incidents/{inc['id']}/notes"), json={"text": "note"})
    owner.post(
        o("/actions"),
        json={
            "action_type": "block_indicator",
            "target": {"indicator_type": "ipv4", "value": "203.0.113.9"},
            "incident_id": inc["id"],
        },
    )
    owner.post(
        o(f"/incidents/{inc['id']}/evidence"),
        json={"kind": "note", "title": "Analyst note", "note": "seen at 09:12"},
    )
    owner.post(o("/reports"), json={"report_type": "incident", "incident_id": inc["id"]})
    owner.post(o("/indicators"), json={"indicator_type": "domain", "value": "evil-a.example"})
    owner.post(o("/network/scopes"), json={"cidr": "10.10.0.0/24", "name": "Lab A"})
    owner.post(o("/investigations"), json={"subject_type": "url", "subject": "http://login-a.example/verify"})
    owner.post(o("/brain/runs"), json={"subject_type": "organization"})
    hook = owner.post(
        o("/automation/webhooks"), json={"name": "A hook", "url": "https://93.184.216.34/a"}
    ).json()["webhook"]
    wf = owner.post(
        o("/automation/workflows"),
        json={
            "name": "A manual",
            "trigger_type": "manual",
            "enabled": True,
            "requires_approval": True,
            "steps": [{"type": "notify", "message": "x"}],
        },
    ).json()
    owner.post(o(f"/automation/workflows/{wf['id']}/run"))
    owner.post(o(f"/automation/webhooks/{hook['id']}/test"))
    owner.post(o("/enrollment-tokens"), json={"label": "spare"})
    from tests.test_lab import BRUTE, _rows

    ds = owner.post(o("/lab/datasets/upload"), json={"name": "Lab A", "rows": _rows()}).json()
    owner.post(o("/lab/experiments"), json={"dataset_id": ds["id"], "name": "Brute force A", "rule": BRUTE})
    # A real camera with a stored snapshot (privacy mode switched off on purpose).
    cam_token = fleet.enroll("cam-a")["device_token"]
    auth = {"Authorization": f"Bearer {cam_token}"}
    fleet.agent.get(
        "/api/v1/agent/vision/config", params={"camera_key": "front", "name": "Front A"}, headers=auth
    )
    camera = next(c for c in owner.get(o("/cameras")).json() if c["name"] == "Front A")
    owner.patch(o(f"/cameras/{camera['id']}"), json={"detection_enabled": True, "privacy_mode": False})
    jpeg = base64.b64encode(b"\xff\xd8\xff\xe0" + b"\x00" * 64 + b"\xff\xd9").decode()
    fleet.device_post(
        cam_token,
        "/vision/detections",
        {"camera_key": "front", "detections": [{"type": "motion"}], "snapshot_base64": jpeg},
    )


def _harvest(client, org_id: str) -> tuple[dict[str, set[str]], set[str]]:
    """Every UUID organization A's owner can see, indexed by the key and list it came from."""
    by_key: dict[str, set[str]] = {}
    every: set[str] = set()

    def walk(node: Any, source: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and UUID_RE.match(v):
                    key = (source if k == "id" else k[:-3]) if k == "id" or k.endswith("_id") else None
                    if key:
                        by_key.setdefault(key, set()).add(v)
                        every.add(v)
                else:
                    walk(v, source)
        elif isinstance(node, list):
            for item in node:
                walk(item, source)

    for method, path in _routes():
        if method != "GET" or "{org_id}" not in path or PARAM_RE.findall(path) != ["org_id"]:
            continue
        resp = client.get(path.replace("{org_id}", org_id), headers={})
        if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("application/json"):
            last = path.rstrip("/").rsplit("/", 1)[-1]
            source = last[:-3] + "y" if last.endswith("ies") else last[:-1] if last.endswith("s") else last
            walk(resp.json(), source)
    # Second pass: nested lists (snapshots of a camera, readings of a sensor, ...) and detail views.
    for method, path in _routes():
        params = PARAM_RE.findall(path)
        if method != "GET" or len(params) != 2 or params[0] != "org_id":
            continue
        for candidate in sorted(_candidates(params[1], by_key, every))[:10]:
            resp = client.get(_fill(path, {"org_id": org_id}, candidate))
            if resp.status_code == 200 and resp.headers.get("content-type", "").startswith(
                "application/json"
            ):
                last = path.rstrip("/").rsplit("/", 1)[-1]
                source = last[:-1] if last.endswith("s") else last
                walk(resp.json(), source)
    notes = client.get("/api/v1/notifications").json()
    walk(notes, "notification")
    return by_key, every


def _candidates(param: str, by_key: dict[str, set[str]], every: set[str]) -> set[str]:
    stem = param[:-3]
    pool = set(by_key.get(stem, set()))
    if stem == "run":
        pool |= by_key.get("run", set())
    if stem == "member":
        pool |= by_key.get("member", set())
    if stem == "token":
        pool |= by_key.get("enrollment-token", set()) | by_key.get("token", set())
    return pool or every


def test_other_tenants_cannot_reach_anything(fleet, account_factory, receiver_ok):
    _seed_rich_org(fleet, account_factory)
    a_org = fleet.org_id
    by_key, every = _harvest_as(fleet.owner, a_org)
    assert len(every) >= 30, sorted(by_key)
    # Positive control: organization A's owner reaches every detail route with the harvested IDs,
    # so the outsider's 404s below are meaningful (not just wrong IDs).
    for method, path in _routes():
        params = [p for p in PARAM_RE.findall(path) if p != "org_id"]
        if method != "GET" or "{org_id}" not in path or not params:
            continue
        ok = any(
            200 <= fleet.owner.get(_fill(path, {"org_id": a_org}, c)).status_code < 300
            for c in sorted(_candidates(params[0], by_key, every))
        )
        assert ok, f"no harvested ID works for {path} — extend _seed_rich_org"
    before = {
        p: fleet.owner.get(f"/api/v1/organizations/{a_org}{p}").text
        for p in ("/incidents", "/actions", "/evidence", "/automation/workflows", "/members")
    }

    outsider = Fleet(account_factory("tenant-b"), "Tenant B")
    b = outsider.owner
    b_org = outsider.org_id
    probed = 0
    for method, path in _routes():
        if "{org_id}" not in path:
            continue
        params = [p for p in PARAM_RE.findall(path) if p != "org_id"]
        # 1. Organization A's URLs: always 404 (indistinguishable from a non-existent org).
        url = _fill(path, {"org_id": a_org}, next(iter(every)))
        resp = _call(b.client, method, url, b.headers)
        probed += 1
        if path.startswith(f"{API}/hooks/"):
            assert resp.status_code in (401, 404), f"{method} {path} -> {resp.status_code}"
        else:
            assert resp.status_code == 404, f"{method} {url} -> {resp.status_code}"
        # 2. B's own organization with A's record IDs: never a success.
        if params and not path.startswith(f"{API}/hooks/"):
            for param in params:
                for candidate in sorted(_candidates(param, by_key, every)):
                    url = _fill(path, {"org_id": b_org, param: candidate}, candidate)
                    resp = _call(b.client, method, url, b.headers)
                    probed += 1
                    assert not 200 <= resp.status_code < 300, f"{method} {url} leaked ({resp.status_code})"
    # Notifications are per user: B cannot mark A's notifications as read.
    for nid in by_key.get("notification", set()):
        assert b.post(f"/api/v1/notifications/{nid}/read").status_code == 404
    assert probed > 300
    after = {p: fleet.owner.get(f"/api/v1/organizations/{a_org}{p}").text for p in before}
    assert after == before  # nothing B tried changed A's data


def _harvest_as(account, org_id: str):
    class _Client:
        def get(self, url, headers=None):
            return account.get(url)

    return _harvest(_Client(), org_id)


@pytest.fixture
def receiver_ok(monkeypatch):
    import httpx

    from app.automation import delivery, targets

    delivery.set_transport(httpx.MockTransport(lambda request: httpx.Response(200)))
    monkeypatch.setattr(targets, "resolver", lambda host, port: ["93.184.216.34"])
    yield
    delivery.set_transport(None)


# ------------------------------------------------------------------------------------ tokens
def test_forged_and_misused_tokens_are_rejected(fleet):
    settings = get_settings()
    me = f"{API}/auth/me"
    good = fleet.owner.headers["Authorization"].split()[1]
    claims = jwt.decode(good, options={"verify_signature": False})
    assert fleet.owner.get(me).status_code == 200

    def call(token: str) -> int:
        return make_client().get(me, headers={"Authorization": f"Bearer {token}"}).status_code

    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    )
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    forged = {
        "alg none": f"{header}.{payload}.",
        "wrong key": jwt.encode(claims, "attacker-secret-" + "x" * 40, algorithm="HS256"),
        "expired": jwt.encode(
            {**claims, "exp": int(time.time()) - 60}, settings.effective_jwt_secret, algorithm="HS256"
        ),
        "wrong audience": jwt.encode(
            {**claims, "aud": "another-api"}, settings.effective_jwt_secret, algorithm="HS256"
        ),
        "wrong issuer": jwt.encode(
            {**claims, "iss": "someone-else"}, settings.effective_jwt_secret, algorithm="HS256"
        ),
        "unknown session": jwt.encode(
            {**claims, "sid": str(uuid.uuid4())}, settings.effective_jwt_secret, algorithm="HS256"
        ),
        "tampered signature": good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB"),
        "garbage": "not-a-token",
    }
    for name, token in forged.items():
        assert call(token) == 401, name
    # A device credential is not a user session, and vice versa.
    device_token = fleet.enroll("ws-tok")["device_token"]
    assert call(device_token) == 401
    assert fleet.device_post(good, "/heartbeat", {"agent_version": "0.3.0"}).status_code == 401
    # Logging out revokes the session behind the access token.
    no_csrf = fleet.owner.post(f"{API}/auth/logout")
    assert no_csrf.status_code == 403 and call(good) == 200  # CSRF header required: nothing revoked
    out = fleet.owner.client.post(
        f"{API}/auth/logout", headers={**fleet.owner.headers, "X-Requested-With": "sentinel-x"}
    )
    assert out.status_code == 200
    assert call(good) == 401


# ---------------------------------------------------------------------------- headers & errors
def test_security_headers_and_error_hygiene(fleet):
    for resp in (
        fleet.owner.get(f"{API}/auth/me"),
        make_client().get(f"{API}/organizations"),
        make_client().get(f"{API}/does-not-exist"),
    ):
        for name in (
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
            "X-Request-ID",
        ):
            assert name in resp.headers, (resp.request.url, name)
        assert resp.headers["Cache-Control"] == "no-store"
    bad = fleet.owner.client.post(
        f"/api/v1/organizations/{fleet.org_id}/events",
        content=b'{"title": "unterminated',
        headers={**fleet.owner.headers, "Content-Type": "application/json"},
    )
    assert bad.status_code == 422 and "Traceback" not in bad.text and bad.json()["error"]["code"]
    probes = [
        "' OR 1=1 --",
        '"; DROP TABLE users; --',
        "../../../../etc/passwd",
        "<script>alert(1)</script>",
        "%00",
        "{{7*7}}",
    ]
    for probe in probes:
        for path in ("/events", "/incidents", "/devices", "/audit-logs", "/automation/runs"):
            resp = fleet.owner.get(
                f"/api/v1/organizations/{fleet.org_id}{path}",
                params={"q": probe, "status": probe, "severity": probe},
            )
            assert resp.status_code in (200, 422), (path, probe, resp.status_code)
            assert (
                "Traceback" not in resp.text
                and "sqlite" not in resp.text.lower()
                and "psycopg" not in resp.text.lower()
            )


def test_oversized_bodies_are_refused_before_they_are_read(fleet):
    limit = get_settings().max_request_bytes
    client = make_client()
    big = b'{"email":"' + b"a" * (limit + 10) + b'","password":"x"}'
    resp = client.post(f"{API}/auth/login", content=big, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413

    def chunks():  # no Content-Length: the limit is enforced while streaming
        for _ in range(limit // 65_536 + 2):
            yield b"a" * 65_536

    resp = client.post(f"{API}/auth/login", content=chunks(), headers={"Content-Type": "application/json"})
    assert resp.status_code == 413
    # Upload routes keep their larger, purpose-sized limits.
    o = f"/api/v1/organizations/{fleet.org_id}"
    inc = fleet.owner.post(f"{o}/incidents", json={"title": "Upload limits"}).json()
    payload = base64.b64encode(b"x" * (limit + 100_000)).decode()
    resp = fleet.owner.post(
        f"{o}/incidents/{inc['id']}/evidence",
        json={
            "kind": "file",
            "title": "Disk image excerpt",
            "filename": "dump.bin",
            "content_base64": payload,
        },
    )
    assert resp.status_code == 201, resp.text


def test_fuzzer_findings_stay_fixed(fleet):
    """Regressions for what Schemathesis found in Phase 9 (each used to be a 500)."""
    o = f"/api/v1/organizations/{fleet.org_id}"
    resp = fleet.owner.patch(o, json={"name": None, "description": ""})
    assert resp.status_code == 422 and "cannot be null" in resp.text
    fleet.owner.post(f"{o}/simulator/run")
    sensor = fleet.owner.get(f"{o}/sensors").json()[0]
    assert fleet.owner.patch(f"{o}/sensors/{sensor['id']}", json={"name": None}).status_code == 422
    assert (
        fleet.owner.patch(f"{o}/sensors/{sensor['id']}", json={"unit": None}).status_code == 200
    )  # nullable column
    for path in ("/automation/runs", "/automation/deliveries", "/events", "/audit-logs"):
        assert fleet.owner.get(f"{o}{path}", params={"offset": 9223372036854775808}).status_code == 422


def test_responses_made_outside_the_app_still_carry_security_headers(fleet):
    """CORS preflights and early 413s never reach the app middleware (found by OWASP ZAP)."""
    client = make_client()
    origin = get_settings().cors_origins[0]
    responses = {
        "preflight": client.options(
            f"{API}/auth/me", headers={"Origin": origin, "Access-Control-Request-Method": "GET"}
        ),
        "too large": client.post(
            f"{API}/auth/login",
            content=b"x" * (get_settings().max_request_bytes + 1),
            headers={"Content-Type": "application/json"},
        ),
    }
    assert responses["preflight"].status_code == 200 and responses["too large"].status_code == 413
    for name, resp in responses.items():
        for header in (
            "Cross-Origin-Resource-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
        ):
            assert header in resp.headers, (name, header)
        assert resp.headers["Cache-Control"] == "no-store", name
