from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.services.sweeper import sweep_offline_devices
from tests.conftest import AGENT, Fleet, facts, make_client


def _org(fleet: Fleet, path: str = "") -> str:
    return f"/api/v1/organizations/{fleet.org_id}{path}"


def test_enrollment_token_is_shown_once_and_rbac_applies(fleet, account_factory):
    created = fleet.token(label="Lab PCs", max_uses=3, expires_in_hours=2)
    assert created["token"].startswith("sxe.") and created["state"] == "active"
    listed = fleet.owner.get(_org(fleet, "/enrollment-tokens")).json()
    assert listed[0]["label"] == "Lab PCs" and "token" not in listed[0]

    analyst, viewer = account_factory("analyst"), account_factory("viewer")
    for acct, role in ((analyst, "analyst"), (viewer, "viewer")):
        fleet.owner.post(_org(fleet, "/members"), json={"email": acct.email, "role": role})
    assert analyst.post(_org(fleet, "/enrollment-tokens"), json={"label": "x"}).status_code == 201
    assert viewer.post(_org(fleet, "/enrollment-tokens"), json={"label": "x"}).status_code == 403
    assert viewer.get(_org(fleet, "/devices")).status_code == 200  # read is allowed


def test_enrollment_validation(fleet):
    for body in (
        {"label": ""},
        {"label": "a", "max_uses": 0},
        {"label": "a", "expires_in_hours": 500},
        {"label": "a", "device_type": "toaster"},
    ):
        assert fleet.owner.post(_org(fleet, "/enrollment-tokens"), json=body).status_code == 422


def test_enroll_creates_device_and_consumes_token(fleet):
    token = fleet.token()["token"]
    enrolled = fleet.enroll("finance-pc", token=token)
    assert enrolled["device_token"].startswith("sxd.")
    assert enrolled["config"]["heartbeat_interval_seconds"] == 60
    assert set(enrolled["config"]) == {"heartbeat_interval_seconds", "collectors", "thresholds"}

    devices = fleet.owner.get(_org(fleet, "/devices")).json()
    assert [(d["name"], d["status"], d["enrollment_status"]) for d in devices] == [
        ("finance-pc", "online", "enrolled")
    ]
    # single-use token is now exhausted
    again = fleet.agent.post(f"{AGENT}/enroll", json={"enrollment_token": token, "device": facts("other")})
    assert again.status_code == 401
    assert fleet.owner.get(_org(fleet, "/enrollment-tokens")).json()[0]["state"] == "exhausted"
    actions = [a["action"] for a in fleet.owner.get(_org(fleet, "/audit-logs")).json()["items"]]
    assert "device.enroll" in actions and "device.enrollment_token_create" in actions


def test_enroll_rejects_bad_expired_and_revoked_tokens(fleet, admin_engine):
    bad = ["garbage", "sxe.not.a.token", fleet.token()["token"][:-4] + "abcd"]
    for token in bad:
        resp = fleet.agent.post(f"{AGENT}/enroll", json={"enrollment_token": token, "device": facts()})
        assert resp.status_code in (401, 422)

    revoked = fleet.token()
    assert (
        fleet.owner.post(_org(fleet, f"/enrollment-tokens/{revoked['id']}/revoke")).json()["state"]
        == "revoked"
    )
    assert (
        fleet.agent.post(
            f"{AGENT}/enroll", json={"enrollment_token": revoked["token"], "device": facts()}
        ).status_code
        == 401
    )

    expired = fleet.token()
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE enrollment_tokens SET expires_at = :t WHERE id = :i"),
            {
                "t": datetime.now(UTC) - timedelta(minutes=1),
                "i": expired["id"].replace("-", "")
                if admin_engine.dialect.name == "sqlite"
                else expired["id"],
            },
        )
    assert (
        fleet.agent.post(
            f"{AGENT}/enroll", json={"enrollment_token": expired["token"], "device": facts()}
        ).status_code
        == 401
    )


def test_enroll_input_is_validated(fleet):
    token = fleet.token(max_uses=5)["token"]
    for device in (
        {"hostname": "<script>", "agent_version": "1"},
        {"hostname": "a", "agent_version": "1; rm -rf"},
        {"hostname": "a", "agent_version": "1", "ip_address": "999.1.1.1"},
        {"hostname": "a", "agent_version": "1", "mac_address": "zz"},
    ):
        assert (
            fleet.agent.post(
                f"{AGENT}/enroll", json={"enrollment_token": token, "device": device}
            ).status_code
            == 422
        )


def test_device_credentials(fleet):
    device = fleet.enroll()
    token = device["device_token"]
    assert fleet.device_post(token, "/heartbeat", {"agent_version": "0.2.0"}).status_code == 200
    forged = token.rsplit(".", 1)[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert fleet.device_post(forged, "/heartbeat", {"agent_version": "0.2.0"}).status_code == 401
    assert fleet.agent.post(f"{AGENT}/heartbeat", json={"agent_version": "1"}).status_code == 401
    # A user's JWT is not a device credential.
    assert fleet.device_post(fleet.owner.token, "/heartbeat", {"agent_version": "1"}).status_code == 401

    rotated = fleet.device_post(token, "/credentials/rotate").json()["device_token"]
    assert fleet.device_post(token, "/heartbeat", {"agent_version": "0.2.0"}).status_code == 401
    assert fleet.device_post(rotated, "/heartbeat", {"agent_version": "0.2.0"}).status_code == 200


def test_device_token_cannot_cross_tenants(fleet, account_factory):
    other = Fleet(account_factory("other"), "Other Org")
    device = fleet.enroll()
    _, _org_hex, dev_hex, secret = device["device_token"].split(".")
    swapped = f"sxd.{other.org_id.replace('-', '')}.{dev_hex}.{secret}"
    assert fleet.device_post(swapped, "/heartbeat", {"agent_version": "1"}).status_code == 401
    assert other.owner.get(f"/api/v1/organizations/{other.org_id}/devices").json() == []
    assert other.owner.get(f"/api/v1/organizations/{fleet.org_id}/devices").status_code == 404
    assert (
        other.owner.get(f"/api/v1/organizations/{other.org_id}/devices/{device['device_id']}").status_code
        == 404
    )
    assert (
        other.owner.post(
            f"/api/v1/organizations/{other.org_id}/devices/{device['device_id']}/revoke"
        ).status_code
        == 404
    )


def test_heartbeat_updates_telemetry_health_and_delivers_config(fleet):
    device = fleet.enroll()
    token = device["device_token"]
    hb = fleet.device_post(
        token,
        "/heartbeat",
        {
            "agent_version": "0.2.1",
            "ip_address": "192.168.1.20",
            "telemetry": {
                "cpu_percent": 97,
                "memory_percent": 40,
                "disk_percent": 95,
                "listening_ports": [443, 22, 22],
            },
        },
    )
    assert hb.status_code == 200 and hb.json()["status"] == "degraded"
    detail = fleet.owner.get(_org(fleet, f"/devices/{device['device_id']}")).json()
    assert detail["health_score"] == 50 and detail["agent_version"] == "0.2.1"
    assert detail["telemetry"]["listening_ports"] == [22, 443] and detail["ip_address"] == "192.168.1.20"

    new_cfg = {"heartbeat_interval_seconds": 30, "collectors": ["system"], "thresholds": {"cpu_percent": 99}}
    patched = fleet.owner.patch(
        _org(fleet, f"/devices/{device['device_id']}"), json={"name": "CFO laptop", "config": new_cfg}
    )
    assert patched.status_code == 200 and patched.json()["config_version"] == 2
    hb2 = fleet.device_post(token, "/heartbeat", {"agent_version": "0.2.1", "config_version": 1}).json()
    assert hb2["config_version"] == 2 and hb2["config"]["heartbeat_interval_seconds"] == 30


def test_config_is_an_allow_list(fleet):
    device = fleet.enroll()
    url = _org(fleet, f"/devices/{device['device_id']}")
    for cfg in (
        {"command": "powershell -enc ..."},
        {"heartbeat_interval_seconds": 1},
        {"collectors": ["system", "keylogger"]},
        {"thresholds": {"cpu_percent": 10}},
        {"thresholds": {"exec": "x"}},
    ):
        assert fleet.owner.patch(url, json={"config": cfg}).status_code == 422, cfg


def test_revoke_and_unenroll(fleet):
    a, b = fleet.enroll("a"), fleet.enroll("b")
    revoked = fleet.owner.post(_org(fleet, f"/devices/{a['device_id']}/revoke")).json()
    assert revoked["status"] == "decommissioned" and revoked["enrollment_status"] == "revoked"
    assert fleet.device_post(a["device_token"], "/heartbeat", {"agent_version": "1"}).status_code == 401

    assert fleet.device_post(b["device_token"], "/unenroll").status_code == 204
    assert fleet.device_post(b["device_token"], "/heartbeat", {"agent_version": "1"}).status_code == 401
    assert fleet.owner.get(_org(fleet, "/devices")).json() == []  # decommissioned hidden by default
    assert len(fleet.owner.get(_org(fleet, "/devices"), params={"include_decommissioned": True}).json()) == 2


def test_sweeper_marks_silent_devices_offline_and_heartbeat_recovers(fleet):
    device = fleet.enroll("quiet-pc")
    assert sweep_offline_devices() == 0
    future = datetime.now(UTC) + timedelta(hours=1)
    assert sweep_offline_devices(now=future) == 1
    assert sweep_offline_devices(now=future) == 0  # idempotent
    detail = fleet.owner.get(_org(fleet, f"/devices/{device['device_id']}")).json()
    assert detail["status"] == "offline"
    titles = [e["title"] for e in fleet.owner.get(_org(fleet, "/events")).json()["items"]]
    assert "Device quiet-pc stopped reporting" in titles

    fleet.device_post(device["device_token"], "/heartbeat", {"agent_version": "1"})
    assert fleet.owner.get(_org(fleet, f"/devices/{device['device_id']}")).json()["status"] == "online"
    types = [e["event_type"] for e in fleet.owner.get(_org(fleet, "/events")).json()["items"]]
    assert "agent.reconnected" in types


def test_agent_endpoints_are_rate_limited_per_device(fleet, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "rate_limit_agent_per_minute", 3)
    token = fleet.enroll()["device_token"]
    codes = [fleet.device_post(token, "/heartbeat", {"agent_version": "1"}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429


def test_unauthenticated_agent_requests_get_no_detail():
    resp = make_client().post(f"{AGENT}/events", json={"events": []})
    assert resp.status_code == 401
