"""AEGIS ONE (Phase 6): IoT hubs and actuators, privacy-first vision, simulator, retention."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.services.sweeper import purge_expired_data
from tests.conftest import Fleet

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64 + b"\xff\xd9"


def _org(fleet: Fleet, path: str = "") -> str:
    return f"/api/v1/organizations/{fleet.org_id}{path}"


def _readings(fleet: Fleet, token: str, *values: tuple[str, float], **extra):
    body = {
        "readings": [
            {"sensor_key": k, "sensor_type": "temperature", "unit": "°C", "value": v} for k, v in values
        ],
        **extra,
    }
    return fleet.device_post(token, "/sensors/readings", body)


def _detect(fleet: Fleet, token: str, detections: list[dict], **extra):
    return fleet.device_post(
        token, "/vision/detections", {"camera_key": "front-door", "detections": detections, **extra}
    )


def test_hub_readings_thresholds_events_and_actuators(fleet):
    token = fleet.enroll("esp32-lab")["device_token"]
    first = _readings(fleet, token, ("rack_temp", 24.5), ("room_temp", 22.0))
    assert first.status_code == 200 and first.json() == {
        "accepted": 2,
        "breaches": 0,
        "actuators": {"led": False, "buzzer": False},
    }
    sensor = next(
        s for s in fleet.owner.get(_org(fleet, "/sensors")).json() if s["sensor_key"] == "rack_temp"
    )
    assert (
        sensor["name"] == "Rack Temp"
        and sensor["device_name"] == "esp32-lab"
        and sensor["last_value"] == 24.5
    )

    upd = fleet.owner.patch(
        _org(fleet, f"/sensors/{sensor['id']}"),
        json={"thresholds": {"max": 40, "severity": "critical"}, "actuator_rules": ["buzzer"]},
    )
    assert upd.status_code == 200 and upd.json()["thresholds"] == {"max": 40, "severity": "critical"}

    hot = _readings(fleet, token, ("rack_temp", 47.0)).json()
    assert hot["breaches"] == 1 and hot["actuators"] == {"led": False, "buzzer": True}
    assert _readings(fleet, token, ("rack_temp", 48.0)).json()["breaches"] == 0  # still the same breach
    alerts = fleet.owner.get(_org(fleet, "/alerts")).json()
    assert (
        len(alerts) == 1
        and alerts[0]["severity"] == "critical"
        and "Rack Temp on esp32-lab is above 40" in alerts[0]["title"]
    )

    cool = _readings(fleet, token, ("rack_temp", 30.0)).json()
    assert cool["actuators"]["buzzer"] is False
    types = {
        e["event_type"]
        for e in fleet.owner.get(_org(fleet, "/events"), params={"category": "iot"}).json()["items"]
    }
    assert types == {"iot.threshold_breach", "iot.threshold_recovered"}
    points = fleet.owner.get(_org(fleet, f"/sensors/{sensor['id']}/readings"), params={"hours": 1}).json()
    assert [p["v"] for p in points] == [24.5, 47.0, 48.0, 30.0]

    assert _readings(fleet, token, ("Bad Key!", 1.0)).status_code == 422
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    bad = fleet.device_post(
        token, "/sensors/readings", {"readings": [{"sensor_key": "x", "value": 1, "recorded_at": future}]}
    )
    assert bad.status_code == 422
    assert (
        fleet.owner.patch(
            _org(fleet, f"/sensors/{sensor['id']}"), json={"thresholds": {"min": 5, "max": 1}}
        ).status_code
        == 422
    )


def test_manual_actuator_override_wins_until_released(fleet, account_factory):
    token = fleet.enroll("esp32-lab")["device_token"]
    _readings(fleet, token, ("rack_temp", 24.0))
    hub = fleet.owner.get(_org(fleet, "/hubs")).json()[0]
    assert hub["actuators"]["led"]["on"] is False and hub["sensor_count"] == 1
    on = fleet.owner.post(
        _org(fleet, f"/devices/{hub['device_id']}/actuators"),
        json={"actuator": "led", "state": "on", "minutes": 10},
    )
    assert on.json()["actuators"]["led"]["source"] == "manual"
    assert _readings(fleet, token, ("rack_temp", 24.0)).json()["actuators"]["led"] is True
    fleet.owner.post(
        _org(fleet, f"/devices/{hub['device_id']}/actuators"), json={"actuator": "led", "state": "auto"}
    )
    assert _readings(fleet, token, ("rack_temp", 24.0)).json()["actuators"]["led"] is False

    viewer = account_factory("viewer")
    fleet.owner.post(_org(fleet, "/members"), json={"email": viewer.email, "role": "viewer"})
    denied = viewer.post(
        _org(fleet, f"/devices/{hub['device_id']}/actuators"), json={"actuator": "led", "state": "on"}
    )
    assert denied.status_code == 403


def test_vision_is_off_until_enabled_and_respects_privacy(fleet, account_factory):
    token = fleet.enroll("cam-box")["device_token"]
    config = fleet.agent.get(
        "/api/v1/agent/vision/config",
        params={"camera_key": "front-door", "name": "Front door"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    assert (
        config["detection_enabled"] is False
        and config["snapshots"] is False
        and config["blur_people"] is True
    )
    ignored = _detect(fleet, token, [{"type": "motion"}]).json()
    assert ignored["accepted"] == 0 and "Detection is off" in ignored["ignored"]

    camera = fleet.owner.get(_org(fleet, "/cameras")).json()[0]
    assert camera["name"] == "Front door" and camera["privacy_mode"] is True
    zone = {"name": "Server room", "x": 0.5, "y": 0.1, "w": 0.4, "h": 0.8}
    assert (
        fleet.owner.patch(
            _org(fleet, f"/cameras/{camera['id']}"), json={"zones": [{**zone, "w": 0.9}]}
        ).status_code
        == 422
    )
    fleet.owner.patch(
        _org(fleet, f"/cameras/{camera['id']}"), json={"detection_enabled": True, "zones": [zone]}
    )

    snap = base64.b64encode(JPEG).decode()
    res = _detect(
        fleet,
        token,
        [{"type": "zone_intrusion", "zone": "Server room", "confidence": 0.9, "objects": 1}],
        snapshot_base64=snap,
    ).json()
    assert (
        res["accepted"] == 1
        and res["snapshot_stored"] is False
        and res["snapshot_discarded"] == "privacy mode is on"
    )
    assert res["config"]["zones"] == [zone]
    alerts = fleet.owner.get(_org(fleet, "/alerts")).json()
    assert (
        alerts[0]["title"] == "Person in restricted zone 'Server room' (Front door)"
        and alerts[0]["severity"] == "high"
    )

    fleet.owner.patch(
        _org(fleet, f"/cameras/{camera['id']}"), json={"privacy_mode": False, "retention_days": 3}
    )
    assert (
        _detect(
            fleet, token, [{"type": "person"}], snapshot_base64=base64.b64encode(b"GIF89a").decode()
        ).status_code
        == 422
    )
    stored = _detect(fleet, token, [{"type": "person", "confidence": 0.7}], snapshot_base64=snap).json()
    assert stored["snapshot_stored"] is True
    snaps = fleet.owner.get(_org(fleet, f"/cameras/{camera['id']}/snapshots")).json()
    assert len(snaps) == 1 and snaps[0]["event_type"] == "person"
    image = fleet.owner.get(_org(fleet, f"/snapshots/{snaps[0]['id']}/image"))
    assert image.content == JPEG and image.headers["content-type"] == "image/jpeg"

    viewer = account_factory("viewer")
    fleet.owner.post(_org(fleet, "/members"), json={"email": viewer.email, "role": "viewer"})
    assert viewer.get(_org(fleet, "/cameras")).status_code == 200
    assert viewer.get(_org(fleet, f"/snapshots/{snaps[0]['id']}/image")).status_code == 403

    again = fleet.owner.patch(_org(fleet, f"/cameras/{camera['id']}"), json={"privacy_mode": True}).json()
    assert again["snapshot_count"] == 0  # privacy mode on deletes stored snapshots at once
    audit = fleet.owner.get(_org(fleet, "/audit-logs"), params={"action": "vision.snapshot_view"}).json()
    assert audit["total"] == 1


def test_simulator_is_labelled_excluded_from_metrics_and_clearable(fleet):
    result = fleet.owner.post(_org(fleet, "/simulator/run"))
    assert result.status_code == 201, result.text
    body = result.json()
    assert body["sensors"] == 3 and body["breaches"] == 2 and body["detections"] == 3
    assert body["actuators"] == {"led": True, "buzzer": True}  # gas spike drives both
    sensors = fleet.owner.get(_org(fleet, "/sensors")).json()
    assert len(sensors) == 3 and all(s["is_simulated"] for s in sensors)
    assert fleet.owner.get(_org(fleet, "/cameras")).json()[0]["is_simulated"] is True

    summary = fleet.owner.get(_org(fleet, "/dashboard/summary")).json()
    assert summary["devices_total"] == 0 and summary["critical_alerts"] == 0
    assert summary["simulated_records_excluded"] > 0

    cleared = fleet.owner.delete(_org(fleet, "/simulator")).json()
    assert (
        cleared["sensors"] == 3
        and cleared["cameras"] == 1
        and cleared["devices"] == 1
        and cleared["alerts"] >= 2
    )
    assert fleet.owner.get(_org(fleet, "/sensors")).json() == []
    assert fleet.owner.get(_org(fleet, "/alerts")).json() == []


def test_retention_purges_old_readings_and_expired_snapshots(fleet, admin_engine):
    token = fleet.enroll("cam-box")["device_token"]
    _readings(fleet, token, ("rack_temp", 21.0))
    fleet.agent.get(
        "/api/v1/agent/vision/config",
        params={"camera_key": "front-door"},
        headers={"Authorization": f"Bearer {token}"},
    )
    camera = fleet.owner.get(_org(fleet, "/cameras")).json()[0]
    fleet.owner.patch(
        _org(fleet, f"/cameras/{camera['id']}"), json={"detection_enabled": True, "privacy_mode": False}
    )
    _detect(fleet, token, [{"type": "motion"}], snapshot_base64=base64.b64encode(JPEG).decode())
    with admin_engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT set_config('app.current_org_id', :o, true)"), {"o": fleet.org_id})
        old = datetime.now(UTC) - timedelta(days=30)
        conn.execute(text("UPDATE sensor_readings SET recorded_at = :t"), {"t": old})
        conn.execute(text("UPDATE camera_snapshots SET expires_at = :t"), {"t": old})
    assert purge_expired_data() == {"readings": 1, "snapshots": 1}


def test_aegis_is_tenant_isolated(fleet, account_factory):
    token = fleet.enroll("esp32-lab")["device_token"]
    _readings(fleet, token, ("rack_temp", 21.0))
    sensor = fleet.owner.get(_org(fleet, "/sensors")).json()[0]
    outsider = account_factory("outsider")
    other = outsider.create_org("Other Org")["organization"]["id"]
    base = f"/api/v1/organizations/{other}"
    assert outsider.patch(f"{base}/sensors/{sensor['id']}", json={"name": "pwned"}).status_code == 404
    assert outsider.get(f"{base}/sensors/{sensor['id']}/readings").status_code == 404
    assert (
        outsider.post(
            f"{base}/devices/{sensor['device_id']}/actuators", json={"actuator": "buzzer", "state": "on"}
        ).status_code
        == 404
    )
    assert outsider.get(f"{base}/sensors").json() == []
