"""Digital Twin (Phase 7): one read model of devices, alerts, incidents, sensors and layout."""

from __future__ import annotations

from tests.conftest import Fleet


def _org(fleet: Fleet, path: str = "") -> str:
    return f"/api/v1/organizations/{fleet.org_id}{path}"


def test_twin_combines_devices_alerts_incidents_sensors_and_segments(fleet):
    token = fleet.enroll("ws-01")["device_token"]
    fleet.device_post(token, "/heartbeat", {"agent_version": "0.3.0", "ip_address": "10.1.2.3"})
    other = fleet.enroll("ws-02")["device_token"]
    fleet.device_post(other, "/heartbeat", {"agent_version": "0.3.0", "ip_address": "10.1.2.40"})
    fleet.device_post(
        token,
        "/events",
        {
            "events": [
                {
                    "event_type": "malware.found",
                    "category": "malware",
                    "severity": "critical",
                    "title": "Ransomware note",
                }
            ]
        },
    )
    fleet.device_post(token, "/sensors/readings", {"readings": [{"sensor_key": "rack_temp", "value": 22}]})
    alert = fleet.owner.get(_org(fleet, "/alerts")).json()[0]
    inc = fleet.owner.post(
        _org(fleet, "/incidents"), json={"title": "Ransomware", "alert_ids": [alert["id"]]}
    ).json()

    twin = fleet.owner.get(_org(fleet, "/twin")).json()
    assert twin["floor"] == {"width": 100.0, "depth": 60.0} and twin["areas"] == []
    ws1 = next(d for d in twin["devices"] if d["name"] == "ws-01")
    assert ws1["open_alerts"] == 1 and ws1["max_alert_severity"] == "critical"
    assert ws1["open_incidents"] == [
        {
            "id": inc["id"],
            "reference": inc["reference"],
            "title": "Ransomware",
            "severity": "critical",
            "status": "open",
        }
    ]
    assert (
        ws1["sensors"][0]["name"] == "Rack Temp"
        and ws1["position"] is None
        and ws1["segment"] == "10.1.2.0/24"
    )
    assert twin["segments"] == [{"cidr": "10.1.2.0/24", "device_ids": [d["id"] for d in twin["devices"]]}]
    assert (
        twin["stats"]["devices"] == 2
        and twin["stats"]["open_incidents"] == 1
        and twin["stats"]["placed"] == 0
    )


def test_layout_is_validated_saved_and_permissioned(fleet, account_factory):
    fleet.enroll("ws-01")
    device = fleet.owner.get(_org(fleet, "/devices")).json()[0]
    bad_area = {"areas": [{"name": "Too wide", "x": 80, "y": 0, "w": 30, "h": 10}]}
    assert fleet.owner.put(_org(fleet, "/twin/layout"), json=bad_area).status_code == 422
    unknown = {"positions": [{"device_id": "00000000-0000-0000-0000-000000000001", "x": 1, "y": 1}]}
    assert fleet.owner.put(_org(fleet, "/twin/layout"), json=unknown).status_code == 404

    layout = {
        "areas": [
            {"name": "Server room", "x": 2, "y": 2, "w": 20, "h": 15, "id": "forged", "simulated": True}
        ],
        "positions": [{"device_id": device["id"], "x": 10, "y": 8, "area": "Server room"}],
    }
    twin = fleet.owner.put(_org(fleet, "/twin/layout"), json=layout).json()
    assert (
        twin["areas"][0]["name"] == "Server room" and twin["areas"][0]["simulated"] is False
    )  # flag not trusted
    assert twin["devices"][0]["position"] == {"x": 10.0, "y": 8.0, "area": "Server room"}
    assert twin["stats"]["placed"] == 1

    viewer = account_factory("viewer")
    fleet.owner.post(_org(fleet, "/members"), json={"email": viewer.email, "role": "viewer"})
    assert viewer.get(_org(fleet, "/twin")).status_code == 200
    assert viewer.put(_org(fleet, "/twin/layout"), json=layout).status_code == 403
    audit = fleet.owner.get(_org(fleet, "/audit-logs"), params={"action": "twin.layout_update"}).json()
    assert audit["total"] == 1


def test_simulator_furnishes_the_twin_and_clearing_keeps_real_areas(fleet):
    fleet.owner.put(
        _org(fleet, "/twin/layout"), json={"areas": [{"name": "Lab", "x": 70, "y": 40, "w": 20, "h": 15}]}
    )
    fleet.owner.post(_org(fleet, "/simulator/run"))
    twin = fleet.owner.get(_org(fleet, "/twin")).json()
    assert {a["name"] for a in twin["areas"]} == {"Lab", "Server room", "Office", "Reception"}
    assert twin["stats"]["simulated"] == 4 and twin["stats"]["placed"] == 4
    db = next(d for d in twin["devices"] if d["name"] == "sim-db-01")
    assert db["status"] == "degraded" and db["risk_score"] == 67 and db["position"]["area"] == "Server room"
    hub = next(d for d in twin["devices"] if d["name"] == "Simulated sensor hub")
    assert len(hub["sensors"]) == 3 and len(hub["cameras"]) == 1 and hub["open_alerts"] >= 1
    assert (
        fleet.owner.get(_org(fleet, "/twin"), params={"include_simulated": "false"}).json()["devices"] == []
    )

    fleet.owner.delete(_org(fleet, "/simulator"))
    twin = fleet.owner.get(_org(fleet, "/twin")).json()
    assert [a["name"] for a in twin["areas"]] == ["Lab"] and twin["devices"] == []


def test_twin_is_tenant_isolated(fleet, account_factory):
    fleet.enroll("ws-01")
    device = fleet.owner.get(_org(fleet, "/devices")).json()[0]
    outsider = account_factory("outsider")
    other = outsider.create_org("Other Org")["organization"]["id"]
    base = f"/api/v1/organizations/{other}"
    assert outsider.get(f"{base}/twin").json()["devices"] == []
    moved = outsider.put(
        f"{base}/twin/layout", json={"positions": [{"device_id": device["id"], "x": 1, "y": 1}]}
    )
    assert moved.status_code == 404
    assert outsider.get(_org(fleet, "/twin")).status_code == 404
