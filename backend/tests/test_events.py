from datetime import UTC, datetime, timedelta

from tests.conftest import Fleet


def ev(**overrides):
    return {
        "event_type": "network.new_listening_port",
        "category": "network",
        "severity": "medium",
        "title": "New listening port 4444",
        "raw": {"port": 4444},
        **overrides,
    }


def _org(fleet: Fleet, path: str = "") -> str:
    return f"/api/v1/organizations/{fleet.org_id}{path}"


def test_agent_ingests_batch_with_per_item_rejections(fleet):
    token = fleet.enroll()["device_token"]
    future = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    old = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    resp = fleet.device_post(
        token,
        "/events",
        {
            "events": [
                ev(),
                ev(title="CPU high", event_type="system.high_cpu", category="system", severity="low"),
                ev(title="Clock skew", occurred_at=future),
                ev(title="Ancient", occurred_at=old),
            ]
        },
    )
    body = resp.json()
    assert resp.status_code == 200 and body["accepted"] == 2
    assert [r["index"] for r in body["rejected"]] == [2, 3]

    page = fleet.owner.get(_org(fleet, "/events"), params={"category": "network"}).json()
    assert page["total"] == 1
    item = page["items"][0]
    assert item["device_name"] == "ws-01" and item["source"] == "agent"
    detail = fleet.owner.get(_org(fleet, f"/events/{item['id']}")).json()
    assert detail["normalized"]["host"]["hostname"] == "ws-01"
    assert detail["normalized"]["observables"]["port"] == 4444


def test_ingest_schema_validation(fleet):
    token = fleet.enroll()["device_token"]
    bad_batches = [
        {"events": []},
        {"events": [ev(category="made-up")]},
        {"events": [ev(event_type="Bad Type!")]},
        {"events": [ev(severity="apocalyptic")]},
        {"events": [ev(raw={"blob": "x" * 20_000})]},
        {"events": [ev() for _ in range(101)]},
    ]
    for batch in bad_batches:
        assert fleet.device_post(token, "/events", batch).status_code == 422


def test_duplicates_fold_into_one_event(fleet):
    token = fleet.enroll()["device_token"]
    first = fleet.device_post(token, "/events", {"events": [ev()]}).json()
    second = fleet.device_post(token, "/events", {"events": [ev(), ev()]}).json()
    assert first["accepted"] == 1 and second["deduplicated"] == 2
    items = fleet.owner.get(_org(fleet, "/events"), params={"category": "network"}).json()["items"]
    assert len(items) == 1 and items[0]["occurrence_count"] == 3
    # Different explicit dedup keys are different events.
    third = fleet.device_post(token, "/events", {"events": [ev(dedup_key="a"), ev(dedup_key="b")]}).json()
    assert third["accepted"] == 2


def test_severity_rule_raises_alert_and_notifies_responders(fleet, account_factory):
    analyst, viewer = account_factory("analyst"), account_factory("viewer")
    for acct, role in ((analyst, "analyst"), (viewer, "viewer")):
        fleet.owner.post(_org(fleet, "/members"), json={"email": acct.email, "role": role})
    token = fleet.enroll()["device_token"]
    result = fleet.device_post(
        token,
        "/events",
        {
            "events": [
                ev(
                    title="Ransomware note detected",
                    event_type="malware.ransom_note",
                    category="malware",
                    severity="critical",
                ),
                ev(title="Low thing", severity="low"),
            ]
        },
    ).json()
    assert result["alerts_created"] == 1

    alerts = fleet.owner.get(_org(fleet, "/alerts")).json()
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical"
    assert alerts[0]["detection_rule"] == "severity-threshold" and alerts[0]["risk_score"] == 95

    def alert_notes(acct):
        return [n for n in acct.get("/api/v1/notifications").json()["items"] if n["kind"] == "alert"]

    assert len(alert_notes(fleet.owner)) == 1 and len(alert_notes(analyst)) == 1
    assert alert_notes(viewer) == []  # viewers are not responders

    summary = fleet.owner.get(_org(fleet, "/dashboard/summary")).json()
    assert summary["critical_alerts"] == 1 and summary["devices_total"] == 1
    assert summary["active_events"] >= 2
    assert summary["recent_events"][0]["device_name"] == "ws-01"


def test_bruteforce_rule_counts_duplicates_and_fires_once(fleet):
    token = fleet.enroll()["device_token"]
    fail = ev(event_type="auth.login_failed", category="auth", severity="low", title="Failed login for admin")
    for _ in range(4):
        assert fleet.device_post(token, "/events", {"events": [fail]}).json()["alerts_created"] == 0
    assert fleet.device_post(token, "/events", {"events": [fail]}).json()["alerts_created"] == 1
    assert fleet.device_post(token, "/events", {"events": [fail]}).json()["alerts_created"] == 0
    alerts = fleet.owner.get(_org(fleet, "/alerts")).json()
    assert [a["detection_rule"] for a in alerts] == ["auth-bruteforce"]
    assert "5 failed logins" in alerts[0]["description"]


def test_manual_events_and_triage_rbac(fleet, account_factory):
    analyst, viewer = account_factory("analyst"), account_factory("viewer")
    for acct, role in ((analyst, "analyst"), (viewer, "viewer")):
        fleet.owner.post(_org(fleet, "/members"), json={"email": acct.email, "role": role})
    created = analyst.post(
        _org(fleet, "/events"),
        json=ev(title="Suspicious USB inserted", category="policy", event_type="policy.usb_inserted"),
    )
    assert created.status_code == 201
    event_id = created.json()["event_ids"][0]
    assert viewer.post(_org(fleet, "/events"), json=ev()).status_code == 403

    assert viewer.patch(_org(fleet, f"/events/{event_id}"), json={"status": "closed"}).status_code == 403
    triaged = analyst.patch(_org(fleet, f"/events/{event_id}"), json={"status": "triaged"})
    assert triaged.status_code == 200 and triaged.json()["status"] == "triaged"
    assert fleet.owner.get(_org(fleet, "/events"), params={"status": "triaged"}).json()["total"] == 1
    actions = [a["action"] for a in fleet.owner.get(_org(fleet, "/audit-logs")).json()["items"]]
    assert "event.status_change" in actions and "event.submit" in actions


def test_events_are_tenant_isolated(fleet, account_factory):
    other = Fleet(account_factory("other"), "Other")
    token = fleet.enroll()["device_token"]
    event_id = fleet.device_post(token, "/events", {"events": [ev()]}).json()["event_ids"][0]
    other_device = other.enroll("their-pc")

    assert (
        other.owner.get(f"/api/v1/organizations/{other.org_id}/events").json()["total"] == 1
    )  # only their enroll
    assert other.owner.get(f"/api/v1/organizations/{other.org_id}/events/{event_id}").status_code == 404
    assert other.owner.get(f"/api/v1/organizations/{fleet.org_id}/events").status_code == 404
    # An analyst cannot attach an event to another tenant's device.
    resp = fleet.owner.post(_org(fleet, "/events"), json={**ev(), "device_id": other_device["device_id"]})
    assert resp.status_code == 404
