"""Organization A's data must never be visible to, or modifiable by, members of organization B."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import insert

from app.models import Alert, Device, Incident, SecurityEvent

ORGS = "/api/v1/organizations"


def _seed_operational_data(engine, org_id: str, simulated: bool = False) -> None:
    now = datetime.now(UTC)
    oid = uuid.UUID(org_id)
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            from sqlalchemy import text

            conn.execute(text("SELECT set_config('app.current_org_id', :o, true)"), {"o": org_id})
        conn.execute(
            insert(Device),
            [
                {
                    "id": uuid.uuid4(),
                    "organization_id": oid,
                    "name": f"ws-{i}",
                    "device_type": "workstation",
                    "status": status,
                    "enrollment_status": "enrolled",
                    "health_score": 80 + i,
                    "location": {},
                    "tags": [],
                    "attributes": {},
                    "is_simulated": simulated,
                    "created_at": now,
                    "updated_at": now,
                }
                for i, status in enumerate(("online", "online", "offline"))
            ],
        )
        conn.execute(
            insert(SecurityEvent),
            [
                {
                    "id": uuid.uuid4(),
                    "organization_id": oid,
                    "source": "agent",
                    "category": "network",
                    "event_type": "port_scan",
                    "severity": "high",
                    "status": "new",
                    "title": "Scan",
                    "raw": {},
                    "normalized": {},
                    "occurred_at": now - timedelta(hours=1),
                    "ingested_at": now,
                    "is_simulated": simulated,
                },
            ],
        )
        conn.execute(
            insert(Alert),
            [
                {
                    "id": uuid.uuid4(),
                    "organization_id": oid,
                    "title": "Critical thing",
                    "severity": "critical",
                    "status": "open",
                    "is_simulated": simulated,
                    "created_at": now,
                    "updated_at": now,
                },
            ],
        )
        conn.execute(
            insert(Incident),
            [
                {
                    "id": uuid.uuid4(),
                    "organization_id": oid,
                    "reference": "INC-SIM-1" if simulated else "INC-1",
                    "title": "Incident",
                    "severity": "high",
                    "status": "investigating",
                    "opened_at": now,
                    "is_simulated": simulated,
                    "created_at": now,
                    "updated_at": now,
                },
            ],
        )


def test_non_members_cannot_see_or_touch_another_org(account_factory):
    alice, mallory = account_factory("alice"), account_factory("mallory")
    org_a = alice.create_org("Org A")["organization"]["id"]
    mallory.create_org("Org B")

    for path in ("", "/members", "/dashboard/summary", "/audit-logs"):
        resp = mallory.get(f"{ORGS}/{org_a}{path}")
        assert resp.status_code == 404, path  # indistinguishable from non-existent
    assert mallory.patch(f"{ORGS}/{org_a}", json={"name": "pwned"}).status_code == 404
    assert (
        mallory.post(f"{ORGS}/{org_a}/members", json={"email": mallory.email, "role": "owner"}).status_code
        == 404
    )
    assert alice.get(f"{ORGS}/{org_a}").json()["organization"]["name"] == "Org A"

    # Random / malformed IDs behave the same way.
    assert mallory.get(f"{ORGS}/{uuid.uuid4()}").status_code == 404
    assert mallory.get(f"{ORGS}/not-a-uuid").status_code == 422


def test_org_listing_only_shows_own_memberships(account_factory):
    alice, bob = account_factory("alice"), account_factory("bob")
    alice.create_org("Alpha")
    bob.create_org("Bravo")
    assert [m["organization"]["name"] for m in alice.get(ORGS).json()] == ["Alpha"]
    assert [m["organization"]["name"] for m in bob.get(ORGS).json()] == ["Bravo"]


def test_audit_logs_are_tenant_scoped(account_factory):
    alice, bob = account_factory("alice"), account_factory("bob")
    org_a = alice.create_org("Alpha")["organization"]["id"]
    org_b = bob.create_org("Bravo")["organization"]["id"]
    bob.patch(f"{ORGS}/{org_b}", json={"description": "bob's change"})
    a_logs = alice.get(f"{ORGS}/{org_a}/audit-logs").json()["items"]
    assert {log["action"] for log in a_logs} == {"org.create"}
    assert all(log["actor"]["email"] == alice.email for log in a_logs)


def test_member_ids_from_other_orgs_cannot_be_targeted(account_factory):
    alice, bob = account_factory("alice"), account_factory("bob")
    org_a = alice.create_org("Alpha")["organization"]["id"]
    org_b = bob.create_org("Bravo")["organization"]["id"]
    bob_member_id = bob.get(f"{ORGS}/{org_b}/members").json()[0]["id"]
    # Alice is owner of A, but Bob's membership belongs to B.
    assert alice.patch(f"{ORGS}/{org_a}/members/{bob_member_id}", json={"role": "viewer"}).status_code == 404
    assert alice.delete(f"{ORGS}/{org_a}/members/{bob_member_id}").status_code == 404


def test_dashboard_reports_real_numbers_per_tenant(account_factory, admin_engine):
    alice, bob = account_factory("alice"), account_factory("bob")
    org_a = alice.create_org("Alpha")["organization"]["id"]
    org_b = bob.create_org("Bravo")["organization"]["id"]

    empty = alice.get(f"{ORGS}/{org_a}/dashboard/summary").json()
    assert empty["devices_total"] == 0 and empty["open_incidents"] == 0
    assert empty["critical_alerts"] == 0 and empty["device_health_avg"] is None
    assert len(empty["network_activity_24h"]) == 24

    _seed_operational_data(admin_engine, org_a)
    _seed_operational_data(admin_engine, org_a, simulated=True)

    a = alice.get(f"{ORGS}/{org_a}/dashboard/summary").json()
    assert a["devices_total"] == 3
    assert {c["key"]: c["count"] for c in a["devices_by_status"]} == {"online": 2, "offline": 1}
    assert a["device_health_avg"] == 81.0
    assert a["active_events"] == 1 and a["events_last_24h"] == 1
    assert a["critical_alerts"] == 1 and a["open_incidents"] == 1
    assert sum(b["count"] for b in a["network_activity_24h"]) == 1
    assert a["simulated_records_excluded"] == 6  # simulated rows are never counted as real

    b = bob.get(f"{ORGS}/{org_b}/dashboard/summary").json()
    assert b["devices_total"] == 0 and b["critical_alerts"] == 0 and b["simulated_records_excluded"] == 0
