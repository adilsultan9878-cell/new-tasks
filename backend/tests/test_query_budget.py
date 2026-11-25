"""Phase 9 performance: list endpoints run a fixed number of SQL statements (no N+1).

Each endpoint is measured with a few records, then again with many more; the statement count must
not grow with the number of rows returned.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import event

from app.db.session import get_engine
from tests.conftest import Fleet

ENDPOINTS = (
    "/devices",
    "/events",
    "/alerts",
    "/incidents",
    "/actions",
    "/evidence",
    "/sensors",
    "/hubs",
    "/cameras",
    "/twin",
    "/dashboard/summary",
    "/brain/runs",
    "/brain/decisions",
    "/automation/workflows",
    "/automation/runs",
    "/automation/webhooks",
    "/members",
    "/audit-logs",
)


@contextmanager
def counted() -> Iterator[list[int]]:
    engine = get_engine()
    n = [0]

    def _count(*_args, **_kwargs) -> None:
        n[0] += 1

    event.listen(engine, "before_cursor_execute", _count)
    try:
        yield n
    finally:
        event.remove(engine, "before_cursor_execute", _count)


def _measure(fleet: Fleet) -> dict[str, int]:
    out = {}
    for path in ENDPOINTS:
        with counted() as n:
            resp = fleet.owner.get(f"/api/v1/organizations/{fleet.org_id}{path}")
        assert resp.status_code == 200, (path, resp.text)
        out[path] = n[0]
    return out


def _grow(fleet: Fleet, account_factory, rounds: int, tag: str) -> None:
    o = f"/api/v1/organizations/{fleet.org_id}"
    owner = fleet.owner
    for i in range(rounds):
        token = fleet.enroll(f"{tag}-ws-{i}")["device_token"]
        fleet.device_post(token, "/heartbeat", {"agent_version": "0.3.0"})
        fleet.device_post(
            token,
            "/events",
            {
                "events": [
                    {
                        "event_type": "auth.failed_login",
                        "category": "auth",
                        "severity": "high",
                        "title": f"{tag} login {i}",
                    }
                ]
            },
        )
        fleet.device_post(
            token,
            "/sensors/readings",
            {"readings": [{"sensor_key": f"temp{i}", "sensor_type": "temperature", "value": 21.5}]},
        )
        member = account_factory(f"{tag}-m{i}")
        owner.post(f"{o}/members", json={"email": member.email, "role": "viewer"})
        alerts = owner.get(f"{o}/alerts").json()
        inc = owner.post(
            f"{o}/incidents", json={"title": f"{tag} incident {i}", "alert_ids": [alerts[0]["id"]]}
        ).json()
        owner.post(
            f"{o}/incidents/{inc['id']}/evidence", json={"kind": "note", "title": f"Note {i}", "note": "x"}
        )
        owner.post(
            f"{o}/actions",
            json={"action_type": "notify_team", "target": {"message": f"m{i}"}, "incident_id": inc["id"]},
        )
        wf = owner.post(
            f"{o}/automation/workflows",
            json={
                "name": f"{tag} wf {i}",
                "trigger_type": "manual",
                "enabled": True,
                "requires_approval": False,
                "steps": [{"type": "notify", "message": "x"}],
            },
        ).json()
        owner.post(f"{o}/automation/workflows/{wf['id']}/run")
        owner.post(
            f"{o}/automation/webhooks",
            json={"name": f"{tag} hook {i}", "url": f"https://93.184.216.{i + 1}/h"},
        )


def test_list_endpoints_do_not_grow_queries_with_rows(fleet, account_factory):
    fleet.owner.post(f"/api/v1/organizations/{fleet.org_id}/simulator/run")
    _grow(fleet, account_factory, 2, "a")
    small = _measure(fleet)
    _grow(fleet, account_factory, 8, "b")
    large = _measure(fleet)
    grown = {p: (small[p], large[p]) for p in ENDPOINTS if large[p] > small[p] + 1}
    assert not grown, f"statement count grows with rows (N+1): {grown}"
    assert max(large.values()) <= 40, large
