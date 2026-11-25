"""Research Lab (Phase 9): labelled datasets, safe rule backtests, reproducibility, isolation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from tests.conftest import Fleet


def _o(fleet: Fleet, path: str = "") -> str:
    return f"/api/v1/organizations/{fleet.org_id}{path}"


def _rows() -> list[dict]:
    """Known lab data: 3 brute-force bursts on two hosts, noise, and labels."""
    t0 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
    rows = []
    for i in range(4):  # ws-1: 4 failed logins in 4 minutes (attack)
        rows.append(
            {
                "occurred_at": (t0 + timedelta(minutes=i)).isoformat(),
                "category": "auth",
                "event_type": "auth.failed_login",
                "severity": "medium",
                "title": f"Failed login {i}",
                "device": "ws-1",
                "label": "malicious",
            }
        )
    for i in range(2):  # ws-2: 2 failed logins (user typo)
        rows.append(
            {
                "occurred_at": (t0 + timedelta(hours=2, minutes=i)).isoformat(),
                "category": "auth",
                "event_type": "auth.failed_login",
                "severity": "medium",
                "title": f"Typo {i}",
                "device": "ws-2",
                "label": "benign",
            }
        )
    rows.append(
        {
            "occurred_at": (t0 + timedelta(hours=3)).isoformat(),
            "category": "malware",
            "event_type": "av.detected",
            "severity": "critical",
            "title": "Mimikatz detected",
            "device": "ws-1",
            "label": "malicious",
        }
    )
    rows.append(
        {
            "occurred_at": (t0 + timedelta(hours=4)).isoformat(),
            "category": "policy",
            "event_type": "policy.violation",
            "severity": "high",
            "title": "USB storage",
            "device": "ws-3",
            "label": "benign",
        }
    )
    rows.append(
        {
            "occurred_at": (t0 + timedelta(hours=5)).isoformat(),
            "category": "network",
            "event_type": "net.scan",
            "severity": "low",
            "title": "Port scan",
            "device": "ws-3",
        }
    )  # unlabelled
    return rows


def _upload(fleet: Fleet, account=None) -> dict:
    resp = (account or fleet.owner).post(
        _o(fleet, "/lab/datasets/upload"), json={"name": "Brute-force lab", "rows": _rows()}
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


BRUTE = {
    "mode": "all",
    "conditions": [{"field": "event_type", "op": "eq", "value": "auth.failed_login"}],
    "threshold": {"count": 3, "within_minutes": 10, "per_device": True},
}


def test_backtest_scores_a_threshold_rule_against_the_baseline(fleet):
    ds = _upload(fleet)
    assert ds["row_count"] == 9 and ds["label_counts"] == {"malicious": 5, "benign": 3, "unlabelled": 1}
    assert len(ds["sha256"]) == 64 and ds["source"] == "upload"
    exp = fleet.owner.post(
        _o(fleet, "/lab/experiments"),
        json={"dataset_id": ds["id"], "name": "3 failures / 10 min", "rule": BRUTE},
    ).json()
    r = exp["results"]
    # Fires on the 3rd and 4th failure on ws-1 only (ws-2 never reaches 3).
    assert r["fired"] == 2 and r["confusion"] == {"tp": 2, "fp": 0, "fn": 3, "tn": 3}
    assert r["precision"] == 1.0 and r["recall"] == 0.4 and r["f1"] == pytest.approx(0.5714, abs=1e-4)
    # Baseline (built-in: high/critical severity) fires on Mimikatz (tp) and USB (fp).
    assert (
        r["baseline"]["confusion"] == {"tp": 1, "fp": 1, "fn": 4, "tn": 2}
        and r["baseline"]["precision"] == 0.5
    )
    assert [s["title"] for s in r["samples"]["tp"]] == ["Failed login 2", "Failed login 3"]
    assert exp["engine_version"] == "lab-1" and exp["dataset_sha256"] == ds["sha256"]

    loose = {
        "mode": "any",
        "conditions": [
            {"field": "severity", "op": "gte", "value": "medium"},
            {"field": "title", "op": "contains", "value": "scan"},
        ],
    }
    r2 = fleet.owner.post(
        _o(fleet, "/lab/experiments"), json={"dataset_id": ds["id"], "name": "Loose", "rule": loose}
    ).json()["results"]
    assert (
        r2["fired"] == 9
        and r2["fired_unlabelled"] == 1
        and r2["recall"] == 1.0
        and r2["precision"] == pytest.approx(0.625)
    )

    again = fleet.owner.post(_o(fleet, f"/lab/experiments/{exp['id']}/reproduce")).json()
    assert again["reproduced"] is True and all(again["checks"].values())


def test_rules_are_data_and_validated(fleet):
    ds = _upload(fleet)
    bad = [
        {"conditions": [{"field": "title", "op": "gte", "value": "high"}]},
        {"conditions": [{"field": "severity", "op": "in", "value": "high"}]},
        {"conditions": [{"field": "__class__", "op": "eq", "value": "x"}]},
        {"conditions": [{"field": "title", "op": "regex", "value": ".*"}]},
        {"conditions": []},
        {"conditions": [{"field": "title", "op": "contains", "value": "x"}] * 21},
        {
            "conditions": [{"field": "title", "op": "contains", "value": "x"}],
            "threshold": {"count": 1, "within_minutes": 5},
        },
        {"conditions": [{"field": "title", "op": "contains", "value": "{{7*7}}" * 40}]},
    ]
    for rule in bad:
        resp = fleet.owner.post(
            _o(fleet, "/lab/experiments"), json={"dataset_id": ds["id"], "name": "Bad rule", "rule": rule}
        )
        assert resp.status_code == 422, rule


def test_datasets_from_recorded_events_carry_analyst_labels(fleet):
    o = _o(fleet)
    for title in ("Confirmed intrusion", "Benign admin script", "Linked to incident", "Still open"):
        fleet.owner.post(
            f"{o}/events",
            json={"event_type": "policy.violation", "category": "policy", "severity": "high", "title": title},
        )
    fleet.owner.post(
        f"{o}/events",
        json={"event_type": "net.info", "category": "network", "severity": "low", "title": "Quiet event"},
    )
    alerts = {a["title"]: a for a in fleet.owner.get(f"{o}/alerts").json()}
    fleet.owner.patch(f"{o}/alerts/{alerts['Confirmed intrusion']['id']}", json={"status": "resolved"})
    fleet.owner.patch(f"{o}/alerts/{alerts['Benign admin script']['id']}", json={"status": "false_positive"})
    fleet.owner.post(
        f"{o}/incidents", json={"title": "Case", "alert_ids": [alerts["Linked to incident"]["id"]]}
    )
    fleet.owner.post(f"{o}/simulator/run")  # simulated data is left out unless asked for

    ds = fleet.owner.post(f"{o}/lab/datasets", json={"name": "Last week", "days": 7}).json()
    assert ds["row_count"] == 5 and ds["includes_simulated"] is False
    assert ds["label_counts"] == {"malicious": 2, "benign": 1, "unlabelled": 2}
    detail = fleet.owner.get(f"{o}/lab/datasets/{ds['id']}").json()
    labels = {r["title"]: r["label"] for r in detail["preview"]}
    assert labels == {
        "Confirmed intrusion": "malicious",
        "Benign admin script": "benign",
        "Linked to incident": "malicious",
        "Still open": None,
        "Quiet event": None,
    }
    with_sim = fleet.owner.post(
        f"{o}/lab/datasets", json={"name": "With demo", "days": 7, "include_simulated": True}
    ).json()
    assert with_sim["row_count"] > 5 and with_sim["includes_simulated"] is True


def test_the_lab_never_touches_live_data(fleet):
    o = _o(fleet)
    fleet.owner.post(
        f"{o}/events",
        json={"event_type": "auth.failed_login", "category": "auth", "severity": "high", "title": "Live"},
    )
    before = {p: fleet.owner.get(f"{o}{p}").text for p in ("/events", "/alerts", "/incidents", "/actions")}
    ds = _upload(fleet)
    for _ in range(3):
        fleet.owner.post(f"{o}/lab/experiments", json={"dataset_id": ds["id"], "name": "Loop", "rule": BRUTE})
    after = {p: fleet.owner.get(f"{o}{p}").text for p in before}
    assert after == before


def test_lab_permissions_isolation_and_deletion(fleet, account_factory):
    viewer = account_factory("viewer")
    fleet.owner.post(_o(fleet, "/members"), json={"email": viewer.email, "role": "viewer"})
    ds = _upload(fleet)
    exp = fleet.owner.post(
        _o(fleet, "/lab/experiments"), json={"dataset_id": ds["id"], "name": "Brute force", "rule": BRUTE}
    ).json()
    assert viewer.get(_o(fleet, "/lab/datasets")).status_code == 200
    assert viewer.post(_o(fleet, "/lab/datasets"), json={"name": "Nope", "days": 7}).status_code == 403
    assert viewer.post(_o(fleet, f"/lab/experiments/{exp['id']}/reproduce")).json()["reproduced"] is True

    other = Fleet(account_factory("other"), "Other Org")
    base = f"/api/v1/organizations/{other.org_id}/lab"
    assert other.owner.get(f"{base}/datasets/{ds['id']}").status_code == 404
    assert (
        other.owner.post(
            f"{base}/experiments", json={"dataset_id": ds["id"], "name": "steal", "rule": BRUTE}
        ).status_code
        == 404
    )
    assert other.owner.post(f"{base}/experiments/{exp['id']}/reproduce").status_code == 404

    assert fleet.owner.delete(_o(fleet, f"/lab/datasets/{ds['id']}")).status_code == 204
    assert fleet.owner.get(_o(fleet, "/lab/experiments")).json() == []  # experiments go with their dataset


def test_lab_records_are_immutable_in_the_database(fleet, admin_engine, postgres_only):
    ds = _upload(fleet)
    fleet.owner.post(
        _o(fleet, "/lab/experiments"), json={"dataset_id": ds["id"], "name": "Brute force", "rule": BRUTE}
    )
    for stmt in ("UPDATE lab_datasets SET rows = '[]'", "UPDATE lab_experiments SET results = '{}'"):
        with pytest.raises(DBAPIError, match="immutable"), admin_engine.begin() as conn:
            conn.execute(text(stmt))
