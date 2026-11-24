"""SENTINEL X SOC (Phase 5): incidents, approval-gated response actions, evidence vault, reports."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.config import get_settings
from tests.conftest import Fleet

C2 = "203.0.113.66"


def _org(fleet: Fleet, path: str = "") -> str:
    return f"/api/v1/organizations/{fleet.org_id}{path}"


def _add(fleet: Fleet, account, role: str) -> None:
    resp = fleet.owner.post(_org(fleet, "/members"), json={"email": account.email, "role": role})
    assert resp.status_code == 201, resp.text


def _alerts(fleet: Fleet, *titles: str, severity: str = "high") -> list[dict]:
    for title in titles:
        body = {"event_type": "policy.violation", "category": "policy", "severity": severity, "title": title}
        assert fleet.owner.post(_org(fleet, "/events"), json=body).status_code == 201
    return fleet.owner.get(_org(fleet, "/alerts")).json()


def _incident(fleet: Fleet, alert_ids: list[str] | None = None, **extra) -> dict:
    resp = fleet.owner.post(
        _org(fleet, "/incidents"),
        json={"title": "Suspicious activity", "alert_ids": alert_ids or [], **extra},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _propose(account, fleet: Fleet, action_type: str, target: dict, **extra):
    return account.post(_org(fleet, "/actions"), json={"action_type": action_type, "target": target, **extra})


def _device(fleet: Fleet) -> dict:
    token = fleet.enroll("ws-09")["device_token"]
    assert fleet.device_post(token, "/heartbeat", {"agent_version": "0.2.0"}).status_code == 200
    return fleet.owner.get(_org(fleet, "/devices")).json()[0]


# ------------------------------------------------------------------------------- incidents
def test_incident_lifecycle_from_alerts(fleet, account_factory):
    analyst = account_factory("analyst")
    _add(fleet, analyst, "analyst")
    alerts = _alerts(fleet, "Unknown USB device", "Admin login at 3am", severity="critical")
    inc = _incident(fleet, [a["id"] for a in alerts])
    year = datetime.now(UTC).year
    assert (
        inc["reference"] == f"INC-{year}-0001" and inc["severity"] == "critical" and inc["alert_count"] == 2
    )
    assert {a["status"] for a in inc["alerts"]} == {"acknowledged"}
    assert _incident(fleet)["reference"] == f"INC-{year}-0002"

    resp = fleet.owner.patch(
        _org(fleet, f"/incidents/{inc['id']}"),
        json={"status": "investigating", "assigned_to": analyst.user["id"]},
    )
    assert resp.status_code == 200 and resp.json()["assignee_name"] == analyst.user["full_name"]
    notes = analyst.get("/api/v1/notifications").json()
    assert any(inc["reference"] in n["title"] for n in (notes["items"] if isinstance(notes, dict) else notes))
    analyst.post(_org(fleet, f"/incidents/{inc['id']}/notes"), json={"text": "Imaged the workstation."})

    closed = fleet.owner.patch(_org(fleet, f"/incidents/{inc['id']}"), json={"status": "closed"}).json()
    assert closed["status"] == "closed" and closed["closed_at"]
    assert {a["status"] for a in closed["alerts"]} == {"resolved"}
    kinds = [t["kind"] for t in closed["timeline"]]
    assert kinds[0] == "status" and "note" in kinds and kinds[-1] == "created"  # newest first

    viewer = account_factory("viewer")
    _add(fleet, viewer, "viewer")
    assert viewer.get(_org(fleet, f"/incidents/{inc['id']}")).status_code == 200
    assert viewer.post(_org(fleet, "/incidents"), json={"title": "nope"}).status_code == 403


def test_alert_triage_workflow(fleet, account_factory):
    alert = _alerts(fleet, "Port scan from the guest Wi-Fi")[0]
    resp = fleet.owner.patch(_org(fleet, f"/alerts/{alert['id']}"), json={"status": "false_positive"})
    assert resp.status_code == 200 and resp.json()["status"] == "false_positive"
    viewer = account_factory("viewer")
    _add(fleet, viewer, "viewer")
    assert viewer.patch(_org(fleet, f"/alerts/{alert['id']}"), json={"status": "open"}).status_code == 403


# ------------------------------------------------------------------------- response actions
def test_low_impact_action_runs_immediately(fleet, account_factory):
    analyst = account_factory("analyst")
    _add(fleet, analyst, "analyst")
    resp = _propose(analyst, fleet, "notify_team", {"message": "Isolate the finance VLAN, call me"})
    assert (
        resp.status_code == 201 and resp.json()["status"] == "succeeded" and resp.json()["approval"] is None
    )
    assert resp.json()["result"]["notified"] >= 1  # the owner (and admins) manage alerts


def test_block_indicator_needs_approval_feeds_blocklist_and_rolls_back(fleet, account_factory):
    analyst = account_factory("analyst")
    _add(fleet, analyst, "analyst")
    assert (
        _propose(
            analyst, fleet, "block_indicator", {"indicator_type": "ipv4", "value": "10.0.0.8"}
        ).status_code
        == 422
    )
    action = _propose(
        analyst, fleet, "block_indicator", {"indicator_type": "ipv4", "value": C2}, reason="C2 beacon"
    ).json()
    assert action["status"] == "pending_approval" and action["impact"] == "medium"
    assert (
        analyst.post(_org(fleet, f"/actions/{action['id']}/decision"), json={"approve": True}).status_code
        == 403
    )

    approved = fleet.owner.post(
        _org(fleet, f"/actions/{action['id']}/decision"), json={"approve": True, "comment": "ok"}
    ).json()
    assert approved["status"] == "succeeded" and approved["approval"]["decided_by_name"]
    blocklist = fleet.owner.get(_org(fleet, "/blocklist"), params={"type": "ip"})
    assert blocklist.headers["content-type"].startswith("text/plain") and f"{C2}\n" in blocklist.text
    indicator = fleet.owner.get(_org(fleet, "/indicators"), params={"q": C2}).json()["items"][0]
    assert indicator["verdict"] == "malicious"

    rolled = fleet.owner.post(_org(fleet, f"/actions/{action['id']}/rollback")).json()
    assert rolled["status"] == "rolled_back"
    assert C2 not in fleet.owner.get(_org(fleet, "/blocklist"), params={"type": "ip"}).text
    assert fleet.owner.get(_org(fleet, "/indicators"), params={"q": C2}).json()["total"] == 0


def test_high_impact_actions_need_a_second_approver(fleet, account_factory):
    admin = account_factory("admin")
    _add(fleet, admin, "admin")
    device = _device(fleet)
    action = _propose(fleet.owner, fleet, "revoke_device", {"device_id": device["id"]}).json()
    assert action["impact"] == "high" and action["reversible"] is False
    denied = fleet.owner.post(_org(fleet, f"/actions/{action['id']}/decision"), json={"approve": True})
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "separation_of_duties"

    done = admin.post(_org(fleet, f"/actions/{action['id']}/decision"), json={"approve": True}).json()
    assert done["status"] == "succeeded"
    assert fleet.owner.get(_org(fleet, f"/devices/{device['id']}")).json()["enrollment_status"] == "revoked"
    assert (
        fleet.owner.post(_org(fleet, f"/actions/{action['id']}/rollback")).json()["error"]["code"]
        == "not_reversible"
    )


def test_sole_approver_may_self_approve_and_it_is_recorded(fleet):
    device = _device(fleet)
    action = _propose(fleet.owner, fleet, "revoke_device", {"device_id": device["id"]}).json()
    done = fleet.owner.post(_org(fleet, f"/actions/{action['id']}/decision"), json={"approve": True}).json()
    assert done["status"] == "succeeded" and "self-approved" in done["approval"]["comment"]


def test_suspend_member_and_restore(fleet, account_factory):
    admin, analyst = account_factory("admin"), account_factory("analyst")
    _add(fleet, admin, "admin")
    _add(fleet, analyst, "analyst")
    assert (
        _propose(fleet.owner, fleet, "suspend_member", {"user_id": fleet.owner.user["id"]}).status_code == 422
    )
    assert (
        _propose(admin, fleet, "suspend_member", {"user_id": fleet.owner.user["id"]}).status_code == 403
    )  # higher role

    action = _propose(
        fleet.owner, fleet, "suspend_member", {"user_id": analyst.user["id"]}, reason="token leaked"
    ).json()
    admin.post(_org(fleet, f"/actions/{action['id']}/decision"), json={"approve": True})
    assert analyst.get(_org(fleet, "/incidents")).status_code == 404  # access is gone at once
    fleet.owner.post(_org(fleet, f"/actions/{action['id']}/rollback"))
    assert analyst.get(_org(fleet, "/incidents")).status_code == 200


def test_heighten_monitoring_and_rollback_restore_the_agent_config(fleet):
    device = _device(fleet)
    action = _propose(fleet.owner, fleet, "heighten_monitoring", {"device_id": device["id"]}).json()
    fleet.owner.post(_org(fleet, f"/actions/{action['id']}/decision"), json={"approve": True})
    assert (
        fleet.owner.get(_org(fleet, f"/devices/{device['id']}")).json()["config"][
            "heartbeat_interval_seconds"
        ]
        == 15
    )
    fleet.owner.post(_org(fleet, f"/actions/{action['id']}/rollback"))
    assert (
        fleet.owner.get(_org(fleet, f"/devices/{device['id']}")).json()["config"][
            "heartbeat_interval_seconds"
        ]
        == 60
    )


def test_emergency_stop_holds_every_execution(fleet, account_factory):
    analyst = account_factory("analyst")
    _add(fleet, analyst, "analyst")
    assert analyst.post(_org(fleet, "/response/emergency-stop"), json={"engaged": True}).status_code == 403
    stop = fleet.owner.post(
        _org(fleet, "/response/emergency-stop"), json={"engaged": True, "reason": "drill"}
    ).json()
    assert stop["engaged"] is True and stop["reason"] == "drill"

    held = _propose(analyst, fleet, "notify_team", {"message": "status update"}).json()
    assert held["status"] == "approved" and "Emergency stop" in held["result"]["held"]
    assert fleet.owner.post(_org(fleet, f"/actions/{held['id']}/run")).json()["status"] == "approved"

    fleet.owner.post(_org(fleet, "/response/emergency-stop"), json={"engaged": False})
    assert fleet.owner.post(_org(fleet, f"/actions/{held['id']}/run")).json()["status"] == "succeeded"
    status = fleet.owner.get(_org(fleet, "/response/status")).json()
    assert status["emergency_stop"]["engaged"] is False and {t["key"] for t in status["action_types"]} == {
        "notify_team",
        "heighten_monitoring",
        "block_indicator",
        "revoke_device",
        "suspend_member",
    }


def test_pending_approvals_expire(fleet, admin_engine):
    action = _propose(
        fleet.owner, fleet, "block_indicator", {"indicator_type": "domain", "value": "evil.example"}
    ).json()
    with admin_engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(
                text(
                    "SELECT set_config('app.current_context', 'api', true), set_config('app.current_org_id', :o, true)"
                ),
                {"o": fleet.org_id},
            )
        conn.execute(
            text("UPDATE approvals SET expires_at = :t"), {"t": datetime.now(UTC) - timedelta(minutes=1)}
        )
    row = fleet.owner.get(_org(fleet, "/actions")).json()["items"][0]
    assert (
        row["id"] == action["id"] and row["status"] == "cancelled" and row["approval"]["status"] == "expired"
    )


def test_closing_an_incident_requires_decided_actions(fleet):
    inc = _incident(fleet)
    action = _propose(
        fleet.owner,
        fleet,
        "block_indicator",
        {"indicator_type": "domain", "value": "evil.example"},
        incident_id=inc["id"],
    ).json()
    resp = fleet.owner.patch(_org(fleet, f"/incidents/{inc['id']}"), json={"status": "closed"})
    assert resp.status_code == 409 and resp.json()["error"]["code"] == "actions_pending"
    fleet.owner.post(_org(fleet, f"/actions/{action['id']}/cancel"))
    detail = fleet.owner.patch(_org(fleet, f"/incidents/{inc['id']}"), json={"status": "closed"}).json()
    assert detail["status"] == "closed" and detail["actions"][0]["status"] == "cancelled"
    assert any("Proposed" in t["text"] for t in detail["timeline"])


# --------------------------------------------------------------------------------- evidence
def test_evidence_vault_hashes_and_tracks_custody(fleet, account_factory, monkeypatch):
    inc = _incident(fleet)
    data = b"MZ\x90\x00 suspicious binary sample"
    digest = hashlib.sha256(data).hexdigest()
    url = _org(fleet, f"/incidents/{inc['id']}/evidence")
    file_body = {
        "kind": "file",
        "title": "Dropper sample",
        "filename": "../../dropper.exe",
        "content_base64": base64.b64encode(data).decode(),
        "sha256": digest,
    }
    bad = fleet.owner.post(url, json={**file_body, "sha256": "0" * 64})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "hash_mismatch"
    item = fleet.owner.post(url, json=file_body).json()
    assert item["sha256"] == digest and item["size_bytes"] == len(data) and item["filename"] == "dropper.exe"
    assert item["stored"] and item["chain_of_custody"][0]["action"] == "collected"

    download = fleet.owner.get(_org(fleet, f"/evidence/{item['id']}/download"))
    assert download.content == data and download.headers["x-evidence-sha256"] == digest
    assert download.headers["content-type"] == "application/octet-stream"
    verified = fleet.owner.post(_org(fleet, f"/evidence/{item['id']}/verify")).json()
    assert verified["intact"] is True
    assert [c["action"] for c in verified["evidence"]["chain_of_custody"]] == [
        "collected",
        "downloaded",
        "verified",
    ]

    assert (
        fleet.owner.post(url, json={"kind": "external", "title": "Disk image", "sha256": "xyz"}).status_code
        == 422
    )
    ext = fleet.owner.post(url, json={"kind": "external", "title": "Disk image", "sha256": "A" * 64}).json()
    assert ext["stored"] is False and ext["sha256"] == "a" * 64
    assert fleet.owner.get(_org(fleet, f"/evidence/{ext['id']}/download")).status_code == 409
    note = fleet.owner.post(
        url, json={"kind": "note", "title": "Interview", "note": "User clicked the link at 09:12"}
    ).json()
    assert note["sha256"] == hashlib.sha256(b"User clicked the link at 09:12").hexdigest()

    monkeypatch.setattr(get_settings(), "evidence_max_bytes", 10)
    assert fleet.owner.post(url, json=file_body).status_code == 413

    viewer = account_factory("viewer")
    _add(fleet, viewer, "viewer")
    assert viewer.get(_org(fleet, "/evidence")).json()["total"] == 3
    assert viewer.get(_org(fleet, f"/evidence/{item['id']}/download")).status_code == 403


def test_evidence_is_immutable_in_the_database(fleet, admin_engine, postgres_only):
    inc = _incident(fleet)
    item = fleet.owner.post(
        _org(fleet, f"/incidents/{inc['id']}/evidence"),
        json={"kind": "note", "title": "Log note", "note": "original"},
    ).json()
    for statement in (
        "UPDATE evidence_blobs SET data = 'tampered'",
        "UPDATE evidence SET sha256 = repeat('0', 64)",
        "UPDATE evidence SET chain_of_custody = '[]'::jsonb",
    ):
        with pytest.raises(DBAPIError, match=r"immutable|append-only"), admin_engine.begin() as conn:
            conn.execute(
                text(statement + " WHERE " + ("evidence_id" if "blobs" in statement else "id") + " = :i"),
                {"i": item["id"]},
            )


# ---------------------------------------------------------------------------------- reports
def test_incident_and_executive_reports(fleet, account_factory):
    alerts = _alerts(fleet, "Credential stuffing on VPN", severity="critical")
    inc = _incident(fleet, [alerts[0]["id"]])
    fleet.owner.post(
        _org(fleet, f"/incidents/{inc['id']}/evidence"),
        json={"kind": "note", "title": "VPN log", "note": "x"},
    )
    _propose(fleet.owner, fleet, "notify_team", {"message": "VPN under attack"}, incident_id=inc["id"])

    report = fleet.owner.post(
        _org(fleet, "/reports"), json={"report_type": "incident", "incident_id": inc["id"]}
    ).json()
    md = report["markdown"]
    assert (
        inc["reference"] in report["title"]
        and "Credential stuffing on VPN" in md
        and "Notify responders" in md
    )
    assert (
        hashlib.sha256(b"x").hexdigest() in md
        and "no AI-written text" in md
        and report["is_ai_generated"] is False
    )

    exec_report = fleet.owner.post(
        _org(fleet, "/reports"), json={"report_type": "executive", "period_days": 7}
    ).json()
    m = exec_report["metrics"]
    assert m["alerts"] == 1 and m["incidents_opened"] == 1 and m["alerts_by_severity"]["critical"] == 1
    assert m["mean_time_to_acknowledge_hours"] is not None and m["actions"] == 1

    download = fleet.owner.get(_org(fleet, f"/reports/{exec_report['id']}/download"))
    assert (
        download.headers["content-type"].startswith("text/markdown")
        and "Executive security summary" in download.text
    )
    assert fleet.owner.post(_org(fleet, "/reports"), json={"report_type": "incident"}).status_code == 422

    viewer = account_factory("viewer")
    _add(fleet, viewer, "viewer")
    assert viewer.get(_org(fleet, "/reports")).json()["total"] == 2
    assert viewer.post(_org(fleet, "/reports"), json={"report_type": "executive"}).status_code == 403


# --------------------------------------------------------------------------- isolation & brain
def test_soc_is_tenant_isolated(fleet, account_factory):
    inc = _incident(fleet)
    action = _propose(
        fleet.owner, fleet, "notify_team", {"message": "hello team"}, incident_id=inc["id"]
    ).json()
    item = fleet.owner.post(
        _org(fleet, f"/incidents/{inc['id']}/evidence"),
        json={"kind": "note", "title": "Log note", "note": "n"},
    ).json()
    report = fleet.owner.post(
        _org(fleet, "/reports"), json={"report_type": "incident", "incident_id": inc["id"]}
    ).json()

    outsider = account_factory("outsider")
    other = outsider.create_org("Other Org")["organization"]["id"]
    base = f"/api/v1/organizations/{other}"
    assert outsider.get(f"{base}/incidents/{inc['id']}").status_code == 404
    assert outsider.post(f"{base}/actions/{action['id']}/rollback").status_code == 404
    assert outsider.get(f"{base}/evidence/{item['id']}/download").status_code == 404
    assert outsider.get(f"{base}/reports/{report['id']}").status_code == 404
    assert (
        outsider.post(
            f"{base}/incidents/{inc['id']}/evidence", json={"kind": "note", "title": "Log note", "note": "n"}
        ).status_code
        == 404
    )
    assert outsider.get(f"{base}/evidence").json()["total"] == 0
    assert outsider.get(_org(fleet, "/incidents")).status_code == 404


def test_brain_recommendations_become_one_click_proposals(fleet):
    token = fleet.enroll("ws-07")["device_token"]
    fleet.owner.post(
        _org(fleet, "/indicators"), json={"indicator_type": "ipv4", "value": C2, "verdict": "malicious"}
    )
    event = {
        "event_type": "network.c2_connection",
        "category": "network",
        "severity": "critical",
        "title": "Outbound connection to a known C2 server",
        "raw": {"destination_ip": C2},
    }
    fleet.device_post(token, "/events", {"events": [event]})
    run = fleet.owner.get(_org(fleet, "/brain/runs")).json()["items"][0]
    detail = fleet.owner.get(_org(fleet, f"/brain/runs/{run['id']}")).json()
    proposal = next(r["proposal"] for r in detail["recommendations"] if r["code"] == "intel.malicious_match")
    assert proposal == {"action_type": "block_indicator", "target": {"indicator_type": "ipv4", "value": C2}}
    action = _propose(
        fleet.owner, fleet, proposal["action_type"], proposal["target"], agent_run_id=run["id"]
    ).json()
    assert action["proposed_by_run_id"] == run["id"] and action["status"] == "pending_approval"
