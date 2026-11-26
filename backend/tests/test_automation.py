"""Automation (Phase 8): workflows, approval gates, signed webhooks in and out, safety rails."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import text

from app.automation import delivery, signing, targets, worker
from app.core.config import get_settings
from tests.conftest import Fleet

HOOK_URL = "https://hooks.example.com/sentinel/abc123token"


def _org(fleet: Fleet, path: str = "") -> str:
    return f"/api/v1/organizations/{fleet.org_id}{path}"


def _auto(fleet: Fleet, path: str = "") -> str:
    return _org(fleet, f"/automation{path}")


def _add(fleet: Fleet, account, role: str) -> dict:
    resp = fleet.owner.post(_org(fleet, "/members"), json={"email": account.email, "role": role})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _event(fleet: Fleet, title: str, severity: str = "high", **extra) -> None:
    body = {
        "event_type": "policy.violation",
        "category": "policy",
        "severity": severity,
        "title": title,
        **extra,
    }
    assert fleet.owner.post(_org(fleet, "/events"), json=body).status_code == 201


class Receiver:
    """Stands in for n8n/Slack: records requests and answers with a configurable status."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.status = 200

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json={"ok": self.status < 300})

    def verify(self, request: httpx.Request, secret: str) -> bool:
        ts = request.headers["X-Sentinel-Timestamp"]
        expected = hmac.new(secret.encode(), f"{ts}.".encode() + request.content, hashlib.sha256).hexdigest()
        return request.headers["X-Sentinel-Signature"] == f"v1={expected}"


@pytest.fixture
def receiver(monkeypatch):
    rec = Receiver()
    delivery.set_transport(httpx.MockTransport(rec.handler))
    monkeypatch.setattr(targets, "resolver", lambda host, port: ["93.184.216.34"])  # a public address
    yield rec
    delivery.set_transport(None)


def _webhook(fleet: Fleet, name: str = "n8n", url: str = HOOK_URL) -> tuple[dict, str]:
    resp = fleet.owner.post(_auto(fleet, "/webhooks"), json={"name": name, "url": url, "provider": "n8n"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["secret"].startswith("whsec_")
    return body["webhook"], body["secret"]


def _workflow(account, fleet: Fleet, **body) -> dict:
    payload = {"name": "Workflow", "enabled": True, "requires_approval": False, **body}
    resp = account.post(_auto(fleet, "/workflows"), json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _runs(fleet: Fleet, **params) -> list[dict]:
    return fleet.owner.get(_auto(fleet, "/runs"), params=params).json()["items"]


def _signed_post(
    client, path: str, secret: str, body: dict | bytes, ts: int | None = None, sig: str | None = None
):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    ts = ts if ts is not None else int(time.time())
    headers = {"Content-Type": "application/json", "X-Sentinel-Timestamp": str(ts)}
    headers["X-Sentinel-Signature"] = sig if sig is not None else signing.sign(secret, ts, raw)
    return client.post(path, content=raw, headers=headers)


# ------------------------------------------------------------------------------ primitives
def test_signatures_are_derived_rotatable_and_time_bound():
    import uuid

    oid = uuid.uuid4()
    s1, s1_again, s2 = (
        signing.derive_secret("webhook", oid, 1),
        signing.derive_secret("webhook", oid, 1),
        signing.derive_secret("webhook", oid, 2),
    )
    assert s1 == s1_again and s1 != s2 and s1 != signing.derive_secret("workflow", oid, 1)
    body, now = b'{"a":1}', time.time()
    headers = signing.signed_headers(s1, body, now)
    ok = signing.verify(s1, headers["X-Sentinel-Timestamp"], headers["X-Sentinel-Signature"], body, now)
    assert ok is None
    assert signing.verify(s2, headers["X-Sentinel-Timestamp"], headers["X-Sentinel-Signature"], body, now)
    assert signing.verify(s1, headers["X-Sentinel-Timestamp"], headers["X-Sentinel-Signature"], b"{}", now)
    late = now + get_settings().signature_tolerance_seconds + 5
    assert "window" in signing.verify(
        s1, headers["X-Sentinel-Timestamp"], headers["X-Sentinel-Signature"], body, late
    )
    # Several signatures (old and new secret during a rotation) are accepted.
    both = f"{signing.sign(s2, int(now), body)} {headers['X-Sentinel-Signature']}"
    assert signing.verify(s1, headers["X-Sentinel-Timestamp"], both, body, now) is None
    assert signing.key_source() == "jwt"  # tests set JWT_SECRET, no dedicated key


def test_targets_refuse_internal_addresses_and_plain_http(monkeypatch):
    monkeypatch.setattr(targets, "resolver", lambda host, port: ["10.0.0.8"])
    for url, fragment in [
        ("http://hooks.example.com/x", "https"),
        ("https://user:pw@hooks.example.com/x", "password"),
        ("https://127.0.0.1/x", "loopback"),
        ("https://169.254.169.254/latest/meta-data", "link-local"),
        ("https://localhost/x", "Internal"),
        ("https://hooks.example.com/x", "private"),  # DNS answer is private
        ("ftp://hooks.example.com/x", "https"),
    ]:
        with pytest.raises(targets.TargetRefused, match=fragment):
            targets.check(url)
    monkeypatch.setattr(get_settings(), "automation_allow_private_targets", True)
    assert targets.check("http://n8n:5678/webhook/x") == ["10.0.0.8"]  # local n8n allowed when opted in


# ------------------------------------------------------------------------- event workflows
def test_alert_workflow_notifies_and_sends_a_signed_minimal_webhook(fleet, account_factory, receiver):
    analyst = account_factory("analyst")
    _add(fleet, analyst, "analyst")
    hook, secret = _webhook(fleet)
    wf = _workflow(
        fleet.owner,
        fleet,
        name="Serious alerts to n8n",
        trigger_type="event",
        trigger_config={"event": "alert.created", "min_severity": "high"},
        steps=[
            {
                "type": "notify",
                "audience": "responders",
                "message": "{{alert.severity}}: {{alert.title}} {{nope}}",
            },
            {"type": "send_webhook", "webhook_id": hook["id"]},
        ],
    )
    assert wf["trigger_label"] == "A new alert is raised (high or above)" and wf["requires_approval"] is False
    assert [s["title"] for s in wf["steps"]] == ["Notify responders", "Send to n8n"]

    _event(fleet, "Low noise", severity="medium")  # below the threshold: no alert, no run
    _event(fleet, "Ransomware note found", severity="critical", raw={"password": "hunter2"})
    runs = _runs(fleet)
    assert len(runs) == 1 and runs[0]["status"] == "succeeded", runs
    assert [s["status"] for s in runs[0]["steps"]] == ["succeeded", "succeeded"]
    notes = analyst.get("/api/v1/notifications").json()
    items = notes["items"] if isinstance(notes, dict) else notes
    assert any(n["title"] == "critical: Ransomware note found" for n in items)

    assert receiver.requests == []  # nothing is sent inside the request transaction
    assert worker.tick()["delivered"] == 1
    (req,) = receiver.requests
    assert receiver.verify(req, secret)
    payload = json.loads(req.content)
    assert (
        req.headers["X-Sentinel-Delivery"] == payload["id"]
        and req.headers["X-Sentinel-Event"] == "alert.created"
    )
    assert payload["data"]["alert"]["title"] == "Ransomware note found" and payload["simulated"] is False
    assert "hunter2" not in req.content.decode()  # raw event data never leaves the platform
    hooks = fleet.owner.get(_auto(fleet, "/webhooks")).json()
    assert hooks[0]["last_success_at"] and hooks[0]["failure_count"] == 0 and hooks[0]["used_by"] == 1
    assert worker.tick()["delivered"] == 0  # delivered exactly once


def test_simulated_alerts_are_ignored_unless_opted_in(fleet, receiver):
    _workflow(
        fleet.owner,
        fleet,
        trigger_type="event",
        trigger_config={"event": "alert.created", "min_severity": "low"},
        steps=[{"type": "notify", "audience": "responders", "message": "{{alert.title}}"}],
    )
    assert fleet.owner.post(_org(fleet, "/simulator/run")).status_code == 201
    assert _runs(fleet) == []
    fleet.owner.delete(_org(fleet, "/simulator"))
    _workflow(
        fleet.owner,
        fleet,
        name="Demo notifier",
        trigger_type="event",
        trigger_config={"event": "alert.created", "min_severity": "low", "include_simulated": True},
        steps=[{"type": "notify", "audience": "responders", "message": "{{alert.title}}"}],
    )
    fleet.owner.post(_org(fleet, "/simulator/run"))
    runs = _runs(fleet)
    assert runs and all(r["is_simulated"] and r["workflow_name"] == "Demo notifier" for r in runs)
    cleared = fleet.owner.delete(_org(fleet, "/simulator")).json()
    assert cleared["automation_runs"] == len(runs) and _runs(fleet) == []


def test_medium_steps_always_wait_for_an_approver(fleet, account_factory):
    viewer = account_factory("viewer")
    _add(fleet, viewer, "viewer")
    wf = _workflow(
        fleet.owner,
        fleet,
        name="Incident for critical alerts",
        trigger_type="event",
        trigger_config={"event": "alert.created", "min_severity": "critical"},
        steps=[{"type": "create_incident", "title": "Auto: {{alert.title}}"}],
        requires_approval=False,  # asked for no approval, but the step is medium risk
    )
    assert wf["requires_approval"] is True and wf["approval_forced"] is True
    _event(fleet, "Domain admin created", severity="critical")
    (run,) = _runs(fleet)
    assert run["status"] == "awaiting_approval" and run["steps"][0]["status"] == "waiting"
    assert fleet.owner.get(_org(fleet, "/incidents")).json()["total"] == 0  # nothing happened yet
    assert viewer.post(_auto(fleet, f"/runs/{run['id']}/decision"), json={"approve": True}).status_code == 403

    decided = fleet.owner.post(_auto(fleet, f"/runs/{run['id']}/decision"), json={"approve": True}).json()
    assert decided["status"] == "succeeded" and decided["decided_by_name"]
    step = decided["steps"][0]
    assert step["detail"].startswith("Opened INC-") and step["link"].startswith("/incidents/")
    incidents = fleet.owner.get(_org(fleet, "/incidents")).json()["items"]
    assert incidents[0]["title"] == "Auto: Domain admin created" and incidents[0]["alert_count"] == 1
    again = fleet.owner.post(_auto(fleet, f"/runs/{run['id']}/decision"), json={"approve": True})
    assert again.status_code == 409


def test_manual_run_needs_a_second_person_unless_sole_approver(fleet, account_factory):
    admin = account_factory("admin")
    _add(fleet, admin, "admin")
    wf = _workflow(
        admin,
        fleet,
        trigger_type="manual",
        steps=[{"type": "notify", "audience": "approvers", "message": "Weekly check"}],
        requires_approval=True,
    )
    run = admin.post(_auto(fleet, f"/workflows/{wf['id']}/run")).json()
    assert run["status"] == "awaiting_approval" and run["requested_by_name"]
    refused = admin.post(_auto(fleet, f"/runs/{run['id']}/decision"), json={"approve": True})
    assert refused.status_code == 403 and refused.json()["error"]["code"] == "separation_of_duties"
    rejected = fleet.owner.post(
        _auto(fleet, f"/runs/{run['id']}/decision"), json={"approve": False, "comment": "Not now"}
    )
    assert rejected.json()["status"] == "rejected" and rejected.json()["steps"][0]["status"] == "skipped"


def test_sole_approver_self_approval_is_recorded(fleet):
    wf = _workflow(
        fleet.owner,
        fleet,
        trigger_type="manual",
        steps=[{"type": "notify", "audience": "approvers", "message": "Check"}],
        requires_approval=True,
    )
    run = fleet.owner.post(_auto(fleet, f"/workflows/{wf['id']}/run")).json()
    done = fleet.owner.post(_auto(fleet, f"/runs/{run['id']}/decision"), json={"approve": True}).json()
    assert done["status"] == "succeeded" and "self-approved" in done["decision_comment"]


def test_pending_runs_expire(fleet, admin_engine):
    wf = _workflow(
        fleet.owner,
        fleet,
        trigger_type="manual",
        steps=[{"type": "notify", "audience": "approvers", "message": "Check"}],
        requires_approval=True,
    )
    run = fleet.owner.post(_auto(fleet, f"/workflows/{wf['id']}/run")).json()
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE automation_runs SET expires_at = :t"),
            {"t": datetime.now(UTC) - timedelta(minutes=1)},
        )
    assert _runs(fleet)[0]["status"] == "expired"
    assert (
        fleet.owner.post(_auto(fleet, f"/runs/{run['id']}/decision"), json={"approve": True}).status_code
        == 409
    )


# --------------------------------------------------------------------------- incoming hooks
def test_incoming_hook_is_signed_replay_safe_and_only_proposes(fleet):
    created = fleet.owner.post(
        _auto(fleet, "/workflows"),
        json={
            "name": "Block what n8n reports",
            "trigger_type": "webhook",
            "enabled": True,
            "requires_approval": False,
            "steps": [
                {
                    "type": "propose_response",
                    "action_type": "block_indicator",
                    "indicator_type": "ipv4",
                    "value": "{{payload.value}}",
                }
            ],
        },
    )
    assert created.status_code == 201, created.text
    secret, path = created.json()["secret"], created.json()["hook_path"]
    client = fleet.agent  # an unauthenticated client
    body = {"value": "203.0.113.66", "reason": "seen in phishing kit"}

    assert client.post(path, json=body).status_code == 401  # unsigned
    assert _signed_post(client, path, "whsec_wrong", body).status_code == 401
    old = int(time.time()) - get_settings().signature_tolerance_seconds - 60
    assert _signed_post(client, path, secret, body, ts=old).status_code == 401

    ts = int(time.time())
    ok = _signed_post(client, path, secret, body, ts=ts)
    assert ok.status_code == 202 and ok.json()["status"] == "succeeded", ok.text
    assert _signed_post(client, path, secret, body, ts=ts).status_code == 409  # replay

    actions = fleet.owner.get(_org(fleet, "/actions")).json()["items"]
    assert len(actions) == 1 and actions[0]["status"] == "pending_approval"  # nothing blocked yet
    assert actions[0]["target"] == {"indicator_type": "ipv4", "value": "203.0.113.66"}
    assert "Block what n8n reports" in actions[0]["reason"]
    assert (
        fleet.owner.get(_org(fleet, "/blocklist")).text.strip() == ""
        or "203.0.113.66" not in fleet.owner.get(_org(fleet, "/blocklist")).text
    )

    assert _signed_post(client, path, secret, b"[1, 2]").status_code == 422
    assert (
        _signed_post(client, path, secret, b"x" * (get_settings().inbound_hook_max_bytes + 1)).status_code
        == 413
    )
    other = f"/api/v1/hooks/{fleet.org_id}/00000000-0000-0000-0000-000000000000"
    assert _signed_post(client, other, secret, body).status_code == 404

    rotated = fleet.owner.post(
        _auto(fleet, f"/workflows/{created.json()['workflow']['id']}/rotate-secret")
    ).json()
    assert rotated["secret"] != secret
    assert _signed_post(client, path, secret, {"value": "203.0.113.67"}).status_code == 401
    assert _signed_post(client, path, rotated["secret"], {"value": "203.0.113.67"}).status_code == 202

    fleet.owner.patch(_auto(fleet, f"/workflows/{created.json()['workflow']['id']}"), json={"enabled": False})
    assert _signed_post(client, path, rotated["secret"], {"value": "203.0.113.68"}).status_code == 409


def test_imported_events_raise_alerts_but_never_start_more_automation(fleet):
    _workflow(
        fleet.owner,
        fleet,
        name="Alert notifier",
        trigger_type="event",
        trigger_config={"event": "alert.created", "min_severity": "low"},
        steps=[{"type": "notify", "audience": "responders", "message": "{{alert.title}}"}],
    )
    created = fleet.owner.post(
        _auto(fleet, "/workflows"),
        json={
            "name": "Import",
            "trigger_type": "webhook",
            "enabled": True,
            "steps": [{"type": "create_event"}],
        },
    ).json()
    assert created["workflow"]["requires_approval"] is True  # default on; low steps may switch it off
    fleet.owner.patch(
        _auto(fleet, f"/workflows/{created['workflow']['id']}"), json={"requires_approval": False}
    )
    path, secret = created["hook_path"], created["secret"]
    bad = _signed_post(fleet.agent, path, secret, {"title": "", "severity": "loud"})
    assert bad.status_code == 202 and bad.json()["status"] == "failed"
    run = _signed_post(
        fleet.agent,
        path,
        secret,
        {"title": "EDR: credential dumping", "severity": "critical", "category": "malware"},
    ).json()
    assert run["status"] == "succeeded"
    alerts = fleet.owner.get(_org(fleet, "/alerts")).json()
    assert [a["title"] for a in alerts] == ["EDR: credential dumping"]
    assert {r["workflow_name"] for r in _runs(fleet)} == {"Import"}  # the alert notifier did not run


# ------------------------------------------------------------------------------ safety rails
def test_emergency_stop_pauses_runs_approvals_and_deliveries(fleet, receiver):
    hook, _ = _webhook(fleet)
    _workflow(
        fleet.owner,
        fleet,
        trigger_type="event",
        trigger_config={"event": "alert.created", "min_severity": "high"},
        steps=[{"type": "send_webhook", "webhook_id": hook["id"]}],
    )
    manual = _workflow(
        fleet.owner,
        fleet,
        trigger_type="manual",
        steps=[{"type": "notify", "audience": "approvers", "message": "x"}],
        requires_approval=True,
    )
    _event(fleet, "Before the stop")
    pending = fleet.owner.post(_auto(fleet, f"/workflows/{manual['id']}/run")).json()
    assert (
        fleet.owner.post(
            _org(fleet, "/response/emergency-stop"), json={"engaged": True, "reason": "drill"}
        ).status_code
        == 200
    )
    assert worker.tick()["delivered"] == 0 and receiver.requests == []  # held
    _event(fleet, "During the stop")
    assert _runs(fleet)[0]["status"] == "skipped"
    refused = fleet.owner.post(_auto(fleet, f"/runs/{pending['id']}/decision"), json={"approve": True})
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "emergency_stop"
    assert fleet.owner.get(_auto(fleet, "/overview")).json()["emergency_stop"] is True
    fleet.owner.post(_org(fleet, "/response/emergency-stop"), json={"engaged": False})
    assert worker.tick()["delivered"] == 1


def test_removed_owner_stops_permissioned_steps(fleet, account_factory):
    admin = account_factory("admin")
    member = _add(fleet, admin, "admin")
    created = admin.post(
        _auto(fleet, "/workflows"),
        json={
            "name": "Import",
            "trigger_type": "webhook",
            "enabled": True,
            "requires_approval": False,
            "steps": [{"type": "create_event"}],
        },
    ).json()
    assert fleet.owner.delete(_org(fleet, f"/members/{member['id']}")).status_code == 204
    run = _signed_post(
        fleet.agent, created["hook_path"], created["secret"], {"title": "x", "severity": "low"}
    ).json()
    detail = _runs(fleet)[0]["steps"][0]["detail"]
    assert run["status"] == "failed" and "no longer an active member" in detail
    # Saving the workflow transfers ownership; then it runs again.
    fleet.owner.patch(_auto(fleet, f"/workflows/{created['workflow']['id']}"), json={"name": "Import events"})
    again = _signed_post(
        fleet.agent, created["hook_path"], created["secret"], {"title": "y", "severity": "low"}
    )
    assert again.json()["status"] == "succeeded"


def test_definitions_are_validated_against_the_allow_list(fleet, account_factory):
    other = Fleet(account_factory("other"), "Other Org")
    foreign_hook = other.owner.post(
        f"/api/v1/organizations/{other.org_id}/automation/webhooks",
        json={"name": "theirs", "url": "https://93.184.216.34/x"},
    ).json()["webhook"]
    cases = [
        ({"trigger_type": "manual", "steps": [{"type": "run_shell", "cmd": "rm -rf /"}]}, "allow-list"),
        ({"trigger_type": "manual", "steps": []}, None),
        (
            {
                "trigger_type": "event",
                "trigger_config": {"event": "alert.created"},
                "steps": [{"type": "create_event"}],
            },
            "trigger",
        ),
        (
            {
                "trigger_type": "event",
                "trigger_config": {"event": "alert.created"},
                "steps": [
                    {
                        "type": "propose_response",
                        "action_type": "block_indicator",
                        "indicator_type": "ipv4",
                        "value": "1.2.3.4",
                    }
                ],
            },
            "webhook or a manual run",
        ),
        (
            {
                "trigger_type": "webhook",
                "steps": [{"type": "propose_response", "action_type": "revoke_device"}],
            },
            "only propose",
        ),
        (
            {"trigger_type": "manual", "steps": [{"type": "send_webhook", "webhook_id": foreign_hook["id"]}]},
            "webhook",
        ),
        (
            {
                "trigger_type": "schedule",
                "trigger_config": {"every_minutes": 1},
                "steps": [{"type": "notify", "message": "x"}],
            },
            "schedule",
        ),
        (
            {
                "trigger_type": "event",
                "trigger_config": {"event": "file.deleted"},
                "steps": [{"type": "notify", "message": "x"}],
            },
            "start",
        ),
        ({"trigger_type": "manual", "steps": [{"type": "notify", "message": "x"}] * 11}, None),
    ]
    for body, fragment in cases:
        resp = fleet.owner.post(_auto(fleet, "/workflows"), json={"name": "Bad workflow", **body})
        assert resp.status_code == 422, (body, resp.text)
        if fragment:
            assert fragment in resp.json()["error"]["message"], resp.text


def test_schedules_run_once_per_slot_with_real_counts(fleet, receiver, admin_engine):
    hook, _ = _webhook(fleet)
    wf = _workflow(
        fleet.owner,
        fleet,
        name="Daily summary",
        trigger_type="schedule",
        trigger_config={"every_minutes": 1440},
        steps=[{"type": "send_webhook", "webhook_id": hook["id"]}],
    )
    assert wf["next_run_at"] and wf["trigger_label"] == "Every day"
    _event(fleet, "Real alert")
    fleet.owner.post(_org(fleet, "/simulator/run"))
    assert worker.tick()["scheduled"] == 0  # not due yet
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE automation_workflows SET next_run_at = :t"),
            {"t": datetime.now(UTC) - timedelta(minutes=1)},
        )
    totals = worker.tick()
    assert totals["scheduled"] == 1 and totals["delivered"] == 1
    assert worker.tick()["scheduled"] == 0
    summary = json.loads(receiver.requests[0].content)["data"]["summary"]
    assert summary["open_alerts"]["high"] == 1 and summary["simulated_data_excluded"] is True
    nxt = datetime.fromisoformat(
        fleet.owner.get(_auto(fleet, f"/workflows/{wf['id']}")).json()["next_run_at"]
    )
    assert nxt.replace(tzinfo=nxt.tzinfo or UTC) > datetime.now(UTC) + timedelta(hours=23)


# ------------------------------------------------------------------------------- deliveries
def test_deliveries_retry_transient_errors_and_give_up(fleet, receiver, monkeypatch):
    hook, _ = _webhook(fleet)
    receiver.status = 503
    test = fleet.owner.post(_auto(fleet, f"/webhooks/{hook['id']}/test")).json()
    assert test["status"] == "pending" and test["attempts"] == 1 and test["last_status_code"] == 503
    assert test["next_attempt_at"]
    monkeypatch.setattr(get_settings(), "webhook_max_attempts", 2)
    retried = fleet.owner.post(_auto(fleet, f"/deliveries/{test['id']}/retry")).json()
    assert retried["status"] == "failed" and retried["attempts"] == 2
    assert fleet.owner.get(_auto(fleet, "/webhooks")).json()[0]["failure_count"] == 2

    receiver.status = 404  # not retried
    assert fleet.owner.post(_auto(fleet, f"/webhooks/{hook['id']}/test")).json()["status"] == "failed"
    receiver.status = 302
    redirect = fleet.owner.post(_auto(fleet, f"/webhooks/{hook['id']}/test")).json()
    assert redirect["status"] == "failed" and "redirect" in redirect["last_error"]
    receiver.status = 200
    ok = fleet.owner.post(_auto(fleet, f"/webhooks/{hook['id']}/test")).json()
    assert ok["status"] == "delivered" and ok["response_ms"] is not None
    assert fleet.owner.get(_auto(fleet, "/webhooks")).json()[0]["failure_count"] == 0

    # DNS now points at an internal address: refused before any request is made.
    monkeypatch.setattr(targets, "resolver", lambda host, port: ["192.168.1.10"])
    sent = len(receiver.requests)
    refused = fleet.owner.post(_auto(fleet, f"/webhooks/{hook['id']}/test")).json()
    assert (
        refused["status"] == "failed"
        and "private" in refused["last_error"]
        and len(receiver.requests) == sent
    )
    deliveries = fleet.owner.get(_auto(fleet, "/deliveries"), params={"webhook_id": hook["id"]}).json()
    assert deliveries["total"] == 5


def test_webhook_management_permissions_and_masking(fleet, account_factory, receiver):
    viewer = account_factory("viewer")
    _add(fleet, viewer, "viewer")
    hook, secret = _webhook(fleet)
    assert viewer.post(_auto(fleet, "/webhooks"), json={"name": "x", "url": HOOK_URL}).status_code == 403
    seen = viewer.get(_auto(fleet, "/webhooks")).json()[0]
    assert seen["url"] == "https://hooks.example.com/…" and "abc123token" not in json.dumps(seen)
    assert fleet.owner.get(_auto(fleet, "/webhooks")).json()[0]["url"] == HOOK_URL
    dup = fleet.owner.post(_auto(fleet, "/webhooks"), json={"name": "n8n", "url": HOOK_URL})
    assert dup.status_code == 409
    rotated = fleet.owner.post(_auto(fleet, f"/webhooks/{hook['id']}/rotate-secret")).json()
    assert rotated["secret"] != secret
    fleet.owner.post(_auto(fleet, f"/webhooks/{hook['id']}/test"))
    assert receiver.verify(receiver.requests[-1], rotated["secret"])
    assert not receiver.verify(receiver.requests[-1], secret)

    _workflow(
        fleet.owner, fleet, trigger_type="manual", steps=[{"type": "send_webhook", "webhook_id": hook["id"]}]
    )
    blocked = fleet.owner.delete(_auto(fleet, f"/webhooks/{hook['id']}"))
    assert blocked.status_code == 409 and "Used by 1" in blocked.json()["error"]["message"]
    audit = fleet.owner.get(_org(fleet, "/audit-logs")).json()
    actions = {e["action"] for e in (audit["items"] if isinstance(audit, dict) else audit)}
    assert {
        "automation.webhook_create",
        "automation.webhook_secret_rotate",
        "automation.workflow_create",
    } <= actions
    assert secret not in json.dumps(audit) and rotated["secret"] not in json.dumps(audit)


def test_automation_is_tenant_isolated(fleet, account_factory):
    wf = _workflow(fleet.owner, fleet, trigger_type="manual", steps=[{"type": "notify", "message": "hi"}])
    other = Fleet(account_factory("other"), "Other Org")
    base = f"/api/v1/organizations/{other.org_id}/automation"
    assert other.owner.get(f"{base}/workflows").json() == []
    assert other.owner.get(f"{base}/workflows/{wf['id']}").status_code == 404
    assert other.owner.post(f"{base}/workflows/{wf['id']}/run").status_code == 404
    assert other.owner.get(_auto(fleet, "/workflows")).status_code == 404
    overview = fleet.owner.get(_auto(fleet, "/overview")).json()
    assert overview["workflows"] == 1 and overview["signing_key"] == "jwt"
    catalog = fleet.owner.get(_auto(fleet, "/catalog")).json()
    assert {s["key"] for s in catalog["steps"]} == {
        "notify",
        "send_webhook",
        "create_incident",
        "propose_response",
        "create_event",
    }
    assert len(catalog["recipes"]) == 7


def test_switched_off_deliveries_send_nothing_even_on_test_or_retry(fleet, receiver, monkeypatch):
    hook, _ = _webhook(fleet)
    monkeypatch.setattr(get_settings(), "automation_delivery_enabled", False)
    test = fleet.owner.post(_auto(fleet, f"/webhooks/{hook['id']}/test")).json()
    assert test["status"] == "pending" and test["attempts"] == 0 and "switched off" in test["last_error"]
    retry = fleet.owner.post(_auto(fleet, f"/deliveries/{test['id']}/retry")).json()
    assert retry["status"] == "pending" and receiver.requests == []
    assert worker.tick()["delivered"] == 0 and receiver.requests == []
