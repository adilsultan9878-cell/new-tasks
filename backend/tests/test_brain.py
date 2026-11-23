"""Security Brain (Phase 4): deterministic agents, read-only tools, scoring and API."""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest

from app.brain import agents as brain_agents
from app.brain.scoring import MODELS, FactorResult, compute, level_for
from app.brain.toolbox import TOOLS, ReadOnlyViolation, Toolbox, tool
from app.core.config import get_settings
from tests.conftest import Fleet

BRAIN = Path(__file__).resolve().parents[1] / "app" / "brain"
C2 = "203.0.113.66"


def _org(fleet: Fleet, path: str = "") -> str:
    return f"/api/v1/organizations/{fleet.org_id}{path}"


def _compromised_device(fleet: Fleet) -> str:
    """A degraded device with a backdoor port that talks to a watch-listed C2 address."""
    token = fleet.enroll("ws-07")["device_token"]
    hb = {
        "agent_version": "0.2.0",
        "ip_address": "10.0.0.5",
        "telemetry": {
            "cpu_percent": 97,
            "memory_percent": 96,
            "disk_percent": 97,
            "listening_ports": [3389, 4444],
        },
    }
    assert fleet.device_post(token, "/heartbeat", hb).status_code == 200
    added = fleet.owner.post(
        _org(fleet, "/indicators"), json={"indicator_type": "ipv4", "value": C2, "verdict": "malicious"}
    )
    assert added.status_code == 201
    event = {
        "event_type": "network.c2_connection",
        "category": "network",
        "severity": "critical",
        "title": "Outbound connection to a known C2 server",
        "raw": {"source_ip": "10.0.0.5", "destination_ip": C2},
    }
    assert fleet.device_post(token, "/events", {"events": [event]}).json()["accepted"] == 1
    return token


# ------------------------------------------------------------------------------- engine
def test_status_describes_a_deterministic_engine(account_factory):
    user = account_factory()
    body = user.get("/api/v1/brain/status").json()
    assert body["engine"]["provider"] == "none" and body["engine"]["ai_enabled"] is False
    assert body["engine"]["model"] is None and body["auto_triage"] is True
    assert {a["name"] for a in body["agents"]} == {"triage", "device", "exposure", "intel", "posture"}
    tools = {t["name"] for t in body["tools"]}
    assert all(set(a["tools"]) <= tools for a in body["agents"])
    for subject, factors in body["models"].items():
        assert sum(f["max_points"] for f in factors) == 100, subject


def test_scoring_levels_coverage_and_clamping():
    assert [level_for(s) for s in (0, 9, 10, 25, 50, 75, 100)] == [
        "info",
        "info",
        "low",
        "medium",
        "high",
        "critical",
        "critical",
    ]
    result = compute(
        "alert",
        {
            "alert_severity": FactorResult(999, "clamped to the factor maximum"),
            "corroboration": FactorResult(-5, "never negative"),
            "asset_condition": FactorResult(10, "ignored: no data", has_data=False),
        },
    )
    by_key = {f["key"]: f for f in result.factors}
    assert by_key["alert_severity"]["points"] == 50 and by_key["corroboration"]["points"] == 0
    assert by_key["asset_condition"]["points"] == 0 and by_key["exposure"]["has_data"] is False
    assert result.score == 50 and result.level == "high" and result.priority == "P2"
    assert result.coverage == 65  # severity 50 + corroboration 15 had data
    assert all(sum(f.weight for f in model) == 100 for model in MODELS.values())


def test_agent_risky_service_list_matches_network_monitor():
    from app.services.network import RISKY_SERVICES

    assert brain_agents.RISKY_SERVICES == RISKY_SERVICES


# --------------------------------------------------------------------------- read-only
FORBIDDEN_IMPORTS = {
    "subprocess",
    "os",
    "socket",
    "shutil",
    "httpx",
    "requests",
    "urllib",
    "app.intel.client",
}
FORBIDDEN_METHODS = {
    "add",
    "add_all",
    "delete",
    "merge",
    "commit",
    "flush",
    "bulk_save_objects",
    "bulk_insert_mappings",
}
FORBIDDEN_SQL = {"insert", "update", "delete", "text"}


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names |= {f"{node.module}.{a.name}" for a in node.names}
    return names


@pytest.mark.parametrize("module", ["toolbox.py", "agents.py"])
def test_agents_and_tools_cannot_write_or_reach_out(module):
    tree = ast.parse((BRAIN / module).read_text())
    imports = _imports(tree)
    assert not {i for i in imports if i.split(".")[0] in FORBIDDEN_IMPORTS or i in FORBIDDEN_IMPORTS}
    assert not {i for i in imports if i.startswith("sqlalchemy.") and i.rsplit(".", 1)[1] in FORBIDDEN_SQL}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in FORBIDDEN_METHODS, (
                f"{module}:{node.lineno} calls .{node.func.attr}()"
            )
            if node.func.attr == "execute":  # only SELECT statements may be executed
                arg = node.args[0]
                while isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                    arg = arg.func.value  # unwind select(...).where(...).group_by(...)
                assert isinstance(arg, ast.Call) and getattr(arg.func, "id", None) == "select", node.lineno
    if module == "agents.py":  # agents only see data through the toolbox
        assert not {
            i for i in imports if i.startswith(("sqlalchemy", "app.models", "app.db", "app.services"))
        }


def test_toolbox_aborts_a_tool_that_leaves_pending_writes():
    from app.db.session import get_sessionmaker
    from app.models import Device

    class Rogue(Toolbox):
        @tool("test.rogue", "writes — must be rejected")
        def rogue(self) -> None:
            self.db.add(Device(id=uuid.uuid4(), organization_id=self.org_id, name="x", device_type="other"))

    try:
        with get_sessionmaker()() as db:
            with pytest.raises(ReadOnlyViolation):
                Rogue(db, uuid.uuid4()).rogue()
            db.rollback()
    finally:
        TOOLS.pop("test.rogue", None)


# ------------------------------------------------------------------------------- end-to-end
def test_new_alert_is_triaged_automatically(fleet):
    _compromised_device(fleet)
    alerts = fleet.owner.get(_org(fleet, "/alerts")).json()
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical"
    triage = alerts[0]["triage"]
    assert triage["priority"] == "P1" and triage["risk_level"] == "critical"

    runs = fleet.owner.get(_org(fleet, "/brain/runs"), params={"subject_type": "alert"}).json()
    assert runs["total"] == 1 and runs["items"][0]["trigger"] == "alert"
    run = fleet.owner.get(_org(fleet, f"/brain/runs/{triage['run_id']}")).json()
    factors = {f["key"]: (f["points"], f["max_points"]) for f in run["factors"]}
    assert factors == {
        "alert_severity": (50, 50),  # critical
        "corroboration": (0, 15),  # first occurrence, no other alerts
        "asset_condition": (6, 10),  # degraded 3 + health 30/100 3
        "exposure": (10, 10),  # port 4444 is a backdoor port
        "threat_intel": (15, 15),  # destination IP is on the watchlist as malicious
    }
    assert run["risk_score"] == 81 and run["coverage"] == 100 and run["model_provider"] == "none"
    assert run["agents"] == ["triage", "device", "exposure", "intel"]

    recs = {r["code"]: r for r in run["recommendations"]}
    assert C2 in recs["intel.malicious_match"]["text"] and recs["intel.malicious_match"]["changes_system"]
    assert recs["exposure.backdoor_port"]["urgency"] == "now"
    assert all(d["is_ai_generated"] is False for d in run["decisions"])
    assert {d["decision_type"] for d in run["decisions"]} == {"score", "classify", "finding", "recommend"}

    # Every tool call is traced, and each agent used only the tools it declares.
    declared = {name: set(spec.tools) for name, spec in brain_agents.AGENTS.items()}
    declared["orchestrator"] = {"alerts.get", "events.get", "devices.get"}
    assert run["trace"] and all(t["tool"] in declared[t["agent"]] for t in run["trace"])
    assert run["trace"][0]["tool"] == "alerts.get" and run["trace"][0]["args"] == {
        "alert_id": alerts[0]["id"]
    }
    assert recs["alert.detection"]["urgency"] == "now"  # open alert: confirm, then acknowledge or escalate

    audit = fleet.owner.get(_org(fleet, "/audit-logs"), params={"action": "brain.run"}).json()["items"]
    assert audit and audit[0]["actor_type"] == "system"


def test_manual_device_and_organization_analyses(fleet):
    _compromised_device(fleet)
    device = fleet.owner.get(_org(fleet, "/devices")).json()[0]
    assert device["risk_score"] is None

    resp = fleet.owner.post(
        _org(fleet, "/brain/runs"), json={"subject_type": "device", "subject_id": device["id"]}
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()
    factors = {f["key"]: f["points"] for f in run["factors"]}
    # degraded 6 + unhealthy 6 | one critical alert | one critical event | backdoor | C2 seen
    assert factors == {
        "device_state": 12,
        "open_alerts": 15,
        "event_activity": 5,
        "exposure": 20,
        "threat_intel": 15,
    }
    assert run["risk_score"] == 67 and run["risk_level"] == "high" and run["trigger"] == "manual"
    assert fleet.owner.get(_org(fleet, f"/devices/{device['id']}")).json()["risk_score"] == 67

    org_run = fleet.owner.post(_org(fleet, "/brain/runs"), json={"subject_type": "organization"}).json()
    factors = {f["key"]: f["points"] for f in org_run["factors"]}
    assert factors == {
        "open_alerts": 10,
        "stale_alerts": 0,
        "device_fleet": 20,
        "exposure": 20,
        "threat_intel": 20,
    }
    assert org_run["subject_id"] == fleet.org_id and org_run["subject_label"] == "Fleet Org"

    report = fleet.owner.get(_org(fleet, f"/brain/runs/{org_run['id']}/report"))
    assert report.status_code == 200 and report.headers["content-type"].startswith("text/markdown")
    assert "attachment" in report.headers["content-disposition"]
    assert "no AI model" in report.text and "Recommendations only" in report.text and C2 in report.text


def test_low_coverage_is_reported_not_hidden(account_factory):
    owner = account_factory()
    org = owner.create_org("Empty Org")["organization"]["id"]
    run = owner.post(f"/api/v1/organizations/{org}/brain/runs", json={"subject_type": "organization"}).json()
    assert run["risk_score"] == 0 and run["risk_level"] == "info"
    assert run["coverage"] == 40  # only the alert factors had data
    assert "No data for" in run["summary"]
    assert {r["code"] for r in run["recommendations"]} == {"posture.no_devices"}


def test_auto_triage_can_be_disabled(fleet, monkeypatch):
    monkeypatch.setattr(get_settings(), "brain_auto_triage", False)
    _compromised_device(fleet)
    assert fleet.owner.get(_org(fleet, "/alerts")).json()[0]["triage"] is None
    assert fleet.owner.get(_org(fleet, "/brain/runs")).json()["total"] == 0


def test_brain_rbac_validation_and_tenant_isolation(fleet, account_factory):
    _compromised_device(fleet)
    viewer, outsider = account_factory("viewer"), account_factory("outsider")
    fleet.owner.post(_org(fleet, "/members"), json={"email": viewer.email, "role": "viewer"})
    run_id = fleet.owner.get(_org(fleet, "/brain/runs")).json()["items"][0]["id"]

    assert viewer.get(_org(fleet, f"/brain/runs/{run_id}")).status_code == 200
    assert viewer.post(_org(fleet, "/brain/runs"), json={"subject_type": "organization"}).status_code == 403
    assert outsider.get(_org(fleet, f"/brain/runs/{run_id}")).status_code == 404
    assert outsider.get(_org(fleet, f"/brain/runs/{run_id}/report")).status_code == 404

    # The outsider's own organization cannot reach this org's alert or device.
    other = outsider.create_org("Other Org")["organization"]["id"]
    alert_id = fleet.owner.get(_org(fleet, "/alerts")).json()[0]["id"]
    device_id = fleet.owner.get(_org(fleet, "/devices")).json()[0]["id"]
    base = f"/api/v1/organizations/{other}/brain"
    assert (
        outsider.post(f"{base}/runs", json={"subject_type": "alert", "subject_id": alert_id}).status_code
        == 404
    )
    assert (
        outsider.post(f"{base}/runs", json={"subject_type": "device", "subject_id": device_id}).status_code
        == 404
    )
    assert outsider.get(f"{base}/runs/{run_id}").status_code == 404
    assert outsider.get(f"{base}/runs").json()["total"] == 0

    assert fleet.owner.post(_org(fleet, "/brain/runs"), json={"subject_type": "alert"}).status_code == 422
    assert fleet.owner.post(_org(fleet, "/brain/runs"), json={"subject_type": "user"}).status_code == 422


def test_decision_history_and_agent_activity(fleet):
    _compromised_device(fleet)
    page = fleet.owner.get(_org(fleet, "/brain/decisions"), params={"agent": "intel"}).json()
    assert page["total"] >= 2  # a finding and its recommendation
    assert all(d["agent_name"] == "intel" and d["subject_type"] == "alert" for d in page["items"])
    activity = fleet.owner.get(_org(fleet, "/brain/activity")).json()
    assert activity["runs_total"] == 1 and activity["runs_by_trigger"] == {"alert": 1}
    by_agent = {a["agent"]: a for a in activity["agents"]}
    assert set(by_agent) == set(brain_agents.AGENTS)
    assert by_agent["intel"]["findings"] == 1 and by_agent["posture"]["findings"] == 0
