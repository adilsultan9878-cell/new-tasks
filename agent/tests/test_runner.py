from sentinel_agent.client import AuthError, TransportError
from sentinel_agent.runner import Agent
from sentinel_agent.spool import Spool
from sentinel_agent.state import AgentState, load_state


class FakeClient:
    def __init__(self, fail_events: bool = False, revoked: bool = False, config_version: int = 1):
        self.sent: list[dict] = []
        self.heartbeats: list[dict] = []
        self.fail_events = fail_events
        self.revoked = revoked
        self.config_version = config_version

    def heartbeat(self, payload):
        if self.revoked:
            raise AuthError("revoked")
        self.heartbeats.append(payload)
        return {
            "status": "online",
            "config_version": self.config_version,
            "config": {
                "heartbeat_interval_seconds": 120,
                "collectors": ["system", "ports"],
                "thresholds": {"cpu_percent": 95},
                "command": "ignored",
            },
        }

    def send_events(self, events):
        if self.revoked:
            raise AuthError("revoked")
        if self.fail_events:
            raise TransportError("offline")
        self.sent.extend(events)
        return {"accepted": len(events), "rejected": []}


def _state():
    return AgentState(server_url="https://x/api/v1", device_id="dev", organization_id="org", device_token="t")


def test_single_cycle_reports_telemetry_and_applies_new_config(tmp_path):
    client = FakeClient(config_version=2)
    agent = Agent(_state(), client=client, spool=Spool(tmp_path / "spool.jsonl"))
    assert agent.run(once=True) == 0
    assert client.sent[0]["event_type"] == "agent.started"
    hb = client.heartbeats[0]
    assert hb["agent_version"] and "cpu_percent" in hb["telemetry"]
    saved = load_state()
    assert saved.config_version == 2 and saved.config["heartbeat_interval_seconds"] == 120
    assert "command" not in saved.config
    assert saved.known_ports is not None  # baseline persisted


def test_events_are_spooled_while_offline_and_flushed_later(tmp_path):
    spool = Spool(tmp_path / "spool.jsonl")
    offline = FakeClient(fail_events=True)
    Agent(_state(), client=offline, spool=spool).run(once=True)
    assert len(spool) >= 1  # agent.started kept for later
    online = FakeClient()
    Agent(_state(), client=online, spool=spool).run(once=True)
    assert len(spool) == 0
    assert [e["event_type"] for e in online.sent].count("agent.started") == 2


def test_revoked_credential_stops_the_agent(tmp_path):
    agent = Agent(_state(), client=FakeClient(revoked=True), spool=Spool(tmp_path / "s.jsonl"))
    assert agent.run(once=False) == 3
    assert "revoked" in load_state().last_error
