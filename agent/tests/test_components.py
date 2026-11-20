import os
import stat

import pytest

from sentinel_agent.client import normalize_server_url
from sentinel_agent.collectors import collect
from sentinel_agent.detectors import Detector
from sentinel_agent.spool import Spool
from sentinel_agent.state import AgentState, load_state, save_state, state_path


def test_server_url_rules():
    assert normalize_server_url("https://api.example.com/") == "https://api.example.com/api/v1"
    assert normalize_server_url("https://api.example.com/api/v1") == "https://api.example.com/api/v1"
    assert normalize_server_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000/api/v1"
    with pytest.raises(ValueError):
        normalize_server_url("http://api.example.com")  # no plain HTTP to remote hosts
    assert normalize_server_url("http://10.0.0.5:8000", allow_http=True).startswith("http://10.0.0.5")
    with pytest.raises(ValueError):
        normalize_server_url("ftp://x")


def test_state_round_trip_and_permissions():
    state = AgentState(
        server_url="https://x/api/v1", device_id="d", organization_id="o", device_token="sxd.secret"
    )
    path = save_state(state)
    assert path == state_path()
    assert load_state().device_token == "sxd.secret"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_collectors_return_bounded_real_values():
    telemetry = collect(["system", "network", "ports"])
    assert 0 <= telemetry["cpu_percent"] <= 100
    assert 0 <= telemetry["disk_percent"] <= 100
    assert telemetry["uptime_seconds"] > 0
    assert isinstance(telemetry.get("listening_ports", []), list)
    assert collect([]) == {}
    assert "cpu_percent" not in collect(["ports"])  # disabled collectors do not run


def test_threshold_detection_with_cooldown():
    d = Detector(thresholds={"cpu_percent": 90, "memory_percent": 90, "disk_percent": 90})
    events = d.evaluate({"cpu_percent": 97.0, "memory_percent": 20, "disk_percent": 98}, now=1000)
    assert {e["event_type"] for e in events} == {"system.high_cpu", "system.disk_almost_full"}
    assert next(e for e in events if e["event_type"] == "system.disk_almost_full")["severity"] == "high"
    assert d.evaluate({"cpu_percent": 99.0}, now=1100) == []  # cooling down
    assert len(d.evaluate({"cpu_percent": 99.0}, now=1000 + 901)) == 1


def test_new_listening_port_detection_uses_a_baseline():
    d = Detector(thresholds={})
    assert d.evaluate({"listening_ports": [22, 443]}) == []  # baseline
    events = d.evaluate({"listening_ports": [22, 443, 8080, 4444]})
    by_port = {e["raw"]["port"]: e for e in events}
    assert set(by_port) == {8080, 4444}
    assert by_port[4444]["severity"] == "high" and by_port[8080]["severity"] == "medium"
    assert d.evaluate({"listening_ports": [22, 443, 8080, 4444]}) == []


def test_spool_is_bounded_and_tolerates_corruption(tmp_path):
    spool = Spool(tmp_path / "s.jsonl", max_events=3)
    assert spool.push([{"n": i} for i in range(5)]) == 2
    assert [e["n"] for e in spool.load()] == [2, 3, 4]
    with spool.path.open("a", encoding="utf-8") as fh:
        fh.write("{torn line\n")
    assert len(spool.load()) == 3
    spool.clear()
    assert spool.load() == []
