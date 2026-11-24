"""The real local agent, talking HTTP to a real uvicorn server running this API."""

import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from app.main import app

AGENT_DIR = Path(__file__).resolve().parents[2] / "agent"
pytest.importorskip("psutil")
sys.path.insert(0, str(AGENT_DIR))

from sentinel_agent import __version__ as AGENT_VERSION  # noqa: E402
from sentinel_agent import cli  # noqa: E402
from sentinel_agent.state import load_state  # noqa: E402


@pytest.fixture
def live_server(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_AGENT_HOME", str(tmp_path / "agent-home"))
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(var, ",".join(filter(None, [os.environ.get(var), "127.0.0.1", "localhost"])))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def test_agent_enroll_run_rotate_unenroll(live_server, fleet, capsys):
    org = f"/api/v1/organizations/{fleet.org_id}"
    token = fleet.token(label="Integration")["token"]

    assert cli.main(["enroll", "--server", live_server, "--token", token, "--name", "it-laptop"]) == 0
    state = load_state()
    assert state is not None and state.device_token.startswith("sxd.")

    assert cli.main(["run", "--once"]) == 0
    devices = fleet.owner.get(f"{org}/devices").json()
    assert [(d["name"], d["status"] in ("online", "degraded")) for d in devices] == [("it-laptop", True)]
    detail = fleet.owner.get(f"{org}/devices/{devices[0]['id']}").json()
    assert 0 <= detail["telemetry"]["cpu_percent"] <= 100
    assert detail["health_score"] is not None and detail["agent_version"] == AGENT_VERSION
    types = {e["event_type"] for e in fleet.owner.get(f"{org}/events").json()["items"]}
    assert {"agent.enrolled", "agent.started"} <= types

    # Config pushed from the console reaches the agent on its next heartbeat.
    fleet.owner.patch(
        f"{org}/devices/{devices[0]['id']}", json={"config": {"heartbeat_interval_seconds": 30}}
    )
    assert cli.main(["run", "--once"]) == 0
    assert load_state().config["heartbeat_interval_seconds"] == 30

    assert cli.main(["rotate-credentials"]) == 0
    assert load_state().device_token != state.device_token
    assert cli.main(["run", "--once"]) == 0

    assert cli.main(["unenroll", "--purge"]) == 0
    assert load_state() is None
    final = fleet.owner.get(f"{org}/devices", params={"include_decommissioned": True}).json()[0]
    assert final["enrollment_status"] == "revoked"


def test_agent_stops_when_device_is_revoked(live_server, fleet):
    org = f"/api/v1/organizations/{fleet.org_id}"
    assert cli.main(["enroll", "--server", live_server, "--token", fleet.token()["token"]]) == 0
    device_id = load_state().device_id
    fleet.owner.post(f"{org}/devices/{device_id}/revoke")
    assert cli.main(["run"]) == 3  # exits instead of looping with a dead credential
    assert "revoked" in load_state().last_error


def test_edge_components_against_the_live_api(live_server, fleet):
    """The MQTT bridge and camera monitor speak the real protocol (no broker or camera needed)."""
    from sentinel_agent.client import AgentClient
    from sentinel_agent.mqtt_bridge import Bridge
    from sentinel_agent.vision import Box, CameraMonitor

    org = f"/api/v1/organizations/{fleet.org_id}"
    assert cli.main(["enroll", "--server", live_server, "--token", fleet.token()["token"], "--name", "pi-gateway"]) == 0
    state = load_state()
    client = AgentClient(state.server_url, state.device_token)

    published: list[tuple[str, str]] = []
    bridge = Bridge(client, lambda topic, body: published.append((topic, body)))
    bridge.on_message("sentinel/esp32-kitchen/readings", b'{"sensor_key": "gas", "sensor_type": "gas", "value": 90}')
    assert bridge.flush()["accepted"] == 1
    sensor = fleet.owner.get(f"{org}/sensors").json()[0]
    assert sensor["sensor_key"] == "esp32-kitchen-gas" and sensor["device_name"] == "pi-gateway"
    fleet.owner.patch(f"{org}/sensors/{sensor['id']}", json={"thresholds": {"max": 300}, "actuator_rules": ["buzzer"]})
    bridge.on_message("sentinel/esp32-kitchen/readings", b'{"sensor_key": "gas", "sensor_type": "gas", "value": 450}')
    bridge.flush()
    assert published[-1] == ("sentinel/esp32-kitchen/actuators", '{"led": false, "buzzer": true}')

    class Motion:
        def detect(self, frame):
            return [Box(0, 0, 10, 10)]

    class People:
        def detect(self, frame):
            return [(Box(70, 10, 20, 60), 0.9)]

    class Frame:
        shape = (100, 100, 3)

    monitor = CameraMonitor(client, "lobby", "Lobby", motion=Motion(), people=People())
    monitor.refresh_config()
    assert monitor.config["detection_enabled"] is False and monitor.handle(Frame()) is None
    camera = fleet.owner.get(f"{org}/cameras").json()[0]
    fleet.owner.patch(f"{org}/cameras/{camera['id']}", json={
        "detection_enabled": True, "zones": [{"name": "Vault", "x": 0.6, "y": 0.0, "w": 0.4, "h": 1.0}]})
    monitor.refresh_config()
    result = monitor.handle(Frame())
    assert result["accepted"] == 3 and result["snapshot_stored"] is False
    assert any(a["title"] == "Person in restricted zone 'Vault' (Lobby)" for a in fleet.owner.get(f"{org}/alerts").json())
