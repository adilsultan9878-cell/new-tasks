"""The MicroPython hub firmware, run on CPython with fake hardware and a fake server."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import ClassVar

import pytest

FIRMWARE = Path(__file__).resolve().parents[2] / "firmware" / "micropython"


class FakePin:
    IN, OUT, PULL_UP = 0, 1, 2
    states: ClassVar[dict[int, int]] = {}

    def __init__(self, pin, mode=None, pull=None):
        self.pin = pin

    def value(self, v=None):
        if v is None:
            return FakePin.states.get(self.pin, 1)
        FakePin.states[self.pin] = v
        return None


class FakeADC:
    ATTN_11DB = 3

    def __init__(self, pin):
        pass

    def atten(self, _):
        pass

    def read(self):
        return 1600


class FakeDHT:
    def __init__(self, pin):
        pass

    def measure(self):
        pass

    def temperature(self):
        return 24.5

    def humidity(self):
        return 51.0


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self.text = json.dumps(body)
        self._body = body

    def json(self):
        return self._body

    def close(self):
        pass


@pytest.fixture
def firmware(tmp_path, monkeypatch):
    calls: list[tuple[str, dict, dict]] = []
    replies: list[FakeResponse] = []

    def post(url, data=None, headers=None):
        calls.append((url, json.loads(data), headers or {}))
        return replies.pop(0)

    machine = types.SimpleNamespace(Pin=FakePin, ADC=FakeADC)
    wlan = types.SimpleNamespace(
        active=lambda *_: None,
        isconnected=lambda: True,
        ifconfig=lambda: ("10.0.0.9",),
        connect=lambda *_: None,
    )
    stubs = {
        "machine": machine,
        "network": types.SimpleNamespace(WLAN=lambda _: wlan, STA_IF=0),
        "urequests": types.SimpleNamespace(post=post),
        "dht": types.SimpleNamespace(DHT22=FakeDHT),
    }
    config = types.ModuleType("config")
    exec(compile((FIRMWARE / "config.example.py").read_text(), "config.py", "exec"), config.__dict__)  # noqa: S102
    stubs["config"] = config
    for name, module in stubs.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.chdir(tmp_path)
    spec = importlib.util.spec_from_file_location("sentinel_firmware", FIRMWARE / "main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    FakePin.states = {}
    return module, calls, replies


def test_firmware_enrolls_reports_and_applies_only_known_outputs(firmware):
    fw, calls, replies = firmware
    replies.append(FakeResponse(201, {"device_token": "sxd.org.dev.secret"}))
    token = fw.enroll("10.0.0.9")
    assert token == "sxd.org.dev.secret" and fw.load_token() == token
    assert (
        calls[0][0].endswith("/api/v1/agent/enroll")
        and calls[0][1]["device"]["hostname"] == "esp32-server-room"
    )

    sensors = fw.Sensors(fw.config.SENSORS)
    actuators = fw.Actuators(fw.config.LED_PIN, fw.config.BUZZER_PIN)
    replies.append(
        FakeResponse(200, {"accepted": 4, "actuators": {"led": False, "buzzer": True, "shell": "rm -rf /"}})
    )
    assert fw.cycle(token, sensors, actuators) == 200
    url, body, headers = calls[1]
    assert url.endswith("/sensors/readings") and headers["Authorization"] == "Bearer sxd.org.dev.secret"
    assert {r["sensor_key"]: r["value"] for r in body["readings"]} == {
        "room_temp": 24.5,
        "room_humidity": 51.0,
        "gas": 400.0,
        "rack_door": 0,
    }
    assert FakePin.states == {2: 0, 15: 1}  # LED off, buzzer on; the unknown key is ignored


def test_firmware_stops_and_forgets_a_revoked_credential(firmware):
    fw, _, replies = firmware
    fw.save_token("sxd.old")
    replies.append(FakeResponse(401, {"error": {"message": "revoked"}}))
    with pytest.raises(fw.Revoked):
        fw.cycle("sxd.old", fw.Sensors(fw.config.SENSORS), fw.Actuators(None, None))
    fw.forget_token()
    assert fw.load_token() is None
