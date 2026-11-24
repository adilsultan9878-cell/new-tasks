"""Camera agent (OpenCV) and MQTT bridge — no camera, broker or server needed."""

from __future__ import annotations

import json

import pytest

from sentinel_agent.mqtt_bridge import Bridge, InvalidMessage, parse_message
from sentinel_agent.vision import Box, CameraMonitor, Cooldown, Detection, in_zone

cv2 = pytest.importorskip("cv2")
np = pytest.importorskip("numpy")

from sentinel_agent.vision import MotionDetector, blur_boxes, encode_jpeg  # noqa: E402


class FakeClient:
    def __init__(self, config: dict | None = None):
        self.sent: list[dict] = []
        self.config = {
            "detection_enabled": True,
            "zones": [],
            "snapshots": False,
            "blur_people": True,
            "cooldown_seconds": 30,
            **(config or {}),
        }

    def vision_config(self, key, name=None):
        return self.config

    def send_detections(self, payload):
        self.sent.append(payload)
        return {"accepted": len(payload["detections"]), "config": self.config}


class StubMotion:
    def __init__(self, boxes):
        self.boxes = boxes

    def detect(self, frame):
        return self.boxes


class StubPeople:
    def __init__(self, found):
        self.found = found

    def detect(self, frame):
        return self.found


def frame(value: int = 0, size=(120, 160)):
    return np.full((*size, 3), value, np.uint8)


# --------------------------------------------------------------------------------- geometry
def test_zone_overlap_and_cooldown():
    zone = {"name": "Vault", "x": 0.5, "y": 0.0, "w": 0.5, "h": 1.0}
    assert in_zone(Box(90, 10, 20, 40), zone, 160, 120)  # fully inside
    assert not in_zone(Box(0, 0, 40, 40), zone, 160, 120)  # outside
    assert not in_zone(Box(70, 0, 20, 20), zone, 160, 120, min_overlap=0.6)  # half in, too little
    clock = iter([0.0, 5.0, 31.0])
    cd = Cooldown(30, clock=lambda: next(clock))
    assert cd.allow("motion") and not cd.allow("motion") and cd.allow("motion")


def test_motion_detector_finds_a_moving_object_after_warmup():
    detector = MotionDetector(warmup_frames=3)
    for _ in range(6):
        assert detector.detect(frame()) == []  # still scene
    moved = frame()
    cv2.rectangle(moved, (40, 30), (90, 90), (255, 255, 255), -1)
    boxes = detector.detect(moved)
    assert boxes and max(b.area for b in boxes) > 1000


def test_blur_and_jpeg_never_leak_the_original_pixels():
    img = frame()
    img[20:80, 40:100] = np.indices((60, 60, 3)).sum(axis=0).astype(np.uint8) * 3  # detailed texture
    blurred = blur_boxes(img, [Box(40, 20, 60, 60)])
    assert not np.array_equal(blurred[20:80, 40:100], img[20:80, 40:100])
    assert np.array_equal(blurred[:, :30], img[:, :30])  # outside the box untouched
    assert encode_jpeg(blurred)[:3] == b"\xff\xd8\xff"


# ----------------------------------------------------------------------------- the monitor
def test_monitor_reports_nothing_while_detection_is_off():
    client = FakeClient({"detection_enabled": False})
    monitor = CameraMonitor(client, "door", motion=StubMotion([Box(0, 0, 50, 50)]), people=StubPeople([]))
    monitor.refresh_config()
    assert monitor.handle(frame()) is None and client.sent == []


def test_monitor_detects_zone_intrusion_with_cooldown_and_blurred_snapshot():
    client = FakeClient(
        {"zones": [{"name": "Vault", "x": 0.5, "y": 0.0, "w": 0.5, "h": 1.0}], "snapshots": True}
    )
    now = [0.0]
    monitor = CameraMonitor(
        client,
        "door",
        "Door",
        motion=StubMotion([Box(80, 10, 40, 80)]),
        people=StubPeople([(Box(90, 10, 30, 80), 0.87)]),
        clock=lambda: now[0],
    )
    monitor.refresh_config()
    monitor.handle(frame(200))
    payload = client.sent[0]
    assert payload["name"] == "Door"
    assert [d["type"] for d in payload["detections"]] == ["motion", "person", "zone_intrusion"]
    assert payload["detections"][2] == {
        "type": "zone_intrusion",
        "zone": "Vault",
        "objects": 1,
        "confidence": 0.87,
    }
    assert payload["snapshot_base64"]  # snapshots allowed by the console, people blurred
    now[0] = 10.0
    assert monitor.handle(frame(200)) is None  # within the 30 s cooldown
    now[0] = 40.0
    monitor.handle(frame(200))
    assert len(client.sent) == 2


def test_no_snapshot_leaves_while_privacy_mode_is_on():
    client = FakeClient({"snapshots": False})
    monitor = CameraMonitor(client, "door", motion=StubMotion([Box(0, 0, 40, 40)]), people=StubPeople([]))
    monitor.refresh_config()
    monitor.handle(frame())
    assert "snapshot_base64" not in client.sent[0] and client.sent[0]["detections"] == [
        {"type": "motion", "objects": 1}
    ]
    assert Detection("person", confidence=0.5).as_dict() == {"type": "person", "confidence": 0.5}


# ------------------------------------------------------------------------------ MQTT bridge
def test_mqtt_messages_are_validated():
    node, readings = parse_message(
        "sentinel/esp32-kitchen/readings",
        b'{"readings": [{"sensor_key": "temp", "sensor_type": "temperature", "unit": "C", "value": 21}]}',
    )
    assert node == "esp32-kitchen" and readings == [
        {"sensor_key": "esp32-kitchen-temp", "sensor_type": "temperature", "value": 21.0, "unit": "C"}
    ]
    bad = [
        ("sentinel/../readings", b'{"sensor_key": "t", "value": 1}'),
        ("other/topic", b'{"sensor_key": "t", "value": 1}'),
        ("sentinel/node/readings", b"not json"),
        ("sentinel/node/readings", b'{"sensor_key": "T!", "value": 1}'),
        ("sentinel/node/readings", b'{"sensor_key": "t", "value": true}'),
        ("sentinel/node/readings", b'{"sensor_key": "t", "value": "1; rm -rf /"}'),
        ("sentinel/node/readings", b'{"sensor_key": "t", "value": 1, "pad": "' + b"x" * 20000 + b'"}'),
        ("sentinel/node/readings", json.dumps({"readings": []}).encode()),
    ]
    for topic, payload in bad:
        with pytest.raises(InvalidMessage):
            parse_message(topic, payload)


def test_bridge_batches_forwards_and_publishes_actuator_state():
    class Client:
        def __init__(self):
            self.batches = []

        def send_readings(self, readings):
            self.batches.append(readings)
            return {"accepted": len(readings), "actuators": {"led": True, "buzzer": False}}

    published = []
    client = Client()
    bridge = Bridge(client, lambda topic, body: published.append((topic, json.loads(body))), max_batch=2)
    bridge.on_message("sentinel/a/readings", b'{"sensor_key": "t", "value": 1}')
    bridge.on_message(
        "sentinel/b/readings",
        b'{"readings": [{"sensor_key": "t", "value": 2}, {"sensor_key": "h", "value": 3}]}',
    )
    bridge.on_message("sentinel/b/readings", b"garbage")
    assert bridge.rejected == 1
    bridge.flush()
    bridge.flush()
    assert [len(b) for b in client.batches] == [2, 1] and bridge.flush() is None
    assert ("sentinel/a/actuators", {"led": True, "buzzer": False}) in published
    assert {t for t, _ in published} == {"sentinel/a/actuators", "sentinel/b/actuators"}
