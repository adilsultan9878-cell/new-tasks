"""MQTT bridge: ESP32/Arduino sensors publish to a local, authenticated broker; the bridge forwards.

Topics (``<node>`` is the sensor board's own short name, e.g. ``esp32-kitchen``):

* the board publishes ``sentinel/<node>/readings`` with JSON
  ``{"readings": [{"sensor_key": "temp", "sensor_type": "temperature", "unit": "°C", "value": 24.1}]}``
  (a single reading object is accepted too);
* the bridge publishes the desired actuator state to ``sentinel/<node>/actuators`` as
  ``{"led": false, "buzzer": true}`` (retained) — state, never a command.

The bridge runs on an enrolled device (e.g. a Raspberry Pi) and reports the boards' sensors as
``<node>-<sensor_key>`` with its own device credential. Install with
``pip install "sentinel-x-agent[mqtt]"``; broker credentials come from SENTINEL_MQTT_USERNAME /
SENTINEL_MQTT_PASSWORD.
"""

from __future__ import annotations

import json
import logging
import math
import re
import threading
import time
from collections.abc import Callable
from typing import Any

log = logging.getLogger("sentinel.mqtt")

NODE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}$")
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,38}$")
TYPE_RE = re.compile(r"^[a-z_]{1,48}$")
MAX_PAYLOAD = 16_384
TOPIC_RE = re.compile(r"^sentinel/([^/]+)/readings$")


class InvalidMessage(ValueError):
    pass


def parse_message(topic: str, payload: bytes) -> tuple[str, list[dict[str, Any]]]:
    """Validate one MQTT message and return (node, readings ready for the API)."""
    match = TOPIC_RE.match(topic)
    if not match or not NODE_RE.match(match.group(1)):
        raise InvalidMessage(f"unexpected topic {topic!r}")
    node = match.group(1)
    if len(payload) > MAX_PAYLOAD:
        raise InvalidMessage("payload too large")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidMessage("payload is not JSON") from None
    items = data.get("readings") if isinstance(data, dict) and "readings" in data else [data]
    if not isinstance(items, list) or not 1 <= len(items) <= 50:
        raise InvalidMessage("readings must be a list of 1-50 items")
    readings = []
    for item in items:
        if not isinstance(item, dict):
            raise InvalidMessage("each reading must be an object")
        key, kind = str(item.get("sensor_key", "")), str(item.get("sensor_type", "generic"))
        value = item.get("value")
        if not KEY_RE.match(key) or not TYPE_RE.match(kind):
            raise InvalidMessage("invalid sensor_key or sensor_type")
        if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
            raise InvalidMessage("value must be a finite number")
        reading: dict[str, Any] = {"sensor_key": f"{node}-{key}", "sensor_type": kind, "value": float(value)}
        if item.get("unit") is not None:
            reading["unit"] = str(item["unit"])[:16]
        readings.append(reading)
    return node, readings


class Bridge:
    """Buffers readings from many boards and forwards them in batches; publishes actuator state."""

    def __init__(self, client: Any, publish: Callable[[str, str], None], max_batch: int = 100) -> None:
        self.client = client
        self.publish = publish
        self.max_batch = max_batch
        self.pending: list[dict[str, Any]] = []
        self.nodes: set[str] = set()
        self.lock = threading.Lock()
        self.rejected = 0

    def on_message(self, topic: str, payload: bytes) -> None:
        try:
            node, readings = parse_message(topic, payload)
        except InvalidMessage as exc:
            self.rejected += 1
            log.warning("ignored MQTT message: %s", exc)
            return
        with self.lock:
            self.pending.extend(readings)
            self.nodes.add(node)

    def flush(self) -> dict[str, Any] | None:
        with self.lock:
            batch, self.pending = self.pending[: self.max_batch], self.pending[self.max_batch :]
            nodes = sorted(self.nodes)
            self.nodes = set() if not self.pending else self.nodes
        if not batch:
            return None
        result = self.client.send_readings(batch)
        state = json.dumps({k: bool(v) for k, v in (result.get("actuators") or {}).items()})
        for node in nodes:
            self.publish(f"sentinel/{node}/actuators", state)
        return result


def run(
    client: Any,
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    tls_ca: str | None = None,
    interval: float = 10.0,
) -> None:  # pragma: no cover - needs a broker
    import paho.mqtt.client as mqtt

    mq = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="sentinel-x-bridge")
    if username:
        mq.username_pw_set(username, password)
    if tls_ca:
        mq.tls_set(ca_certs=tls_ca)
    bridge = Bridge(client, lambda topic, body: mq.publish(topic, body, qos=1, retain=True))
    mq.on_connect = lambda c, *_: c.subscribe("sentinel/+/readings", qos=1)
    mq.on_message = lambda _c, _u, msg: bridge.on_message(msg.topic, msg.payload)
    mq.connect(host, port, keepalive=60)
    mq.loop_start()
    log.info("bridging MQTT %s:%s → SENTINEL X", host, port)
    try:
        while True:
            time.sleep(interval)
            try:
                bridge.flush()
            except Exception as exc:  # keep the bridge up through API hiccups; readings are retried
                log.warning("could not forward readings: %s", exc)
    finally:
        mq.loop_stop()
        mq.disconnect()
