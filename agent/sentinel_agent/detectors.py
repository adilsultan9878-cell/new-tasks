"""Local, deterministic detections over the collected telemetry."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# Ports commonly used by backdoors / remote-access trojans: escalate when one starts listening.
SUSPICIOUS_PORTS = {1337, 4444, 5555, 6666, 6667, 12345, 31337}

THRESHOLD_EVENTS = {
    "cpu_percent": ("system.high_cpu", "High CPU usage"),
    "memory_percent": ("system.high_memory", "High memory usage"),
    "disk_percent": ("system.disk_almost_full", "System disk almost full"),
}


@dataclass
class Detector:
    thresholds: dict[str, float]
    known_ports: set[int] | None = None
    cooldown_seconds: int = 900
    _last_fired: dict[str, float] = field(default_factory=dict)

    def _cooling(self, key: str, now: float) -> bool:
        last = self._last_fired.get(key)
        if last is not None and now - last < self.cooldown_seconds:
            return True
        self._last_fired[key] = now
        return False

    def evaluate(self, telemetry: dict[str, Any], now: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now is None else now
        events: list[dict[str, Any]] = []

        for metric, (event_type, label) in THRESHOLD_EVENTS.items():
            value = telemetry.get(metric)
            limit = self.thresholds.get(metric, 90)
            if value is None or value < limit or self._cooling(event_type, now):
                continue
            severity = "high" if metric == "disk_percent" and value >= 97 else "medium"
            events.append(
                {
                    "event_type": event_type,
                    "category": "system",
                    "severity": severity,
                    "title": f"{label}: {value:.0f}% (threshold {limit:.0f}%)",
                    "dedup_key": event_type,
                    "raw": {"metric": metric, "value": value, "threshold": limit},
                }
            )

        ports = telemetry.get("listening_ports")
        if isinstance(ports, list):
            current = set(ports)
            if self.known_ports is None:
                self.known_ports = current  # first observation is the baseline, not an alert
            else:
                for port in sorted(current - self.known_ports):
                    suspicious = port in SUSPICIOUS_PORTS
                    events.append(
                        {
                            "event_type": "network.new_listening_port",
                            "category": "network",
                            "severity": "high" if suspicious else "medium",
                            "title": f"New listening port {port}"
                            + (" (commonly used by backdoors)" if suspicious else ""),
                            "dedup_key": f"port:{port}",
                            "raw": {"port": port, "suspicious": suspicious},
                        }
                    )
                self.known_ports = current
        return events
