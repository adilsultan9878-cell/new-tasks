"""Recommendations: a fixed playbook keyed by finding code.

Recommendations are advice for a human. Nothing here is executed. Entries marked
``changes_system`` would change a system (block, isolate, close a port) — in the SOC phase they
become response-action proposals that need explicit approval.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.brain.agents import Finding

URGENCY_ORDER = {"now": 0, "soon": 1, "later": 2}

# code → (template, urgency, changes_system)
PLAYBOOK: dict[str, tuple[str, str, bool]] = {
    "alert.detection": (
        "Confirm with the asset owner whether this {severity} activity was expected, then acknowledge the "
        "alert or escalate it to an incident.",
        "now",
        False,
    ),
    "alert.unlinked": (
        "Identify the affected host; once it runs the SENTINEL X agent, future detections are correlated "
        "with its health, exposure and watchlist matches.",
        "later",
        False,
    ),
    "alert.bruteforce": (
        "Review authentication logs on {host}; lock or reset the targeted account(s), enforce MFA and block "
        "the source address if it is external.",
        "now",
        True,
    ),
    "alert.related_alerts": (
        "Correlate the {count} related alert(s) on {host} — several detections on one device often belong to "
        "the same incident.",
        "now",
        False,
    ),
    "alert.unacknowledged": (
        "Acknowledge and assign this alert; it has been open for more than 24 hours.",
        "soon",
        False,
    ),
    "device.offline": (
        "Find out why {host} stopped reporting (power, network or a stopped agent). Treat an unexplained outage "
        "during an active alert as possible tampering.",
        "now",
        False,
    ),
    "device.degraded": ("Check what is consuming resources on {host}.", "soon", False),
    "device.unhealthy": (
        "Investigate resource exhaustion on {host} ({usage}) — runaway processes and crypto-miners show up this way.",
        "soon",
        False,
    ),
    "device.credential_old": (
        "Rotate the agent credential of {host} (last rotated {days} days ago).",
        "later",
        False,
    ),
    "device.open_alerts": ("Triage the {count} open alert(s) on {host}.", "now", False),
    "device.severe_events": (
        "Review the high/critical events on {host} from the last 24 hours.",
        "now",
        False,
    ),
    "device.event_spike": (
        "Investigate the event spike on {host}: {last24} events in 24 h against a daily average of {avg}.",
        "soon",
        False,
    ),
    "exposure.backdoor_port": (
        "Port {port} on {host} is commonly used by backdoors and reverse shells — isolate the host and identify "
        "the listening process.",
        "now",
        True,
    ),
    "exposure.risky_service": (
        "Close or firewall {services} on {host} unless required; allow management services only from a trusted "
        "network.",
        "soon",
        True,
    ),
    "exposure.out_of_scope": (
        "Add the {count} out-of-scope asset(s) to an authorized scope, or remove them from the inventory.",
        "later",
        False,
    ),
    "intel.malicious_match": (
        "Block {value} at the firewall / DNS filter and check other devices for connections to it.",
        "now",
        True,
    ),
    "intel.suspicious_match": (
        "Review the activity involving {value} (rated suspicious by {source}).",
        "soon",
        False,
    ),
    "posture.active_alerts": (
        "Work through the {count} active alert(s), highest severity first.",
        "soon",
        False,
    ),
    "posture.stale_alerts": (
        "Clear the backlog of {count} alert(s) open for more than 24 hours.",
        "soon",
        False,
    ),
    "posture.devices_down": (
        "Restore reporting on the {count} offline or degraded device(s).",
        "soon",
        False,
    ),
    "posture.no_devices": (
        "Enroll devices with the local agent so health, exposure and activity can be assessed.",
        "later",
        False,
    ),
}


def _device_action(action_type: str) -> Callable[[dict[str, Any]], dict[str, Any] | None]:
    def build(params: dict[str, Any]) -> dict[str, Any] | None:
        device_id = params.get("device_id")
        return {"action_type": action_type, "target": {"device_id": device_id}} if device_id else None

    return build


def _block(params: dict[str, Any]) -> dict[str, Any] | None:
    if not params.get("indicator_type") or not params.get("value"):
        return None
    return {
        "action_type": "block_indicator",
        "target": {"indicator_type": params["indicator_type"], "value": params["value"]},
    }


# code → a response action an analyst can propose in one click (it still goes through approval).
PROPOSALS: dict[str, Callable[[dict[str, Any]], dict[str, Any] | None]] = {
    "intel.malicious_match": _block,
    "exposure.backdoor_port": _device_action("revoke_device"),
    "alert.bruteforce": _device_action("heighten_monitoring"),
    "device.severe_events": _device_action("heighten_monitoring"),
    "device.event_spike": _device_action("heighten_monitoring"),
}


class _Defaults(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return "?"


def recommend(findings: list[Finding]) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        entry = PLAYBOOK.get(finding.code)
        if entry is None:
            continue
        template, urgency, changes_system = entry
        text = template.format_map(_Defaults(finding.params))
        if text in seen:
            continue
        seen.add(text)
        recs.append(
            {
                "code": finding.code,
                "text": text,
                "urgency": urgency,
                "changes_system": changes_system,
                "agent": finding.agent,
                "because": finding.title,
                "evidence": finding.evidence[:10],
                "proposal": PROPOSALS[finding.code](finding.params) if finding.code in PROPOSALS else None,
            }
        )
    recs.sort(key=lambda r: URGENCY_ORDER[r["urgency"]])
    return recs
