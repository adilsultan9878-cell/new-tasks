"""Recommendations: a fixed playbook keyed by finding code.

Recommendations are advice for a human. Nothing here is executed. Entries marked
``changes_system`` would change a system (block, isolate, close a port) — in the SOC phase they
become response-action proposals that need explicit approval.
"""

from __future__ import annotations

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
            }
        )
    recs.sort(key=lambda r: URGENCY_ORDER[r["urgency"]])
    return recs
