"""Transparent, weighted risk scoring.

Each subject type has a fixed scoring model: a list of factors whose maximum points add up to
100. Agents award points within a factor's maximum and say why; a factor with no input data
(e.g. an alert that is not tied to any device) scores 0 and is reported as "no data".

* **risk score** = sum of awarded points (0-100)
* **coverage**   = share of the model (in points) that had data — a low coverage means the
  score is a lower bound, not a clean bill of health
* **level**      = critical >= 75, high >= 50, medium >= 25, low >= 10, otherwise info
* **priority**   (alerts) = P1 critical, P2 high, P3 medium, P4 low/info
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FactorSpec:
    key: str
    label: str
    weight: int  # maximum points
    agent: str
    description: str


@dataclass
class FactorResult:
    points: int
    evidence: str
    has_data: bool = True


MODELS: dict[str, tuple[FactorSpec, ...]] = {
    "alert": (
        FactorSpec(
            "alert_severity",
            "Alert severity",
            50,
            "triage",
            "Severity assigned by the detection rule: info 0, low 25%, medium 50%, high 75%, critical 100%.",
        ),
        FactorSpec(
            "corroboration",
            "Corroborating activity",
            15,
            "triage",
            "Repeats of the triggering event and other alerts on the same device in the last 24 hours.",
        ),
        FactorSpec(
            "asset_condition",
            "Affected device condition",
            10,
            "device",
            "Whether the affected device is offline, degraded, unhealthy or has a stale credential.",
        ),
        FactorSpec(
            "exposure",
            "Network exposure",
            10,
            "exposure",
            "Risky services listening on the affected device (e.g. Telnet, SMB, RDP, Redis, backdoor ports).",
        ),
        FactorSpec(
            "threat_intel",
            "Threat-intel match",
            15,
            "intel",
            "Observables of the event matching indicators on your watchlist rated suspicious or malicious.",
        ),
    ),
    "device": (
        FactorSpec(
            "device_state",
            "Device state",
            20,
            "device",
            "Offline / degraded status, health score and credential age.",
        ),
        FactorSpec(
            "open_alerts",
            "Open alerts",
            30,
            "device",
            "Open or acknowledged alerts on the device: critical 15, high 10, medium 5, low 2 points each.",
        ),
        FactorSpec(
            "event_activity",
            "Event activity",
            15,
            "device",
            "High/critical events in the last 24 hours and spikes against the device's 7-day baseline.",
        ),
        FactorSpec(
            "exposure",
            "Network exposure",
            20,
            "exposure",
            "Risky services listening on the device, 5 points each; a backdoor port scores the maximum.",
        ),
        FactorSpec(
            "threat_intel",
            "Threat-intel match",
            15,
            "intel",
            "Observables in the device's recent events matching watchlist indicators.",
        ),
    ),
    "organization": (
        FactorSpec(
            "open_alerts",
            "Open alerts",
            30,
            "posture",
            "Open or acknowledged alerts: critical 10, high 5, medium 2, low 1 point each.",
        ),
        FactorSpec(
            "stale_alerts",
            "Alert backlog",
            10,
            "posture",
            "Alerts still open (not acknowledged) after 24 hours, 2 points each.",
        ),
        FactorSpec(
            "device_fleet",
            "Device fleet health",
            20,
            "posture",
            "Share of enrolled devices that are offline or degraded.",
        ),
        FactorSpec(
            "exposure",
            "Network exposure",
            20,
            "exposure",
            "Assets with risky services, 4 points each; any backdoor port scores the maximum.",
        ),
        FactorSpec(
            "threat_intel",
            "Threat-intel sightings",
            20,
            "intel",
            "Watchlist indicators rated suspicious/malicious seen in events during the look-back window.",
        ),
    ),
}

assert all(sum(f.weight for f in model) == 100 for model in MODELS.values()), "scoring models must total 100"

LEVELS = ((75, "critical"), (50, "high"), (25, "medium"), (10, "low"), (0, "info"))
PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}
SEVERITY_FRACTION = {"info": 0.0, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def level_for(score: int) -> str:
    return next(name for threshold, name in LEVELS if score >= threshold)


def model_spec(subject_type: str) -> dict[str, FactorSpec]:
    return {f.key: f for f in MODELS[subject_type]}


@dataclass
class Score:
    score: int
    level: str
    coverage: int
    priority: str
    factors: list[dict[str, Any]]


def compute(subject_type: str, results: dict[str, FactorResult]) -> Score:
    factors: list[dict[str, Any]] = []
    total = covered = 0
    for spec in MODELS[subject_type]:
        result = results.get(spec.key) or FactorResult(0, "Not evaluated", has_data=False)
        points = max(0, min(spec.weight, int(result.points))) if result.has_data else 0
        total += points
        covered += spec.weight if result.has_data else 0
        factors.append(
            {
                "key": spec.key,
                "label": spec.label,
                "agent": spec.agent,
                "points": points,
                "max_points": spec.weight,
                "has_data": result.has_data,
                "evidence": result.evidence,
            }
        )
    level = level_for(total)
    return Score(score=total, level=level, coverage=covered, priority=PRIORITY[level], factors=factors)


def models_catalogue() -> dict[str, list[dict[str, Any]]]:
    return {
        subject: [
            {
                "key": f.key,
                "label": f.label,
                "max_points": f.weight,
                "agent": f.agent,
                "description": f.description,
            }
            for f in model
        ]
        for subject, model in MODELS.items()
    }
