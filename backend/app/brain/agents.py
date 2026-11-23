"""Specialised, deterministic Security Brain agents.

Each agent receives the resolved subject (:class:`Context`) and a :class:`~app.brain.toolbox.Toolbox`
and returns findings plus points for the scoring factors it owns. Agents never import the
database session or models: everything they know comes from a recorded, read-only tool call.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.brain.scoring import SEVERITY_FRACTION, FactorResult, model_spec
from app.brain.toolbox import Toolbox

# Mirrors app.services.network.RISKY_SERVICES (kept local so agents import no service code).
RISKY_SERVICES: dict[int, str] = {
    21: "ftp",
    23: "telnet",
    135: "msrpc",
    139: "netbios-ssn",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    2375: "docker-api",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    4444: "backdoor",
    31337: "backdoor",
}
BACKDOOR_PORTS = frozenset({4444, 31337})
# Cleartext or commonly unauthenticated by default → high rather than medium.
HIGH_RISK_PORTS = frozenset({23, 2375, 6379, 9200, 11211, 27017})
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
CREDENTIAL_MAX_AGE_DAYS = 90


@dataclass
class Finding:
    agent: str
    code: str  # stable key used by the playbook, e.g. "exposure.risky_service"
    title: str
    severity: str
    detail: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "code": self.code,
            "title": self.title,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class AgentResult:
    findings: list[Finding] = field(default_factory=list)
    factors: dict[str, FactorResult] = field(default_factory=dict)


@dataclass
class Context:
    subject_type: str  # alert | device | organization
    lookback_days: int
    alert: dict[str, Any] | None = None
    event: dict[str, Any] | None = None
    device: dict[str, Any] | None = None

    @property
    def host(self) -> str:
        d = self.device
        return (d["name"] or d["hostname"] or d["ip_address"] or "the device") if d else "the device"


@dataclass(frozen=True)
class AgentSpec:
    name: str
    title: str
    description: str
    subjects: tuple[str, ...]
    tools: tuple[str, ...]
    run: Callable[[Context, Toolbox], AgentResult]


def _max_severity(values: list[str]) -> str:
    return max(values, key=SEVERITY_ORDER.index) if values else "info"


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _ref(kind: str, item: dict[str, Any], label: str | None = None) -> dict[str, Any]:
    return {
        "type": kind,
        "id": item["id"],
        "label": (label or item.get("title") or item.get("name") or "")[:160],
    }


def _weight(subject: str, key: str) -> int:
    return model_spec(subject)[key].weight


# ------------------------------------------------------------------------------ triage agent
def run_triage(ctx: Context, tb: Toolbox) -> AgentResult:
    out = AgentResult()
    alert, event, device = ctx.alert, ctx.event, ctx.device
    assert alert is not None
    severity = alert["severity"]
    refs = [_ref("alert", alert)] + ([_ref("event", event)] if event else [])

    weight = _weight("alert", "alert_severity")
    out.factors["alert_severity"] = FactorResult(
        round(weight * SEVERITY_FRACTION[severity]),
        f"Rule '{alert['detection_rule'] or 'manual'}' rated the alert {severity}.",
    )
    out.findings.append(
        Finding(
            "triage",
            # Only an open alert still needs the "confirm and acknowledge" recommendation.
            "alert.detection" if alert["status"] == "open" else "alert.detection_reviewed",
            f"Detection '{alert['detection_rule'] or 'manual'}' rated this alert {severity}",
            severity,
            alert["description"] or "",
            refs,
            {"severity": severity},
        )
    )
    if device is None:
        out.findings.append(
            Finding(
                "triage",
                "alert.unlinked",
                "Alert is not linked to an enrolled device",
                "info",
                "Device condition and network exposure cannot be assessed for this alert.",
                refs[:1],
            )
        )
    if alert["detection_rule"] == "auth-bruteforce":
        out.findings.append(
            Finding(
                "triage",
                "alert.bruteforce",
                f"Repeated failed logins on {ctx.host}",
                "high",
                alert["description"] or "",
                refs,
                {"host": ctx.host},
            )
        )

    # Corroboration: repeats of the triggering event + other alerts on the same device (24 h).
    occurrences = event["occurrence_count"] if event else 0
    repeat_points = 6 if occurrences >= 10 else 4 if occurrences >= 3 else 2 if occurrences >= 2 else 0
    if occurrences >= 2:
        out.findings.append(
            Finding(
                "triage",
                "alert.repeated",
                f"The triggering event repeated {occurrences} times",
                "medium" if occurrences >= 10 else "low",
                "Repeated detections are less likely to be a one-off glitch.",
                refs[1:],
            )
        )
    others: list[dict[str, Any]] = []
    if device is not None:
        others = [
            a
            for a in tb.alerts_for_device(uuid.UUID(device["id"]), since=tb.since(hours=24))
            if a["id"] != alert["id"]
        ]
        if others:
            out.findings.append(
                Finding(
                    "triage",
                    "alert.related_alerts",
                    f"{len(others)} other alert(s) on {ctx.host} in the last 24 hours",
                    _max_severity([a["severity"] for a in others]),
                    "; ".join(f"{a['severity']}: {a['title']}" for a in others[:5]),
                    [_ref("alert", a) for a in others[:10]],
                    {"host": ctx.host, "count": len(others)},
                )
            )
    weight = _weight("alert", "corroboration")
    has_data = event is not None or device is not None
    out.factors["corroboration"] = FactorResult(
        min(weight, repeat_points + min(9, 3 * len(others))),
        f"Event seen {occurrences}x; {len(others)} other alert(s) on the device in 24 h."
        if has_data
        else "The triggering event is no longer available.",
        has_data,
    )

    created = _parse(alert["created_at"])
    if alert["status"] == "open" and created and (tb.now - created).total_seconds() > 86400:
        out.findings.append(
            Finding(
                "triage",
                "alert.unacknowledged",
                "Alert has been open for more than 24 hours",
                "low",
                f"Raised {created:%Y-%m-%d %H:%M} UTC and not yet acknowledged.",
                refs[:1],
            )
        )
    if alert["status"] in ("resolved", "false_positive"):
        out.findings.append(
            Finding(
                "triage",
                "alert.closed",
                f"Alert is already marked {alert['status'].replace('_', ' ')}",
                "info",
                "The score describes the alert as detected; no further action may be needed.",
                refs[:1],
            )
        )
    if alert["is_simulated"]:
        out.findings.append(
            Finding(
                "triage",
                "data.simulated",
                "Simulated data — not a real incident",
                "info",
                "This alert was produced by a simulator or demo data.",
                refs[:1],
            )
        )
    return out


# --------------------------------------------------------------------------- device agent
def _condition(ctx: Context, tb: Toolbox, scale: dict[str, int]) -> tuple[int, list[Finding]]:
    device = ctx.device
    assert device is not None
    ref = [_ref("device", device)]
    findings: list[Finding] = []
    points = 0
    status = device["status"]
    if device["enrollment_status"] != "enrolled" or status == "decommissioned":
        return 0, [
            Finding(
                "device",
                "device.decommissioned",
                f"{ctx.host} is decommissioned / revoked",
                "info",
                "It no longer reports telemetry; its history is still analysed.",
                ref,
            )
        ]
    if status == "offline":
        points += scale["offline"]
        last = _parse(device["last_seen_at"])
        findings.append(
            Finding(
                "device",
                "device.offline",
                f"{ctx.host} is offline",
                "medium",
                f"Last heartbeat {last:%Y-%m-%d %H:%M} UTC." if last else "It has never reported.",
                ref,
                {"host": ctx.host},
            )
        )
    elif status == "degraded":
        points += scale["degraded"]
        findings.append(
            Finding(
                "device",
                "device.degraded",
                f"{ctx.host} is degraded",
                "medium",
                "The agent reports resource pressure above its thresholds.",
                ref,
                {"host": ctx.host},
            )
        )

    health = device["health_score"]
    tel = device["telemetry"]
    usage = {k: tel.get(f"{k}_percent") for k in ("cpu", "memory", "disk")}
    usage_text = (
        ", ".join(f"{k} {v:.0f}%" for k, v in usage.items() if isinstance(v, int | float)) or "no telemetry"
    )
    if health is not None and health < 60:
        points += scale["unhealthy"]
        findings.append(
            Finding(
                "device",
                "device.unhealthy",
                f"Health score {health}/100 on {ctx.host}",
                "medium",
                usage_text,
                ref,
                {"host": ctx.host, "usage": usage_text},
            )
        )
    elif health is not None and health < 80:
        points += scale["health_warning"]
        findings.append(
            Finding(
                "device",
                "device.health_warning",
                f"Health score {health}/100 on {ctx.host}",
                "low",
                usage_text,
                ref,
                {"host": ctx.host, "usage": usage_text},
            )
        )

    rotated = _parse(device["credential_rotated_at"])
    if rotated and (tb.now - rotated).days > CREDENTIAL_MAX_AGE_DAYS:
        days = (tb.now - rotated).days
        points += scale["credential_old"]
        findings.append(
            Finding(
                "device",
                "device.credential_old",
                f"Agent credential is {days} days old",
                "low",
                f"Credentials older than {CREDENTIAL_MAX_AGE_DAYS} days should be rotated.",
                ref,
                {"host": ctx.host, "days": days},
            )
        )
    return points, findings


def run_device(ctx: Context, tb: Toolbox) -> AgentResult:
    out = AgentResult()
    device = ctx.device
    if ctx.subject_type == "alert":
        if device is None:
            out.factors["asset_condition"] = FactorResult(
                0, "The alert is not linked to a device.", has_data=False
            )
            return out
        weight = _weight("alert", "asset_condition")
        points, findings = _condition(
            ctx, tb, {"offline": 4, "degraded": 3, "unhealthy": 3, "health_warning": 0, "credential_old": 3}
        )
        out.findings += findings
        out.factors["asset_condition"] = FactorResult(
            min(weight, points), "; ".join(f.title for f in findings) or f"{ctx.host} is online and healthy."
        )
        return out

    assert device is not None  # subject_type == "device"
    device_id = uuid.UUID(device["id"])
    weight = _weight("device", "device_state")
    points, findings = _condition(
        ctx, tb, {"offline": 8, "degraded": 6, "unhealthy": 6, "health_warning": 3, "credential_old": 3}
    )
    out.findings += findings
    out.factors["device_state"] = FactorResult(
        min(weight, points), "; ".join(f.title for f in findings) or f"{ctx.host} is online and healthy."
    )

    active = tb.alerts_for_device(device_id, since=tb.since(days=3650), active_only=True)
    per = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}
    counts = {s: sum(1 for a in active if a["severity"] == s) for s in reversed(SEVERITY_ORDER)}
    breakdown = ", ".join(f"{n} {s}" for s, n in counts.items() if n)
    out.factors["open_alerts"] = FactorResult(
        min(_weight("device", "open_alerts"), sum(per[a["severity"]] for a in active)),
        f"{len(active)} open/acknowledged alert(s){': ' + breakdown if breakdown else ''}.",
    )
    if active:
        out.findings.append(
            Finding(
                "device",
                "device.open_alerts",
                f"{len(active)} active alert(s) on {ctx.host}",
                _max_severity([a["severity"] for a in active]),
                breakdown,
                [_ref("alert", a) for a in active[:10]],
                {"host": ctx.host, "count": len(active)},
            )
        )

    has_reported = device["last_seen_at"] is not None
    severe = tb.event_volume(since=tb.since(hours=24), device_id=device_id, severities=("high", "critical"))
    last24 = tb.event_volume(since=tb.since(hours=24), device_id=device_id)
    prior = tb.event_volume(since=tb.since(days=8), until=tb.since(hours=24), device_id=device_id)
    daily_avg = prior / 7
    spike = last24 >= 10 and last24 > 3 * max(daily_avg, 1.0)
    if severe:
        out.findings.append(
            Finding(
                "device",
                "device.severe_events",
                f"{severe} high/critical event(s) in 24 hours",
                "high",
                f"On {ctx.host}.",
                [_ref("device", device)],
                {"host": ctx.host},
            )
        )
    if spike:
        out.findings.append(
            Finding(
                "device",
                "device.event_spike",
                f"Event spike on {ctx.host}",
                "medium",
                f"{last24} events in 24 h vs a 7-day daily average of {daily_avg:.1f}.",
                [_ref("device", device)],
                {"host": ctx.host, "last24": last24, "avg": f"{daily_avg:.1f}"},
            )
        )
    out.factors["event_activity"] = FactorResult(
        min(_weight("device", "event_activity"), min(10, 5 * severe) + (5 if spike else 0)),
        f"{severe} high/critical and {last24} total event(s) in 24 h; 7-day daily average {daily_avg:.1f}."
        if has_reported
        else "The device has never reported.",
        has_reported or bool(last24 or prior),
    )
    return out


# ------------------------------------------------------------------------- exposure agent
def _risky_findings(host: str, ports: set[int], refs: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for port in sorted(ports):
        service = RISKY_SERVICES[port]
        if port in BACKDOOR_PORTS:
            findings.append(
                Finding(
                    "exposure",
                    "exposure.backdoor_port",
                    f"Port {port} listening on {host}",
                    "critical",
                    "Commonly used by backdoors and reverse shells.",
                    refs,
                    {"host": host, "port": port},
                )
            )
        else:
            findings.append(
                Finding(
                    "exposure",
                    "exposure.risky_service",
                    f"{service} (port {port}) exposed on {host}",
                    "high" if port in HIGH_RISK_PORTS else "medium",
                    "Cleartext or often unauthenticated by default."
                    if port in HIGH_RISK_PORTS
                    else "Frequently targeted remote-access / database service.",
                    refs,
                    {"host": host, "services": f"{service} ({port})"},
                )
            )
    return findings


def run_exposure(ctx: Context, tb: Toolbox) -> AgentResult:
    out = AgentResult()
    if ctx.subject_type in ("alert", "device"):
        weight = _weight(ctx.subject_type, "exposure")
        device = ctx.device
        if device is None:
            out.factors["exposure"] = FactorResult(0, "The alert is not linked to a device.", has_data=False)
            return out
        asset = tb.asset_for_device(uuid.UUID(device["id"]), device["ip_address"])
        reported = device["telemetry"].get("listening_ports")
        ports = {p for p in (reported or []) if isinstance(p, int)}
        if asset:
            ports |= set(asset["open_ports"]) | {
                s["port"] for s in asset["services"] if isinstance(s.get("port"), int)
            }
        has_data = asset is not None or isinstance(reported, list)
        risky = {p for p in ports if p in RISKY_SERVICES}
        refs = [_ref("asset", asset, asset["ip_address"])] if asset else [_ref("device", device)]
        out.findings += _risky_findings(ctx.host, risky, refs)
        if asset and not asset["in_authorized_scope"]:
            out.findings.append(
                Finding(
                    "exposure",
                    "exposure.out_of_scope",
                    f"{asset['ip_address']} is outside every authorized scope",
                    "info",
                    "Exposure data for it comes from the agent only.",
                    refs,
                    {"count": 1},
                )
            )
        points = weight if risky & BACKDOOR_PORTS else min(weight, 5 * len(risky))
        out.factors["exposure"] = FactorResult(
            points,
            (
                f"{len(ports)} listening port(s), risky: "
                + ", ".join(f"{RISKY_SERVICES[p]}/{p}" for p in sorted(risky))
                if risky
                else f"{len(ports)} listening port(s), none on the risky-service list."
            )
            if has_data
            else "No port data: no agent port report and no network asset for this device.",
            has_data,
        )
        return out

    weight = _weight("organization", "exposure")
    assets = tb.assets()
    risky_assets: list[tuple[dict[str, Any], set[int]]] = []
    for asset in assets:
        ports = set(asset["open_ports"]) | {
            s["port"] for s in asset["services"] if isinstance(s.get("port"), int)
        }
        risky = {p for p in ports if p in RISKY_SERVICES}
        if risky:
            risky_assets.append((asset, risky))
    backdoor = any(r & BACKDOOR_PORTS for _, r in risky_assets)
    for asset, risky in risky_assets[:10]:
        host = asset["hostname"] or asset["ip_address"]
        refs = [_ref("asset", asset, asset["ip_address"])]
        doors = risky & BACKDOOR_PORTS
        out.findings += _risky_findings(host, doors, refs)
        rest = sorted(risky - doors)
        if rest:
            out.findings.append(
                Finding(
                    "exposure",
                    "exposure.risky_service",
                    f"{len(rest)} risky service(s) on {host}",
                    "high" if set(rest) & HIGH_RISK_PORTS else "medium",
                    ", ".join(f"{RISKY_SERVICES[p]} ({p})" for p in rest),
                    refs,
                    {"host": host, "services": ", ".join(f"{RISKY_SERVICES[p]} ({p})" for p in rest)},
                )
            )
    outside = [a for a in assets if not a["in_authorized_scope"]]
    if outside:
        out.findings.append(
            Finding(
                "exposure",
                "exposure.out_of_scope",
                f"{len(outside)} asset(s) outside every authorized scope",
                "info",
                ", ".join(a["ip_address"] for a in outside[:10]),
                [_ref("asset", a, a["ip_address"]) for a in outside[:10]],
                {"count": len(outside)},
            )
        )
    out.factors["exposure"] = FactorResult(
        weight if backdoor else min(weight, 4 * len(risky_assets)),
        f"{len(risky_assets)} of {len(assets)} asset(s) expose risky services."
        if assets
        else "The network inventory is empty (import a scan or enroll agents).",
        bool(assets),
    )
    return out


# ---------------------------------------------------------------------------- intel agent
def run_intel(ctx: Context, tb: Toolbox) -> AgentResult:
    out = AgentResult()
    weight = _weight(ctx.subject_type, "threat_intel")
    if ctx.subject_type == "alert":
        events = [ctx.event] if ctx.event else []
    elif ctx.subject_type == "device":
        assert ctx.device is not None
        events = tb.recent_events(
            since=tb.since(days=ctx.lookback_days), device_id=uuid.UUID(ctx.device["id"])
        )
    else:
        events = tb.recent_events(since=tb.since(days=ctx.lookback_days), limit=500)

    seen: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        for key, value in event["observables"].items():
            if key == "port" or value is None:
                continue
            seen.setdefault(str(value).strip().lower(), []).append(event)
    matches = tb.match_indicators(list(seen)) if seen else []
    for ind in matches:
        malicious = ind["verdict"] == "malicious"
        sightings = seen.get(ind["value"].lower(), [])
        out.findings.append(
            Finding(
                "intel",
                "intel.malicious_match" if malicious else "intel.suspicious_match",
                f"{ind['value']} is on your watchlist as {ind['verdict']}",
                "critical" if malicious else "medium",
                f"{ind['type']} rated {ind['verdict']} (source: {ind['source']}, confidence {ind['confidence']}); "
                f"seen in {len(sightings)} event(s).",
                [_ref("indicator", ind, ind["value"])] + [_ref("event", e) for e in sightings[:10]],
                {"value": ind["value"], "source": ind["source"]},
            )
        )
    if any(m["verdict"] == "malicious" for m in matches):
        points = weight
    elif matches:
        points = round(weight / 2)
    else:
        points = 0
    window = "the triggering event" if ctx.subject_type == "alert" else f"the last {ctx.lookback_days} days"
    out.factors["threat_intel"] = FactorResult(
        points,
        f"{len(seen)} observable(s) from {window} checked against the watchlist: {len(matches)} match(es)."
        if seen
        else f"No observables (IPs, domains, hashes, users) in {window}.",
        bool(seen),
    )

    if ctx.subject_type == "organization":
        recent = tb.recent_investigations(since=tb.since(days=ctx.lookback_days), verdicts=("malicious",))
        if recent:
            out.findings.append(
                Finding(
                    "intel",
                    "intel.recent_malicious",
                    f"{len(recent)} malicious investigation result(s) recently",
                    "medium",
                    "; ".join(f"{i['subject_type']}: {i['subject']}" for i in recent[:5]),
                    [
                        {"type": "investigation", "id": i["id"], "label": i["subject"][:160]}
                        for i in recent[:10]
                    ],
                )
            )
    return out


# --------------------------------------------------------------------------- posture agent
def run_posture(ctx: Context, tb: Toolbox) -> AgentResult:
    out = AgentResult()
    summary = tb.active_alert_summary()
    by = summary["by_severity"]
    per = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    total = sum(by.values())
    breakdown = ", ".join(f"{by[s]} {s}" for s in reversed(SEVERITY_ORDER) if by.get(s))
    out.factors["open_alerts"] = FactorResult(
        min(_weight("organization", "open_alerts"), sum(per.get(s, 0) * n for s, n in by.items())),
        f"{total} open/acknowledged alert(s){': ' + breakdown if breakdown else ''}.",
    )
    if total:
        out.findings.append(
            Finding(
                "posture",
                "posture.active_alerts",
                f"{total} active alert(s)",
                _max_severity([s for s, n in by.items() if n]),
                breakdown,
                [],
                {"count": total},
            )
        )

    stale = summary["stale_open"]
    out.factors["stale_alerts"] = FactorResult(
        min(_weight("organization", "stale_alerts"), 2 * len(stale)),
        f"{len(stale)} alert(s) open and unacknowledged for more than 24 hours.",
    )
    if stale:
        out.findings.append(
            Finding(
                "posture",
                "posture.stale_alerts",
                f"{len(stale)} alert(s) open for more than 24 hours",
                "medium",
                "; ".join(a["title"] for a in stale[:5]),
                [_ref("alert", a) for a in stale[:10]],
                {"count": len(stale)},
            )
        )

    fleet = tb.fleet()
    weight = _weight("organization", "device_fleet")
    if not fleet:
        out.factors["device_fleet"] = FactorResult(0, "No enrolled devices.", has_data=False)
        out.findings.append(
            Finding(
                "posture",
                "posture.no_devices",
                "No enrolled devices",
                "info",
                "Device health cannot be assessed until devices are enrolled.",
            )
        )
        return out
    down = [d for d in fleet if d["status"] in ("offline", "degraded")]
    share = len(down) / len(fleet)
    out.factors["device_fleet"] = FactorResult(
        round(weight * share), f"{len(down)} of {len(fleet)} enrolled device(s) offline or degraded."
    )
    if down:
        out.findings.append(
            Finding(
                "posture",
                "posture.devices_down",
                f"{len(down)} of {len(fleet)} device(s) offline or degraded",
                "high" if share >= 0.5 else "medium",
                ", ".join(f"{d['name']} ({d['status']})" for d in down[:10]),
                [_ref("device", d) for d in down[:10]],
                {"count": len(down)},
            )
        )
    return out


AGENTS: dict[str, AgentSpec] = {
    spec.name: spec
    for spec in (
        AgentSpec(
            "triage",
            "Alert Triage Agent",
            "Rates the detection, looks for repeats and related alerts on the same device, and sets a priority.",
            ("alert",),
            ("alerts.for_device",),
            run_triage,
        ),
        AgentSpec(
            "device",
            "Device Risk Agent",
            "Assesses a device's status, health telemetry, credential age, open alerts and event activity.",
            ("alert", "device"),
            ("alerts.for_device", "events.volume"),
            run_device,
        ),
        AgentSpec(
            "exposure",
            "Network Exposure Agent",
            "Finds risky services (Telnet, SMB, RDP, databases, backdoor ports) in agent port reports and "
            "imported scans, and assets outside authorized scopes.",
            ("alert", "device", "organization"),
            ("network.asset_for_device", "network.assets"),
            run_exposure,
        ),
        AgentSpec(
            "intel",
            "Threat-Intel Correlation Agent",
            "Matches IPs, domains, hashes and users seen in events against your watchlist indicators.",
            ("alert", "device", "organization"),
            ("events.recent", "intel.match_indicators", "intel.recent_investigations"),
            run_intel,
        ),
        AgentSpec(
            "posture",
            "Security Posture Agent",
            "Summarises the alert backlog and fleet health of the whole organization.",
            ("organization",),
            ("alerts.active_summary", "devices.fleet"),
            run_posture,
        ),
    )
}
