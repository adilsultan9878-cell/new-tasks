"""Adapters for external intelligence sources. Each records a SourceCheck (consulted, not
configured, or unavailable) so the investigation shows exactly what was and was not checked."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.intel.client import IntelUnavailable, allowlist, request_json
from app.intel.findings import Analysis, Finding, SourceCheck

PROVIDERS: list[dict[str, Any]] = [
    {
        "key": "heuristics",
        "name": "Deterministic checks",
        "covers": ["url", "domain", "email", "ip", "hash"],
        "requires_key": None,
        "url": None,
    },
    {
        "key": "rdap",
        "name": "RDAP registries (via IANA bootstrap)",
        "covers": ["domain", "ip", "url"],
        "requires_key": None,
        "url": "https://about.rdap.org/",
    },
    {
        "key": "dns",
        "name": "DNS over HTTPS (Cloudflare)",
        "covers": ["domain", "url"],
        "requires_key": None,
        "url": "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
    },
    {
        "key": "cisa_kev",
        "name": "CISA Known Exploited Vulnerabilities",
        "covers": ["cve"],
        "requires_key": None,
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    },
    {
        "key": "nvd",
        "name": "NIST National Vulnerability Database",
        "covers": ["cve"],
        "requires_key": None,
        "optional_key": "NVD_API_KEY",
        "url": "https://nvd.nist.gov/developers/request-an-api-key",
    },
    {
        "key": "urlhaus",
        "name": "abuse.ch URLhaus",
        "covers": ["url", "domain"],
        "requires_key": "ABUSECH_AUTH_KEY",
        "url": "https://auth.abuse.ch/",
    },
    {
        "key": "malwarebazaar",
        "name": "abuse.ch MalwareBazaar",
        "covers": ["hash"],
        "requires_key": "ABUSECH_AUTH_KEY",
        "url": "https://auth.abuse.ch/",
    },
    {
        "key": "abuseipdb",
        "name": "AbuseIPDB",
        "covers": ["ip"],
        "requires_key": "ABUSEIPDB_API_KEY",
        "url": "https://www.abuseipdb.com/register",
    },
    {
        "key": "virustotal",
        "name": "VirusTotal",
        "covers": ["hash", "ip", "domain"],
        "requires_key": "VIRUSTOTAL_API_KEY",
        "url": "https://www.virustotal.com/gui/join-us",
    },
]


def _key(name: str) -> str:
    s = get_settings()
    return {
        "ABUSECH_AUTH_KEY": s.abusech_auth_key,
        "ABUSEIPDB_API_KEY": s.abuseipdb_api_key,
        "VIRUSTOTAL_API_KEY": s.virustotal_api_key,
        "NVD_API_KEY": s.nvd_api_key,
    }.get(name, "")


def provider_status() -> list[dict[str, Any]]:
    offline = get_settings().intel_offline
    out = []
    for p in PROVIDERS:
        configured = p["requires_key"] is None or bool(_key(p["requires_key"]))
        out.append(
            {
                **p,
                "configured": configured,
                "enabled": configured and (not offline or p["key"] == "heuristics"),
            }
        )
    return out


def _run(analysis: Analysis, source: str, fn: Callable[[], str], key_env: str | None = None) -> None:
    """Execute one provider call and record its SourceCheck."""
    if key_env and not _key(key_env):
        analysis.checks.append(SourceCheck(source, "not_configured", f"set {key_env} to enable"))
        return
    started = time.perf_counter()
    try:
        detail = fn()
        status = "ok"
    except IntelUnavailable as exc:
        detail, status = str(exc), "unavailable"
    analysis.checks.append(SourceCheck(source, status, detail, int((time.perf_counter() - started) * 1000)))


# ------------------------------------------------------------------------------------- URLhaus
def urlhaus_url(analysis: Analysis, url: str) -> None:
    def call() -> str:
        _, body = request_json(
            "POST",
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": _key("ABUSECH_AUTH_KEY")},
        )
        if body.get("query_status") == "ok":
            analysis.add(
                Finding(
                    "urlhaus_listed",
                    "Listed on URLhaus as a malware distribution URL",
                    f"Threat: {body.get('threat') or 'malware'} · status {body.get('url_status')} · tags "
                    f"{', '.join(body.get('tags') or []) or 'none'} · added {body.get('date_added')}",
                    "critical",
                    90,
                    "urlhaus",
                    "intel",
                    data={"reference": body.get("urlhaus_reference"), "threat": body.get("threat")},
                )
            )
            return "listed"
        return "not listed"

    _run(analysis, "urlhaus", call, "ABUSECH_AUTH_KEY")


def urlhaus_host(analysis: Analysis, host: str) -> None:
    def call() -> str:
        _, body = request_json(
            "POST",
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": host},
            headers={"Auth-Key": _key("ABUSECH_AUTH_KEY")},
        )
        if body.get("query_status") == "ok" and int(body.get("url_count") or 0) > 0:
            analysis.add(
                Finding(
                    "urlhaus_host",
                    f"Host has served malware ({body.get('url_count')} URLs on URLhaus)",
                    f"First seen {body.get('firstseen')}",
                    "high",
                    70,
                    "urlhaus",
                    "intel",
                    data={"reference": body.get("urlhaus_reference")},
                )
            )
            return "listed"
        return "not listed"

    _run(analysis, "urlhaus", call, "ABUSECH_AUTH_KEY")


# ---------------------------------------------------------------------------- MalwareBazaar
def malwarebazaar(analysis: Analysis, file_hash: str) -> None:
    def call() -> str:
        _, body = request_json(
            "POST",
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": file_hash},
            headers={"Auth-Key": _key("ABUSECH_AUTH_KEY")},
        )
        if body.get("query_status") == "ok" and body.get("data"):
            d = body["data"][0]
            analysis.add(
                Finding(
                    "malwarebazaar_known",
                    f"Known malware sample: {d.get('signature') or 'unclassified'}",
                    f"{d.get('file_type')} · first seen {d.get('first_seen')} · tags {', '.join(d.get('tags') or []) or 'none'}",
                    "critical",
                    95,
                    "malwarebazaar",
                    "intel",
                    data={
                        "signature": d.get("signature"),
                        "file_name": d.get("file_name"),
                        "sha256": d.get("sha256_hash"),
                    },
                )
            )
            analysis.details["sample"] = {
                k: d.get(k) for k in ("file_name", "file_type", "file_size", "signature", "first_seen")
            }
            return "known sample"
        return "not found"

    _run(analysis, "malwarebazaar", call, "ABUSECH_AUTH_KEY")


# -------------------------------------------------------------------------------- AbuseIPDB
def abuseipdb(analysis: Analysis, ip: str) -> None:
    def call() -> str:
        _, body = request_json(
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": _key("ABUSEIPDB_API_KEY")},
        )
        d = body.get("data") or {}
        score = int(d.get("abuseConfidenceScore") or 0)
        analysis.details["abuseipdb"] = {
            k: d.get(k)
            for k in (
                "abuseConfidenceScore",
                "totalReports",
                "countryCode",
                "usageType",
                "isp",
                "domain",
                "lastReportedAt",
            )
        }
        if score >= 75:
            analysis.add(
                Finding(
                    "abuseipdb_high",
                    f"AbuseIPDB confidence of abuse {score}%",
                    f"{d.get('totalReports')} reports in 90 days",
                    "high",
                    80,
                    "abuseipdb",
                    "intel",
                )
            )
        elif score >= 25:
            analysis.add(
                Finding(
                    "abuseipdb_medium",
                    f"AbuseIPDB confidence of abuse {score}%",
                    f"{d.get('totalReports')} reports in 90 days",
                    "medium",
                    40,
                    "abuseipdb",
                    "intel",
                )
            )
        return f"confidence {score}%"

    _run(analysis, "abuseipdb", call, "ABUSEIPDB_API_KEY")


# ------------------------------------------------------------------------------- VirusTotal
def virustotal(analysis: Analysis, kind: str, value: str) -> None:
    path = {"hash": f"files/{value}", "ip": f"ip_addresses/{value}", "domain": f"domains/{value}"}[kind]

    def call() -> str:
        try:
            _, body = request_json(
                "GET",
                f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": _key("VIRUSTOTAL_API_KEY")},
            )
        except IntelUnavailable as exc:
            if "HTTP 404" in str(exc):
                return "not found"
            raise
        stats = ((body.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        total = sum(int(v) for v in stats.values() if isinstance(v, int))
        analysis.details["virustotal"] = stats
        if malicious >= 5:
            analysis.add(
                Finding(
                    "virustotal_malicious",
                    f"{malicious}/{total} VirusTotal engines flag it",
                    "Multi-engine consensus",
                    "high",
                    80,
                    "virustotal",
                    "intel",
                )
            )
        elif malicious >= 1:
            analysis.add(
                Finding(
                    "virustotal_some",
                    f"{malicious}/{total} VirusTotal engines flag it",
                    "Low consensus — review manually",
                    "medium",
                    30,
                    "virustotal",
                    "intel",
                )
            )
        return f"{malicious}/{total} malicious"

    _run(analysis, "virustotal", call, "VIRUSTOTAL_API_KEY")


# ------------------------------------------------------------------------- RDAP (no key)
_bootstrap: dict[str, tuple[float, dict[str, Any]]] = {}
_bootstrap_lock = threading.Lock()


def _iana(kind: str) -> dict[str, Any]:
    with _bootstrap_lock:
        cached = _bootstrap.get(kind)
        if cached and time.time() - cached[0] < 86_400:
            return cached[1]
    _, body = request_json("GET", f"https://data.iana.org/rdap/{kind}.json")
    with _bootstrap_lock:
        _bootstrap[kind] = (time.time(), body)
    return body


def _rdap_base_for_tld(tld: str) -> str | None:
    for tlds, urls in _iana("dns").get("services", []):
        if tld in tlds:
            return next((u for u in urls if u.startswith("https://")), None)
    return None


def _rdap_base_for_ip(ip: str) -> str | None:
    import ipaddress

    addr = ipaddress.ip_address(ip)
    data = _iana("ipv4" if addr.version == 4 else "ipv6")
    for prefixes, urls in data.get("services", []):
        if any(addr in ipaddress.ip_network(p, strict=False) for p in prefixes):
            return next((u for u in urls if u.startswith("https://")), None)
    return None


def _rdap_get(base: str, path: str) -> dict[str, Any]:
    host = urlsplit(base).hostname or ""
    allowlist.allow(host)  # base URLs come from IANA's bootstrap file, not from user input
    _, body = request_json("GET", base.rstrip("/") + "/" + path, accept_status=(200,))
    return body


def _event_date(body: dict[str, Any], action: str) -> datetime | None:
    for ev in body.get("events") or []:
        if ev.get("eventAction") == action and ev.get("eventDate"):
            try:
                return datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


def rdap_domain(analysis: Analysis, domain: str) -> None:
    def call() -> str:
        tld = domain.rsplit(".", 1)[-1]
        base = _rdap_base_for_tld(tld)
        if base is None:
            raise IntelUnavailable(f"no RDAP service published for .{tld}")
        try:
            body = _rdap_get(base, f"domain/{domain}")
        except IntelUnavailable as exc:
            if "HTTP 404" not in str(exc):
                raise
            analysis.details["rdap"] = {"domain": domain, "registered": None, "not_registered": True}
            analysis.add(
                Finding(
                    "not_registered",
                    "Domain is not registered",
                    "The registry has no record of it: a link to it cannot belong to a legitimate service.",
                    "medium",
                    20,
                    "rdap",
                    "intel",
                )
            )
            return "not registered"
        created = _event_date(body, "registration")
        registrar = next(
            (
                (e.get("vcardArray") or [None, []])[1]
                for e in body.get("entities") or []
                if "registrar" in (e.get("roles") or [])
            ),
            None,
        )
        registrar_name = None
        if registrar:
            registrar_name = next((v[3] for v in registrar if v and v[0] == "fn"), None)
        analysis.details["rdap"] = {
            "domain": domain,
            "registered": created.isoformat() if created else None,
            "registrar": registrar_name,
            "status": body.get("status"),
        }
        if created:
            age = (datetime.now(UTC) - created).days
            if age < 30:
                analysis.add(
                    Finding(
                        "new_domain",
                        f"Domain registered {age} days ago",
                        f"Registered {created.date()} — newly registered domains are a strong phishing signal.",
                        "high",
                        30,
                        "rdap",
                        "intel",
                        data={"age_days": age},
                    )
                )
            elif age < 180:
                analysis.add(
                    Finding(
                        "young_domain",
                        f"Domain is only {age} days old",
                        f"Registered {created.date()}.",
                        "low",
                        10,
                        "rdap",
                        "intel",
                        data={"age_days": age},
                    )
                )
            else:
                analysis.add(
                    Finding(
                        "domain_age",
                        f"Domain registered {created.date()} ({age // 365} years ago)",
                        f"Registrar: {registrar_name or 'unknown'}",
                        "info",
                        0,
                        "rdap",
                        "context",
                    )
                )
        return "registered " + (created.date().isoformat() if created else "date unknown")

    _run(analysis, "rdap", call)


def rdap_ip(analysis: Analysis, ip: str) -> None:
    def call() -> str:
        base = _rdap_base_for_ip(ip)
        if base is None:
            raise IntelUnavailable("no RDAP service for this address")
        body = _rdap_get(base, f"ip/{ip}")
        info = {
            "name": body.get("name"),
            "handle": body.get("handle"),
            "country": body.get("country"),
            "range": f"{body.get('startAddress')} – {body.get('endAddress')}",
        }
        analysis.details["rdap"] = info
        analysis.add(
            Finding(
                "ip_owner",
                f"Network {info['name'] or info['handle']}",
                f"{info['range']} · country {info['country'] or 'unknown'}",
                "info",
                0,
                "rdap",
                "context",
            )
        )
        return info["name"] or "ok"

    _run(analysis, "rdap", call)


# ------------------------------------------------------------------------------- DNS (DoH)
def dns(analysis: Analysis, domain: str) -> None:
    def call() -> str:
        answers: dict[str, list[str]] = {}
        nxdomain = False
        for rtype in ("A", "AAAA", "MX"):
            _, body = request_json(
                "GET",
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": rtype},
                headers={"accept": "application/dns-json"},
            )
            if body.get("Status") == 3:
                nxdomain = True
                break
            answers[rtype] = [a.get("data") for a in body.get("Answer") or [] if a.get("data")][:10]
        analysis.details["dns"] = {"nxdomain": nxdomain, **answers}
        if nxdomain:
            analysis.add(
                Finding(
                    "nxdomain",
                    "Domain does not resolve (NXDOMAIN)",
                    "Taken down, not yet active, or a typo.",
                    "medium",
                    10,
                    "dns",
                    "intel",
                )
            )
            return "NXDOMAIN"
        return f"{len(answers.get('A', []))} A record(s)"

    _run(analysis, "dns", call)
