"""IP address analysis: address classification, RDAP ownership, AbuseIPDB, VirusTotal."""

from __future__ import annotations

import ipaddress

from app.intel import providers
from app.intel.addresses import classify
from app.intel.findings import Analysis, Finding, SourceCheck


def analyze(raw: str) -> Analysis:
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise ValueError("enter a valid IPv4 or IPv6 address") from None
    ip = str(addr)
    analysis = Analysis(subject_type="ip", subject=ip)
    analysis.indicators.append(("ipv4" if addr.version == 4 else "ipv6", ip))
    analysis.details["address"] = {
        "version": addr.version,
        "class": classify(addr),
        "global": addr.is_global,
    }

    kind = classify(addr)
    if kind != "public":
        analysis.add(
            Finding(
                "non_public",
                f"{kind.capitalize()} address",
                "Not routable on the internet: public reputation "
                "services do not apply. Investigate the internal host instead.",
                "info",
                0,
                "heuristic",
                "context",
            )
        )
        analysis.checks.append(SourceCheck("reputation", "skipped", f"{kind} address"))
        return analysis

    providers.rdap_ip(analysis, ip)
    providers.abuseipdb(analysis, ip)
    providers.virustotal(analysis, "ip", ip)
    return analysis
