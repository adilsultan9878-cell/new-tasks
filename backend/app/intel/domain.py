"""Domain analysis: look-alike checks, RDAP registration age, DNS, URLhaus/VirusTotal."""

from __future__ import annotations

import re

from app.intel import providers
from app.intel.findings import Analysis, Finding
from app.intel.lookalike import check_host, decode_idna, registrable_domain

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$")


def normalize(raw: str) -> str:
    value = raw.strip().lower().rstrip(".")
    if "://" in value or "/" in value or "@" in value:
        raise ValueError("enter a bare domain such as example.com")
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid domain") from None
    if not DOMAIN_RE.match(ascii_host):
        raise ValueError("invalid domain")
    return ascii_host


def lookalike_findings(analysis: Analysis, host: str) -> None:
    for m in check_host(host):
        if m["kind"] == "lookalike":
            analysis.add(
                Finding(
                    "lookalike",
                    f"Look-alike of {m['brand']}",
                    f"Resembles {m['official']} but is a different domain.",
                    "high",
                    40,
                    "heuristic",
                    data=m,
                )
            )
        else:
            analysis.add(
                Finding(
                    "brand_in_domain",
                    f"Uses the brand “{m['brand']}”",
                    f"The official domain is {m['official']}; this one is not owned by the brand.",
                    "high",
                    35,
                    "heuristic",
                    data=m,
                )
            )


def enrich(analysis: Analysis, host: str, include_urlhaus: bool = True) -> None:
    lookalike_findings(analysis, host)
    reg = registrable_domain(decode_idna(host))
    analysis.details.setdefault("domain", {"host": host, "registrable": reg})
    providers.rdap_domain(analysis, host.encode("idna").decode("ascii") if not host.isascii() else reg)
    providers.dns(analysis, host)
    if include_urlhaus:
        providers.urlhaus_host(analysis, host)


def analyze(raw: str) -> Analysis:
    host = normalize(raw)
    analysis = Analysis(subject_type="domain", subject=host)
    analysis.indicators.append(("domain", host))
    enrich(analysis, host)
    providers.virustotal(analysis, "domain", host)
    return analysis
