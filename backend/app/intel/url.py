"""URL analysis: structural heuristics + domain intelligence + URLhaus. The URL is never fetched."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import unquote, urlsplit

from app.intel import domain as domain_intel
from app.intel import providers
from app.intel.findings import Analysis, Finding
from app.intel.lookalike import decode_idna, registrable_domain

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "work",
    "support",
    "rest",
    "cam",
    "icu",
    "sbs",
    "cfd",
    "quest",
    "monster",
    "buzz",
}
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
    "s.id",
}
RISKY_EXTENSIONS = (
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".apk",
    ".iso",
    ".img",
    ".lnk",
    ".hta",
    ".jar",
    ".dll",
)
KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "wallet",
    "password",
    "reset",
    "invoice",
    "payment",
    "bank",
    "unlock",
    "suspended",
    "confirm",
)
MAX_URL_LENGTH = 2048


def parse(raw: str) -> tuple[str, object]:
    url = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", url):
        url = "http://" + url
    return url, urlsplit(url)


def heuristics(analysis: Analysis, raw: str, prefix: str = "") -> str | None:
    """Structural checks. Returns the host (lower-cased) if there is one."""
    url, parts = parse(raw)
    scheme = parts.scheme.lower()
    analysis.details.setdefault(
        "url",
        {
            "normalized": url,
            "scheme": scheme,
            "host": parts.hostname,
            "port": parts.port if parts.port else None,
            "path": parts.path,
        },
    )
    p = prefix

    if scheme in ("javascript", "data", "vbscript", "file"):
        analysis.add(
            Finding(
                f"{p}dangerous_scheme",
                f"{scheme}: URL",
                "Scripts or local resources in links are a classic attack vector.",
                "critical",
                60,
                "heuristic",
            )
        )
        return None
    if scheme not in ("http", "https"):
        analysis.add(
            Finding(
                f"{p}unusual_scheme",
                f"Unusual scheme “{scheme}”",
                "Only http(s) links are expected in normal messages.",
                "medium",
                15,
                "heuristic",
            )
        )
    if scheme == "http":
        analysis.add(
            Finding(
                f"{p}no_tls",
                "Not encrypted (http://)",
                "Credentials entered on this page would travel in clear text.",
                "low",
                5,
                "heuristic",
            )
        )
    if len(url) > 120:
        analysis.add(
            Finding(
                f"{p}long_url",
                f"Very long URL ({len(url)} characters)",
                "Long URLs are often used to hide the real destination.",
                "low",
                5,
                "heuristic",
            )
        )
    if parts.username or parts.password or "@" in parts.netloc:
        analysis.add(
            Finding(
                f"{p}userinfo",
                "Text before “@” in the address",
                "Browsers ignore everything before “@”: the real host is what follows it.",
                "high",
                30,
                "heuristic",
            )
        )

    host = (parts.hostname or "").lower()
    if not host:
        return None
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
        analysis.add(
            Finding(
                f"{p}ip_host",
                "Raw IP address instead of a domain",
                "Legitimate services almost always use a domain name.",
                "medium",
                20,
                "heuristic",
                data={"ip": host},
            )
        )
    except ValueError:
        pass

    decoded = decode_idna(host)
    if is_ip:
        _path_checks(analysis, parts, decoded, p)
        return host
    if "xn--" in host:
        analysis.add(
            Finding(
                f"{p}punycode",
                "Internationalised (punycode) domain",
                f"Displayed as “{decoded}”: characters from other alphabets can imitate familiar names.",
                "medium",
                20,
                "heuristic",
                data={"decoded": decoded},
            )
        )
    elif not host.isascii():
        analysis.add(
            Finding(
                f"{p}non_ascii",
                "Non-ASCII characters in the domain",
                "May be used to imitate a familiar name.",
                "medium",
                15,
                "heuristic",
            )
        )
    reg = registrable_domain(decoded)
    tld = reg.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        analysis.add(
            Finding(
                f"{p}suspicious_tld",
                f"High-abuse top-level domain “.{tld}”",
                "This TLD is disproportionately used for phishing and malware.",
                "medium",
                15,
                "heuristic",
            )
        )
    sub_labels = decoded[: -len(reg)].strip(".").split(".") if decoded != reg else []
    if len([s for s in sub_labels if s]) >= 3:
        analysis.add(
            Finding(
                f"{p}deep_subdomains",
                "Many sub-domains",
                f"{decoded} — long sub-domain chains are used to push the real domain out of view.",
                "low",
                10,
                "heuristic",
            )
        )
    if decoded.count("-") >= 3:
        analysis.add(
            Finding(
                f"{p}hyphens",
                "Many hyphens in the host",
                "Common in throw-away phishing domains.",
                "low",
                10,
                "heuristic",
            )
        )
    if reg in SHORTENERS or decoded in SHORTENERS:
        analysis.add(
            Finding(
                f"{p}shortener",
                "Link shortener",
                "The real destination is hidden until clicked.",
                "medium",
                10,
                "heuristic",
            )
        )
    if parts.port and parts.port not in (80, 443):
        analysis.add(
            Finding(
                f"{p}port",
                f"Non-standard port {parts.port}",
                "Unusual for public websites.",
                "low",
                10,
                "heuristic",
            )
        )

    _path_checks(analysis, parts, decoded, p)
    return host


def _path_checks(analysis: Analysis, parts: Any, decoded: str, p: str) -> None:
    path = unquote(parts.path + "?" + parts.query).lower()
    hits = sorted({k for k in KEYWORDS if k in path or k in decoded})
    if hits:
        analysis.add(
            Finding(
                f"{p}keywords",
                "Credential/payment lure words",
                ", ".join(hits),
                "low",
                min(15, 5 * len(hits)),
                "heuristic",
                data={"keywords": hits},
            )
        )
    filename = parts.path.rsplit("/", 1)[-1].lower()
    if filename.endswith(RISKY_EXTENSIONS):
        double = re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.[a-z0-9]+$", filename)
        analysis.add(
            Finding(
                f"{p}executable_download",
                "Executable download" + (" with a disguised extension" if double else ""),
                f"“{filename}” would run code on the device.",
                "high",
                35 if double else 25,
                "heuristic",
            )
        )
    if (parts.path + parts.query).count("%") > 10:
        analysis.add(
            Finding(
                f"{p}encoded",
                "Heavily percent-encoded",
                "Encoding is used to hide words from filters.",
                "low",
                5,
                "heuristic",
            )
        )


def analyze(raw: str) -> Analysis:
    analysis = Analysis(subject_type="url", subject=raw.strip())
    if len(raw) > MAX_URL_LENGTH:
        raise ValueError(f"URL longer than {MAX_URL_LENGTH} characters")
    host = heuristics(analysis, raw)
    url, _ = parse(raw)
    analysis.indicators.append(("url", url))
    providers.urlhaus_url(analysis, url)
    if host:
        try:
            ipaddress.ip_address(host.strip("[]"))
            analysis.indicators.append(("ipv4" if ":" not in host else "ipv6", host.strip("[]")))
        except ValueError:
            analysis.indicators.append(("domain", decode_idna(host)))
            domain_intel.enrich(analysis, decode_idna(host), include_urlhaus=False)
    return analysis
