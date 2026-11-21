"""Email analysis from pasted headers (and optional body). Links are analysed, never opened."""

from __future__ import annotations

import re
from email import policy
from email.parser import Parser
from email.utils import getaddresses, parseaddr

from app.intel import providers
from app.intel import url as url_intel
from app.intel.findings import Analysis, Finding
from app.intel.lookalike import BRANDS, check_host, registrable_domain

MAX_BYTES = 200_000
URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
RISKY_ATTACHMENTS = re.compile(
    r"\.(exe|scr|js|jse|vbs|vbe|bat|cmd|ps1|msi|hta|iso|img|lnk|jar|docm|xlsm|pptm|one)$", re.I
)
URGENCY = (
    "urgent",
    "immediately",
    "suspended",
    "verify",
    "action required",
    "final notice",
    "password",
    "invoice",
    "payment",
    "unusual activity",
    "locked",
    "confirm your",
)


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(">") if "@" in address else ""


def _auth_results(headers: list[str]) -> dict[str, str]:
    results: dict[str, str] = {}
    for header in headers:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", header, re.I)
            if m and mech not in results:
                results[mech] = m.group(1).lower()
    return results


def analyze(raw: str) -> Analysis:
    if len(raw.encode("utf-8", "ignore")) > MAX_BYTES:
        raise ValueError("email source larger than 200 KB")
    if not re.search(r"^(from|subject|received|return-path):", raw, re.I | re.M):
        raise ValueError(
            "paste the full message headers (they start with lines such as “Received:” and “From:”)"
        )
    msg = Parser(policy=policy.default).parsestr(raw)
    display, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = _domain(from_addr)
    reply_dom = _domain(parseaddr(str(msg.get("Reply-To", "")))[1])
    return_dom = _domain(parseaddr(str(msg.get("Return-Path", "")))[1])
    subject = str(msg.get("Subject", ""))
    received = msg.get_all("Received") or []
    auth = _auth_results([str(h) for h in (msg.get_all("Authentication-Results") or [])])

    analysis = Analysis(subject_type="email", subject=f"{from_addr or 'unknown sender'} — {subject[:120]}")
    analysis.details["email"] = {
        "from": from_addr,
        "display_name": display,
        "reply_to_domain": reply_dom or None,
        "return_path_domain": return_dom or None,
        "subject": subject[:300],
        "received_hops": len(received),
        "authentication": auth,
    }
    if from_addr:
        analysis.indicators.append(("email", from_addr.lower()))
    if from_dom:
        analysis.indicators.append(("domain", from_dom))

    for mech, weight in (("spf", 20), ("dkim", 20), ("dmarc", 30)):
        result = auth.get(mech)
        if result in ("fail", "permerror"):
            analysis.add(
                Finding(
                    f"{mech}_fail",
                    f"{mech.upper()} failed",
                    "The receiving server could not verify the sender.",
                    "high",
                    weight,
                    "heuristic",
                )
            )
        elif result in ("softfail", "none", "neutral", "temperror"):
            analysis.add(
                Finding(
                    f"{mech}_weak",
                    f"{mech.upper()} result “{result}”",
                    "Sender authentication is not conclusive.",
                    "medium",
                    weight // 2,
                    "heuristic",
                )
            )
        elif result == "pass":
            analysis.add(
                Finding(
                    f"{mech}_pass",
                    f"{mech.upper()} passed",
                    "Authenticated for the sending domain (which may still be a look-alike).",
                    "info",
                    0,
                    "heuristic",
                    "context",
                )
            )
    if not auth:
        analysis.add(
            Finding(
                "no_auth_results",
                "No Authentication-Results header",
                "Include the full headers from your mail client to evaluate SPF/DKIM/DMARC.",
                "info",
                0,
                "heuristic",
                "context",
            )
        )

    if reply_dom and from_dom and registrable_domain(reply_dom) != registrable_domain(from_dom):
        analysis.add(
            Finding(
                "reply_to_mismatch",
                "Replies go to a different domain",
                f"From {from_dom}, Reply-To {reply_dom}.",
                "medium",
                20,
                "heuristic",
            )
        )
    if return_dom and from_dom and registrable_domain(return_dom) != registrable_domain(from_dom):
        analysis.add(
            Finding(
                "return_path_mismatch",
                "Bounce address on a different domain",
                f"Return-Path {return_dom}.",
                "low",
                5,
                "heuristic",
            )
        )
    shown = [a for _, a in getaddresses([display]) if "@" in a]
    if shown and shown[0].lower() != from_addr.lower():
        analysis.add(
            Finding(
                "display_spoof",
                "Display name shows a different address",
                f"Shows “{shown[0]}”, actually {from_addr}.",
                "high",
                30,
                "heuristic",
            )
        )
    brand_in_name = next((b for b in BRANDS if b in display.lower().replace(" ", "")), None)
    if brand_in_name and from_dom and registrable_domain(from_dom) not in BRANDS[brand_in_name]:
        analysis.add(
            Finding(
                "display_brand",
                f"Sender name claims to be {brand_in_name}",
                f"but the address is on {from_dom}.",
                "high",
                30,
                "heuristic",
            )
        )
    if from_dom:
        for m in check_host(from_dom):
            analysis.add(
                Finding(
                    "sender_lookalike",
                    f"Sender domain imitates {m['brand']}",
                    f"{from_dom} vs {m['official']}",
                    "high",
                    35,
                    "heuristic",
                    data=m,
                )
            )
    lures = sorted({w for w in URGENCY if w in subject.lower()})
    if lures:
        analysis.add(
            Finding(
                "urgency",
                "Pressure/lure words in the subject",
                ", ".join(lures),
                "low",
                min(10, 5 * len(lures)),
                "heuristic",
            )
        )

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename and RISKY_ATTACHMENTS.search(filename):
                analysis.add(
                    Finding(
                        "risky_attachment",
                        "Executable or macro attachment",
                        filename,
                        "high",
                        35,
                        "heuristic",
                        data={"filename": filename},
                    )
                )
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    body += str(part.get_content())
                except (LookupError, ValueError):
                    continue
    else:
        try:
            body = str(msg.get_content())
        except (LookupError, ValueError):
            body = msg.get_payload() or ""

    links = list(dict.fromkeys(URL_RE.findall(body)))[:20]
    analysis.details["links"] = links
    for i, link in enumerate(links):
        before = len(analysis.findings)
        url_intel.heuristics(analysis, link, prefix=f"link{i}_")
        for f in analysis.findings[before:]:
            f.title = f"Link: {f.title}"
            f.data = {**f.data, "link": link}
        analysis.indicators.append(("url", link))
        if i < 5:
            providers.urlhaus_url(analysis, link)
    return analysis
