"""File-hash analysis. Files are never uploaded or executed; only the hash is looked up."""

from __future__ import annotations

import re

from app.intel import providers
from app.intel.findings import Analysis, Finding

TYPES = {32: "md5", 40: "sha1", 64: "sha256"}


def normalize(raw: str) -> tuple[str, str]:
    value = raw.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", value) or len(value) not in TYPES:
        raise ValueError("enter an MD5 (32), SHA-1 (40) or SHA-256 (64) hex digest")
    return TYPES[len(value)], value


def analyze(raw: str) -> Analysis:
    kind, value = normalize(raw)
    analysis = Analysis(subject_type="hash", subject=value)
    analysis.indicators.append((kind, value))
    analysis.details["hash"] = {"type": kind}
    if kind == "md5":
        analysis.add(
            Finding(
                "weak_hash",
                "MD5 identifies, but cannot prove, a file",
                "Prefer SHA-256 when you can compute it.",
                "info",
                0,
                "heuristic",
                "context",
            )
        )
    providers.malwarebazaar(analysis, value)
    providers.virustotal(analysis, "hash", value)
    return analysis
