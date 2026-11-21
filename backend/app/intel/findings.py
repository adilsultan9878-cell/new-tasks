from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Kind = Literal["intel", "heuristic", "context"]
Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    code: str
    title: str
    detail: str
    severity: Severity
    score: int  # contribution to the 0-100 risk score
    source: str  # e.g. "urlhaus", "rdap", "heuristic", "cisa_kev"
    kind: Kind = "heuristic"
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SourceCheck:
    source: str
    status: Literal["ok", "not_configured", "unavailable", "skipped"]
    detail: str
    duration_ms: int = 0


@dataclass
class Analysis:
    subject_type: str
    subject: str
    findings: list[Finding] = field(default_factory=list)
    checks: list[SourceCheck] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    indicators: list[tuple[str, str]] = field(default_factory=list)  # (indicator_type, value)

    def add(self, finding: Finding) -> None:
        if not any(f.code == finding.code and f.data == finding.data for f in self.findings):
            self.findings.append(finding)

    @property
    def risk_score(self) -> int:
        score = sum(f.score for f in self.findings)
        if any(f.kind == "intel" and f.severity in ("high", "critical") for f in self.findings):
            score = max(score, 85)
        return max(0, min(100, score))

    @property
    def verdict(self) -> str:
        if any(f.kind == "intel" and f.severity in ("high", "critical") for f in self.findings):
            return "malicious"
        risk = self.risk_score
        if risk >= 70:
            return "malicious"
        if risk >= 35:
            return "suspicious"
        # Absence of evidence is not evidence of safety: never claim "benign" by default.
        return "unknown"
