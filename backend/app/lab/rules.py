"""Research Lab rule language and evaluation (Phase 9).

A detection rule is data, never code: a list of conditions on event fields joined by *all* or *any*,
plus an optional threshold ("at least N matching events within M minutes, per device"). Nothing is
executed, imported or interpolated, so a rule cannot reach anything outside the dataset it is
evaluated on. Evaluation is deterministic: the same rule on the same dataset gives the same result.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

ENGINE_VERSION = "lab-1"
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
FIELDS = ("category", "event_type", "severity", "title", "source", "device")
LABELS = ("malicious", "benign")


class Condition(BaseModel):
    field: Literal["category", "event_type", "severity", "title", "source", "device"]
    op: Literal["eq", "ne", "in", "contains", "not_contains", "startswith", "gte", "lte"]
    value: str | list[str]

    @field_validator("value")
    @classmethod
    def _value(cls, v: str | list[str]) -> str | list[str]:
        if isinstance(v, list):
            if not 1 <= len(v) <= 50 or any(len(x) > 200 for x in v):
                raise ValueError("a list needs 1-50 values of at most 200 characters")
            return [x.strip().lower() for x in v]
        if not 1 <= len(v.strip()) <= 200:
            raise ValueError("value must be 1-200 characters")
        return v.strip().lower()

    @model_validator(mode="after")
    def _ops(self) -> Condition:
        if self.op == "in" and not isinstance(self.value, list):
            raise ValueError("'in' needs a list of values")
        if self.op != "in" and isinstance(self.value, list):
            raise ValueError(f"'{self.op}' needs a single value")
        if self.op in ("gte", "lte"):
            if self.field != "severity":
                raise ValueError("'at least' / 'at most' only work on severity")
            if self.value not in SEVERITY_ORDER:
                raise ValueError(f"severity must be one of {', '.join(SEVERITY_ORDER)}")
        return self


class Threshold(BaseModel):
    count: int = Field(ge=2, le=1000)
    within_minutes: int = Field(ge=1, le=1440)
    per_device: bool = True


class Rule(BaseModel):
    mode: Literal["all", "any"] = "all"
    conditions: list[Condition] = Field(min_length=1, max_length=20)
    threshold: Threshold | None = None

    def digest(self) -> str:
        return hashlib.sha256(canonical(self.model_dump(mode="json")).encode()).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _matches(row: dict[str, Any], c: Condition) -> bool:
    actual = str(row.get(c.field) or "").lower()
    v = c.value
    if c.op == "eq":
        return actual == v
    if c.op == "ne":
        return actual != v
    if c.op == "in":
        return actual in v
    if c.op == "contains":
        return isinstance(v, str) and v in actual
    if c.op == "not_contains":
        return isinstance(v, str) and v not in actual
    if c.op == "startswith":
        return isinstance(v, str) and actual.startswith(v)
    rank = SEVERITY_ORDER.index(actual) if actual in SEVERITY_ORDER else -1
    target = SEVERITY_ORDER.index(v) if isinstance(v, str) else 99
    return rank >= target if c.op == "gte" else 0 <= rank <= target


def evaluate(rule: Rule, rows: list[dict[str, Any]]) -> list[bool]:
    """Which rows the rule fires on. Rows must be in time order (datasets are stored that way)."""
    combine = all if rule.mode == "all" else any
    matched = [combine(_matches(r, c) for c in rule.conditions) for r in rows]
    if rule.threshold is None:
        return matched
    window_s = rule.threshold.within_minutes * 60
    windows: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
    totals: dict[str, int] = defaultdict(int)
    fired = []
    for row, hit in zip(rows, matched, strict=True):
        if not hit:
            fired.append(False)
            continue
        key = str(row.get("device") or "") if rule.threshold.per_device else "*"
        ts = datetime.fromisoformat(row["t"]).timestamp()
        q = windows[key]
        while q and ts - q[0][0] >= window_s:
            totals[key] -= q.popleft()[1]
        weight = max(1, int(row.get("count") or 1))  # folded duplicates count as occurrences
        q.append((ts, weight))
        totals[key] += weight
        fired.append(totals[key] >= rule.threshold.count)
    return fired


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def score(rows: list[dict[str, Any]], fired: list[bool]) -> dict[str, Any]:
    tp = fp = fn = tn = unlabelled = 0
    samples: dict[str, list[dict[str, str]]] = {"tp": [], "fp": [], "fn": []}
    for row, hit in zip(rows, fired, strict=True):
        label = row.get("label")
        kind = None
        if label == "malicious":
            kind = "tp" if hit else "fn"
        elif label == "benign":
            kind = "fp" if hit else "tn"
        elif hit:
            unlabelled += 1
        if kind == "tp":
            tp += 1
        elif kind == "fp":
            fp += 1
        elif kind == "fn":
            fn += 1
        elif kind == "tn":
            tn += 1
        if kind in samples and len(samples[kind]) < 5:
            samples[kind].append(
                {"id": str(row.get("id")), "title": str(row.get("title"))[:200], "t": row.get("t", "")}
            )
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else None
    days = 1.0
    if rows:
        span = datetime.fromisoformat(rows[-1]["t"]) - datetime.fromisoformat(rows[0]["t"])
        days = max(1.0, span.total_seconds() / 86400)
    return {
        "fired": sum(fired),
        "fired_unlabelled": unlabelled,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "alerts_per_day": round(sum(fired) / days, 2),
        "samples": samples,
    }


# Today's built-in detection (severity threshold): every new high or critical event becomes an alert.
BASELINE = Rule(conditions=[Condition(field="severity", op="gte", value="high")])


def run(rule: Rule, rows: list[dict[str, Any]]) -> dict[str, Any]:
    labelled = sum(1 for r in rows if r.get("label") in LABELS)
    result = score(rows, evaluate(rule, rows))
    baseline = score(rows, evaluate(BASELINE, rows))
    baseline.pop("samples", None)
    return {"engine": ENGINE_VERSION, "rows": len(rows), "labelled": labelled, **result, "baseline": baseline}
