"""Phase 10: the go-live verification script detects what it claims to detect."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from tests.conftest import make_client

_spec = importlib.util.spec_from_file_location(
    "verify_deployment", Path(__file__).resolve().parents[1] / "scripts" / "verify_deployment.py"
)
verify = importlib.util.module_from_spec(_spec)
sys.modules["verify_deployment"] = verify  # dataclasses resolve their module through sys.modules
_spec.loader.exec_module(verify)  # type: ignore[union-attr]


def test_a_healthy_local_api_passes_in_dev_mode():
    report = verify.Report()
    verify.check_api(make_client(), "http://testserver", "http://localhost:5173", report, dev=True)
    assert not report.failed, report.rows
    names = {n for n, _, _ in report.rows}
    assert {
        "API readiness",
        "CORS allows the console",
        "CORS refuses other origins",
        "/metrics not public",
    } <= names


def test_production_mode_flags_what_is_not_production_ready():
    report = verify.Report()
    verify.check_api(make_client(), "http://testserver", "https://evil-console.example", report, dev=False)
    failed = set(report.failed)
    # SQLite test API: no RLS, no HSTS (development), docs visible, console origin not in CORS.
    assert {
        "Row-Level Security enforced",
        "API HSTS",
        "/docs hidden in production",
        "CORS allows the console",
    } <= failed
