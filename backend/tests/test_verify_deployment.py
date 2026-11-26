"""Phase 10: the go-live verification script detects what it claims to detect."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from app.core.metrics import registry
from tests.conftest import IS_POSTGRES, make_client

_spec = importlib.util.spec_from_file_location(
    "verify_deployment", Path(__file__).resolve().parents[1] / "scripts" / "verify_deployment.py"
)
verify = importlib.util.module_from_spec(_spec)
sys.modules["verify_deployment"] = verify  # dataclasses resolve their module through sys.modules
_spec.loader.exec_module(verify)  # type: ignore[union-attr]


def _jobs_ran() -> None:
    # Background loops do not run under the test client; record a fresh run like the real loops do.
    registry.job_ok("sweeper")
    registry.job_ok("automation")


def test_a_healthy_local_api_passes_in_dev_mode():
    _jobs_ran()
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
    _jobs_ran()
    report = verify.Report()
    verify.check_api(make_client(), "http://testserver", "https://evil-console.example", report, dev=False)
    failed = set(report.failed)
    # Test API: no HSTS (development), docs visible, console origin not in CORS; SQLite has no RLS.
    assert {"API HSTS", "/docs hidden in production", "CORS allows the console"} <= failed
    assert ("Row-Level Security enforced" in failed) is not IS_POSTGRES
