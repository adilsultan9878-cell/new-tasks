"""API fuzzing with Schemathesis against a throwaway server (Phase 9 security testing).

Schemathesis generates thousands of requests from the OpenAPI document (valid, boundary and invalid
values) for every operation and fails on any 5xx. Server-side tracebacks are printed afterwards.

    python scripts/fuzz_api.py              # 15 examples per operation (CI)
    python scripts/fuzz_api.py --examples 50

Excluded on purpose: logout / change-password (they would end the fuzzing session), incoming hooks
(authenticated by signature, covered by tests/test_automation.py) and the CISA KEV sync, which
correctly answers 502 because outbound intelligence is switched off here.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_target import cleanup, server_errors, throwaway_api

EXCLUDE = (
    r"/(auth/(logout|logout-all|change-password)|hooks/|organizations/\{org_id\}/vulnerabilities/sync-kev)"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--examples", type=int, default=15)
    args = parser.parse_args()
    with throwaway_api() as target:
        (target.workdir / "schemathesis.toml").write_text(
            f'[parameters]\n"path.org_id" = "{target.org_id}"\n'
        )
        st = shutil.which("st", path=str(Path(sys.executable).parent)) or "st"
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                st,
                "run",
                f"{target.base}/openapi.json",
                "-H",
                f"Authorization: Bearer {target.token}",
                "--checks",
                "not_a_server_error",
                "--max-examples",
                str(args.examples),
                "--workers",
                "2",
                "--exclude-path-regex",
                EXCLUDE,
                "--phases",
                "examples,coverage,fuzzing",
                "--generation-deterministic",
            ],
            cwd=target.workdir,
            env=target.env,
        )
    errors = server_errors(target.log)
    if errors:
        print("\nServer-side errors:", *errors, sep="\n  ")
    cleanup(target)
    return result.returncode or (1 if errors else 0)


if __name__ == "__main__":
    raise SystemExit(main())
