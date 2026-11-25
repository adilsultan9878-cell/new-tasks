"""DAST: OWASP ZAP API scan (passive + active attacks) against a throwaway server (Phase 9).

Needs Docker. The organization ID is written into the OpenAPI paths so ZAP reaches real records,
and every request carries a valid session. Reports land in ./zap-report/ (HTML, JSON, Markdown).

    python scripts/dast_zap.py                 # 10 minute active-scan budget
    python scripts/dast_zap.py --minutes 30

Fails on any Medium or High alert that is not listed in ACCEPTED below.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_target import cleanup, server_errors, throwaway_api

IMAGE = "zaproxy/zap-stable"
SKIP = ("/auth/logout", "/auth/change-password", "/hooks/")  # would end the session / signature-only
# Reviewed findings that are expected here (pluginid → reason). Only Low/Informational today.
ACCEPTED = {
    "100000": "502 from the CISA KEV sync: outbound intelligence is switched off in the scan environment",
    "2": "Private IP disclosure: a 422 repeats the private CIDR the scanner itself submitted as a scope",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=int, default=10, help="active scan time budget")
    parser.add_argument("--out", default="zap-report")
    args = parser.parse_args()
    if not shutil.which("docker"):
        print("Docker is required for the ZAP scan", file=sys.stderr)
        return 2
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o777)  # the ZAP container runs as an unprivileged user

    with throwaway_api() as target:
        spec = httpx.get(f"{target.base}/openapi.json", timeout=30, trust_env=False).json()
        paths = {}
        for path, ops in spec["paths"].items():
            if any(s in path for s in SKIP):
                continue
            for op in ops.values():
                op["parameters"] = [
                    p
                    for p in op.get("parameters", [])
                    if not (p.get("in") == "path" and p.get("name") == "org_id")
                ]
            paths[path.replace("{org_id}", target.org_id)] = ops
        spec["paths"] = paths
        spec["servers"] = [{"url": target.base}]
        (out / "openapi.json").write_text(json.dumps(spec))

        auth = [
            "-config replacer.full_list(0).description=auth",
            "-config replacer.full_list(0).enabled=true",
            "-config replacer.full_list(0).matchtype=REQ_HEADER",
            "-config replacer.full_list(0).matchstr=Authorization",
            "-config replacer.full_list(0).regex=false",
            f"-config replacer.full_list(0).replacement=Bearer\\ {target.token}",
            f"-config scanner.maxScanDurationInMins={args.minutes}",
            "-config scanner.maxRuleDurationInMins=2",
        ]
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "-v",
            f"{out}:/zap/wrk/:rw",
            IMAGE,
            "zap-api-scan.py",
            "-t",
            "/zap/wrk/openapi.json",
            "-f",
            "openapi",
            "-O",
            target.base,
            "-r",
            "zap-report.html",
            "-J",
            "zap-report.json",
            "-w",
            "zap-report.md",
            "-I",
            "-z",
            " ".join(auth),
        ]
        subprocess.run(cmd, check=False)  # noqa: S603 - fixed argv, no shell

    report = json.loads((out / "zap-report.json").read_text())
    blocking, accepted, low = [], [], []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            line = f"[{alert.get('riskdesc')}] {alert.get('alert')} (plugin {alert.get('pluginid')}, {len(alert.get('instances', []))}x)"
            if risk >= 1 and alert.get("pluginid") in ACCEPTED:
                accepted.append(f"{line} — accepted: {ACCEPTED[alert['pluginid']]}")
            elif risk >= 2:
                blocking.append(line)
            else:
                low.append(line)
    print("\nZAP summary")
    for title, items in (
        ("Blocking (Medium/High)", blocking),
        ("Accepted", accepted),
        ("Low / informational", low),
    ):
        print(f"  {title}: {len(items)}", *(f"    {i}" for i in items), sep="\n")
    errors = server_errors(target.log)
    if errors:
        print("Server-side errors during the scan:", *errors, sep="\n  ")
    cleanup(target)
    return 1 if blocking or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
