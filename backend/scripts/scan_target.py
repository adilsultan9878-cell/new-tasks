"""A throwaway API for security scanners (Schemathesis, OWASP ZAP): temp SQLite, one account,
one organization with simulator data. Used by fuzz_api.py and dast_zap.py."""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx

BACKEND = Path(__file__).resolve().parents[1]


@dataclass
class Target:
    base: str  # http://127.0.0.1:<port>
    token: str
    org_id: str
    workdir: Path
    log: Path
    env: dict[str, str]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def throwaway_api(**extra_env: str) -> Iterator[Target]:
    work = Path(tempfile.mkdtemp(prefix="sx-scan-"))
    port = _free_port()
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite:///{work / 'scan.db'}",
        "MIGRATION_DATABASE_URL": "",
        "ENVIRONMENT": "development",
        "JWT_SECRET": secrets.token_urlsafe(48),
        "RATE_LIMIT_ENABLED": "false",
        "INTEL_OFFLINE": "true",
        "AUTOMATION_DELIVERY_ENABLED": "false",
        "LOG_LEVEL": "WARNING",
        "ACCESS_TOKEN_TTL_MINUTES": "180",  # long scans must not lose their session
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        **extra_env,
    }
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND,
        env=env,
        check=True,
        capture_output=True,
    )
    log_path = work / "api.log"
    with log_path.open("w") as log:
        server = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=BACKEND,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    base = f"http://127.0.0.1:{port}"
    try:
        client = httpx.Client(base_url=f"{base}/api/v1", trust_env=False, timeout=30)
        for _ in range(120):
            try:
                if client.get("/health").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("API did not start: " + log_path.read_text()[-2000:])
        token = client.post(
            "/auth/register",
            json={
                "email": f"scanner-{secrets.token_hex(4)}@example.com",
                "password": "Scanner-Lab-Account-2026!",
                "full_name": "Security Scanner",
            },
        ).json()["access_token"]
        auth = {"Authorization": f"Bearer {token}"}
        org = client.post("/organizations", json={"name": "Scan Org"}, headers=auth).json()["organization"][
            "id"
        ]
        client.post(f"/organizations/{org}/simulator/run", headers=auth).raise_for_status()
        yield Target(base=base, token=token, org_id=org, workdir=work, log=log_path, env=env)
    finally:
        server.terminate()
        server.wait(timeout=15)


def server_errors(log_path: Path) -> list[str]:
    import json

    errors = []
    for line in log_path.read_text().splitlines():
        if "Unhandled error" in line:
            try:
                entry = json.loads(line)
                errors.append(f"{entry['msg']}: {entry.get('exc', '').splitlines()[-1][:300]}")
            except (ValueError, KeyError, IndexError):
                errors.append(line[:300])
    return sorted(set(errors))


def cleanup(target: Target) -> None:
    shutil.rmtree(target.workdir, ignore_errors=True)
