"""Check a live SENTINEL X deployment from the outside (Phase 10 go-live).

    python scripts/verify_deployment.py --api https://sentinel-x-api.onrender.com \\
                                        --console https://sentinel-x.pages.dev

Read-only: it never signs in, creates data or sends credentials. Checks:

* API liveness and readiness (database, Row-Level Security enforced, background jobs)
* production hardening: interactive docs and OpenAPI hidden, security headers incl. HSTS,
  /metrics not public, CORS allows the console origin only
* the console: served over HTTPS with its security headers, SPA routes, and the same-origin /api
  proxy reaching the API (cookies stay first-party)
* the public sign-up policy (printed, so you see what the world sees)

Exit code 0 when every required check passes. ``--dev`` relaxes the production-only checks so
the script can also be pointed at a local stack.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

API_HEADERS = (
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Cross-Origin-Resource-Policy",
)
CONSOLE_HEADERS = ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy")


@dataclass
class Report:
    rows: list[tuple[str, bool, str]] = field(default_factory=list)

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.rows.append((name, ok, detail))
        return ok

    @property
    def failed(self) -> list[str]:
        return [n for n, ok, _ in self.rows if not ok]

    def print(self) -> None:
        width = max((len(n) for n, _, _ in self.rows), default=10)
        for name, ok, detail in self.rows:
            print(f"  {'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")


def check_api(client: httpx.Client, api: str, console: str | None, report: Report, *, dev: bool) -> None:
    def get(path: str, **kw):
        try:
            return client.get(api + path, **kw)
        except httpx.HTTPError as exc:
            report.check(f"GET {path}", False, type(exc).__name__)
            return None

    live = get("/health")
    if live is None:
        return
    report.check(
        "API liveness",
        live.status_code == 200,
        f"HTTP {live.status_code}, version {live.json().get('version', '?') if live.status_code == 200 else '-'}",
    )
    ready = get("/api/v1/health/ready")
    if ready is not None:
        body = ready.json() if ready.headers.get("content-type", "").startswith("application/json") else {}
        db = body.get("database", {})
        report.check(
            "API readiness",
            ready.status_code == 200,
            f"HTTP {ready.status_code}, jobs {body.get('jobs', {})}",
        )
        report.check(
            "Database reachable", db.get("status") == "ok", f"{db.get('engine')} {db.get('latency_ms')} ms"
        )
        if not dev:
            report.check(
                "Row-Level Security enforced",
                db.get("row_level_security") == "enforced",
                str(db.get("row_level_security")),
            )
        report.check(
            "Rate limiter", body.get("rate_limiter") in ("memory", "redis"), str(body.get("rate_limiter"))
        )

    headers = live.headers
    missing = [h for h in API_HEADERS if h not in headers]
    report.check(
        "API security headers", not missing, "all present" if not missing else f"missing {', '.join(missing)}"
    )
    if not dev:
        report.check(
            "API HSTS",
            "max-age" in headers.get("Strict-Transport-Security", ""),
            headers.get("Strict-Transport-Security", "missing"),
        )
        for path in ("/docs", "/openapi.json"):
            r = get(path)
            if r is not None:
                report.check(f"{path} hidden in production", r.status_code == 404, f"HTTP {r.status_code}")
    metrics = get("/metrics")
    if metrics is not None:
        report.check("/metrics not public", metrics.status_code == 404, f"HTTP {metrics.status_code}")

    if console:
        origin = f"{urlsplit(console).scheme}://{urlsplit(console).netloc}"
        allowed = client.options(
            api + "/api/v1/auth/me", headers={"Origin": origin, "Access-Control-Request-Method": "GET"}
        )
        report.check(
            "CORS allows the console",
            allowed.headers.get("access-control-allow-origin") == origin,
            allowed.headers.get("access-control-allow-origin", "no allow-origin header"),
        )
    evil = client.options(
        api + "/api/v1/auth/me",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    report.check(
        "CORS refuses other origins",
        "access-control-allow-origin" not in evil.headers,
        evil.headers.get("access-control-allow-origin", "refused"),
    )

    policy = get("/api/v1/auth/policy")
    if policy is not None and policy.status_code == 200:
        p = policy.json()
        report.check(
            "Sign-up policy",
            True,
            f"registration={p['registration']}{' ' + ','.join(p['allowed_domains']) if p['allowed_domains'] else ''}, "
            f"e-mail={'on' if p['password_reset'] else 'off'}, verification required={p['email_verification_required']}",
        )


def check_console(client: httpx.Client, console: str, report: Report, *, dev: bool) -> None:
    try:
        home = client.get(console + "/")
    except httpx.HTTPError as exc:
        report.check("Console reachable", False, type(exc).__name__)
        return
    report.check(
        "Console reachable",
        home.status_code == 200 and '<div id="root"' in home.text,
        f"HTTP {home.status_code}",
    )
    missing = [h for h in CONSOLE_HEADERS if h not in home.headers]
    report.check(
        "Console security headers",
        not missing,
        "all present" if not missing else f"missing {', '.join(missing)}",
    )
    csp = home.headers.get("Content-Security-Policy", "")
    report.check(
        "Console CSP allows blob: images",
        "blob:" in csp or dev,
        "camera snapshots are shown through blob: URLs",
    )
    deep = client.get(console + "/org/00000000-0000-0000-0000-000000000000/automation")
    report.check("SPA routes", deep.status_code == 200, f"deep link HTTP {deep.status_code}")
    proxied = client.get(console + "/api/v1/health")
    report.check(
        "Same-origin /api proxy",
        proxied.status_code == 200 and proxied.headers.get("content-type", "").startswith("application/json"),
        f"HTTP {proxied.status_code}",
    )
    if not dev and console.startswith("https://"):
        try:
            plain = client.get("http://" + console.removeprefix("https://") + "/", follow_redirects=False)
            report.check(
                "HTTP redirects to HTTPS",
                plain.status_code in (301, 302, 307, 308),
                f"HTTP {plain.status_code}",
            )
        except httpx.HTTPError as exc:
            report.check("HTTP redirects to HTTPS", False, type(exc).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--api", required=True, help="API base URL, e.g. https://sentinel-x-api.onrender.com")
    parser.add_argument("--console", help="console URL, e.g. https://sentinel-x.pages.dev")
    parser.add_argument("--dev", action="store_true", help="relax production-only checks (local stacks)")
    parser.add_argument(
        "--timeout", type=float, default=60.0, help="seconds (a sleeping free instance needs ~50 s)"
    )
    args = parser.parse_args(argv)
    api = args.api.rstrip("/")
    console = args.console.rstrip("/") if args.console else None
    report = Report()
    with httpx.Client(
        timeout=args.timeout, follow_redirects=True, headers={"User-Agent": "sentinel-x-verify/1"}
    ) as client:
        check_api(client, api, console, report, dev=args.dev)
        if console:
            check_console(client, console, report, dev=args.dev)
    print(f"SENTINEL X deployment check — API {api}" + (f", console {console}" if console else ""))
    report.print()
    if report.failed:
        print(f"\n{len(report.failed)} check(s) failed: {', '.join(report.failed)}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
