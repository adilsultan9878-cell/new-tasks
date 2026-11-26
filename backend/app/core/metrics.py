"""Operational metrics in the Prometheus text format (Phase 10 monitoring).

A small in-process registry — no extra dependency, no labels with user data. Values are per API
process: run one process per container (the default here) or aggregate in Prometheus.

Exposed at ``GET /metrics`` only when METRICS_TOKEN is set, and only with ``Authorization: Bearer
<METRICS_TOKEN>`` (Grafana Cloud, Prometheus or any scraper can send it).

Labels are route *templates* (``/api/v1/organizations/{org_id}/events``), never raw paths, so
IDs and query strings do not end up in metrics.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from app import __version__

BUCKETS = (0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
START = time.time()


class Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: dict[tuple[str, str, str], int] = defaultdict(int)  # method, route, status class
        self.buckets: dict[tuple[str, str], list[int]] = {}
        self.sums: dict[tuple[str, str], float] = defaultdict(float)
        self.counts: dict[tuple[str, str], int] = defaultdict(int)
        self.job_runs: dict[str, float] = {}  # job -> unix time of the last successful run
        self.job_failures: dict[str, int] = defaultdict(int)

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        key = (method, route)
        with self._lock:
            self.requests[(method, route, f"{status // 100}xx")] += 1
            b = self.buckets.setdefault(key, [0] * len(BUCKETS))
            for i, edge in enumerate(BUCKETS):
                if seconds <= edge:
                    b[i] += 1
            self.sums[key] += seconds
            self.counts[key] += 1

    def job_ok(self, job: str) -> None:
        with self._lock:
            self.job_runs[job] = time.time()

    def job_failed(self, job: str) -> None:
        with self._lock:
            self.job_failures[job] += 1

    def reset(self) -> None:
        self.__init__()  # type: ignore[misc]


registry = Registry()


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render() -> str:
    from app.core.rate_limit import limiter
    from app.services import email as mail
    from app.services.realtime import hub

    r = registry
    lines = [
        "# HELP sentinel_build_info Version of the running API.",
        "# TYPE sentinel_build_info gauge",
        f'sentinel_build_info{{version="{_esc(__version__)}"}} 1',
        "# HELP sentinel_process_start_time_seconds Unix time the process started.",
        "# TYPE sentinel_process_start_time_seconds gauge",
        f"sentinel_process_start_time_seconds {START:.0f}",
        "# HELP sentinel_http_requests_total HTTP requests by method, route template and status class.",
        "# TYPE sentinel_http_requests_total counter",
    ]
    with r._lock:
        requests = dict(r.requests)
        buckets = {k: list(v) for k, v in r.buckets.items()}
        sums, counts = dict(r.sums), dict(r.counts)
        jobs, failures = dict(r.job_runs), dict(r.job_failures)
    for (method, route, cls), n in sorted(requests.items()):
        lines.append(
            f'sentinel_http_requests_total{{method="{method}",route="{_esc(route)}",status="{cls}"}} {n}'
        )
    lines += [
        "# HELP sentinel_http_request_duration_seconds Request duration by method and route template.",
        "# TYPE sentinel_http_request_duration_seconds histogram",
    ]
    for (method, route), b in sorted(buckets.items()):
        labels = f'method="{method}",route="{_esc(route)}"'
        for edge, n in zip(BUCKETS, b, strict=True):
            lines.append(f'sentinel_http_request_duration_seconds_bucket{{{labels},le="{edge}"}} {n}')
        lines.append(
            f'sentinel_http_request_duration_seconds_bucket{{{labels},le="+Inf"}} {counts[(method, route)]}'
        )
        lines.append(f"sentinel_http_request_duration_seconds_sum{{{labels}}} {sums[(method, route)]:.6f}")
        lines.append(f"sentinel_http_request_duration_seconds_count{{{labels}}} {counts[(method, route)]}")
    lines += [
        "# HELP sentinel_job_last_success_timestamp_seconds Last successful run of a background job.",
        "# TYPE sentinel_job_last_success_timestamp_seconds gauge",
        *(
            f'sentinel_job_last_success_timestamp_seconds{{job="{j}"}} {t:.0f}'
            for j, t in sorted(jobs.items())
        ),
        "# HELP sentinel_job_failures_total Failed runs of a background job.",
        "# TYPE sentinel_job_failures_total counter",
        *(f'sentinel_job_failures_total{{job="{j}"}} {n}' for j, n in sorted(failures.items())),
        "# HELP sentinel_emails_total E-mails handed to the provider, by result.",
        "# TYPE sentinel_emails_total counter",
        f'sentinel_emails_total{{result="sent"}} {mail.stats.sent}',
        f'sentinel_emails_total{{result="failed"}} {mail.stats.failed}',
        "# HELP sentinel_rate_limit_fallbacks_total Rate-limit checks served per instance because Redis was down.",
        "# TYPE sentinel_rate_limit_fallbacks_total counter",
        f"sentinel_rate_limit_fallbacks_total {limiter.fallbacks}",
        "# HELP sentinel_websocket_subscribers Open real-time connections.",
        "# TYPE sentinel_websocket_subscribers gauge",
        f"sentinel_websocket_subscribers {hub.subscriber_count()}",
    ]
    return "\n".join(lines) + "\n"
