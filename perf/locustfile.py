# ruff: noqa: S311 - random test data, not security
"""SENTINEL X load test (Phase 9). Two kinds of simulated clients:

* ConsoleUser — an analyst with the web console open: dashboard, events, alerts, incidents, the
  digital twin, automation, notifications; now and then reports an event.
* Agent — an enrolled device: heartbeats, event batches and sensor readings.

Every console user signs up and gets an organization with simulator data; agents enroll into one
shared "fleet" organization. Run against a disposable environment only (it creates accounts):

    locust -f perf/locustfile.py --host http://127.0.0.1:8000 --headless -u 60 -r 10 -t 2m --csv perf/results/run

Rate limits are per client address, and every simulated client comes from the same address here, so
the API under test needs higher limits (see docs/PERFORMANCE.md).
"""

from __future__ import annotations

import random
import threading
import uuid

from locust import HttpUser, between, events, task

API = "/api/v1"
PASSWORD = "Load-Test-Account-2026!"
_fleet: dict[str, str] = {}
_fleet_lock = threading.Lock()


def _register(client, prefix: str) -> dict[str, str]:
    email = f"{prefix}-{uuid.uuid4().hex[:10]}@example.com"
    r = client.post(
        f"{API}/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Load Test"},
        name="auth/register",
    )
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    org = client.post(
        f"{API}/organizations", json={"name": f"{prefix} org"}, headers=headers, name="organizations [create]"
    ).json()
    return {"token": token, "org": org["organization"]["id"]}


def _fleet_token(client) -> str:
    """One enrollment token (100 uses) per fleet organization, refreshed when used up."""
    with _fleet_lock:
        if not _fleet or int(_fleet.get("left", "0")) <= 0:
            if "org" not in _fleet:
                _fleet.update(_register(client, "fleet"))
            r = client.post(
                f"{API}/organizations/{_fleet['org']}/enrollment-tokens",
                json={"label": "load test", "max_uses": 100, "expires_in_hours": 2},
                headers={"Authorization": f"Bearer {_fleet['token']}"},
                name="enrollment-tokens [create]",
            )
            _fleet["enroll"] = r.json()["token"]
            _fleet["left"] = "100"
        _fleet["left"] = str(int(_fleet["left"]) - 1)
        return _fleet["enroll"]


class ConsoleUser(HttpUser):
    weight = 3
    wait_time = between(1, 4)

    def on_start(self) -> None:
        me = _register(self.client, "console")
        self.headers = {"Authorization": f"Bearer {me['token']}"}
        self.org = f"{API}/organizations/{me['org']}"
        self.client.post(f"{self.org}/simulator/run", headers=self.headers, name="simulator/run")

    def _get(self, path: str, name: str) -> None:
        self.client.get(f"{self.org}{path}", headers=self.headers, name=name)

    @task(6)
    def dashboard(self) -> None:
        self._get("/dashboard/summary", "dashboard/summary")

    @task(4)
    def events(self) -> None:
        self._get("/events?limit=50", "events")

    @task(4)
    def alerts(self) -> None:
        self._get("/alerts", "alerts")

    @task(2)
    def incidents(self) -> None:
        self._get("/incidents", "incidents")

    @task(2)
    def devices(self) -> None:
        self._get("/devices", "devices")

    @task(1)
    def twin(self) -> None:
        self._get("/twin", "twin")

    @task(1)
    def automation(self) -> None:
        self._get("/automation/overview", "automation/overview")

    @task(2)
    def notifications(self) -> None:
        self.client.get(f"{API}/notifications", headers=self.headers, name="notifications")

    @task(1)
    def report_event(self) -> None:
        sev = random.choice(["low", "medium", "high"])
        self.client.post(
            f"{self.org}/events",
            json={
                "event_type": "policy.violation",
                "category": "policy",
                "severity": sev,
                "title": f"Load test {uuid.uuid4().hex[:6]}",
            },
            headers=self.headers,
            name="events [report]",
        )


class Agent(HttpUser):
    weight = 2
    wait_time = between(2, 6)

    def on_start(self) -> None:
        host = f"load-{uuid.uuid4().hex[:8]}"
        r = self.client.post(
            f"{API}/agent/enroll",
            json={
                "enrollment_token": _fleet_token(self.client),
                "device": {"hostname": host, "os": "Windows 11", "agent_version": "0.3.0"},
            },
            name="agent/enroll",
        )
        self.headers = {"Authorization": f"Bearer {r.json()['device_token']}"}
        self.n = 0

    @task(4)
    def heartbeat(self) -> None:
        self.client.post(
            f"{API}/agent/heartbeat",
            json={
                "agent_version": "0.3.0",
                "telemetry": {"cpu_percent": random.uniform(5, 60), "memory_percent": random.uniform(20, 80)},
            },
            headers=self.headers,
            name="agent/heartbeat",
        )

    @task(2)
    def events(self) -> None:
        self.n += 1
        batch = [
            {
                "event_type": "auth.failed_login",
                "category": "auth",
                "severity": "low",
                "title": f"Failed login {self.n}-{i}",
                "dedup_key": f"{self.n}-{i}",
            }
            for i in range(5)
        ]
        self.client.post(
            f"{API}/agent/events", json={"events": batch}, headers=self.headers, name="agent/events [5]"
        )

    @task(1)
    def readings(self) -> None:
        self.client.post(
            f"{API}/agent/sensors/readings",
            json={
                "readings": [
                    {
                        "sensor_key": "room",
                        "sensor_type": "temperature",
                        "unit": "C",
                        "value": round(random.uniform(19, 26), 1),
                    }
                ]
            },
            headers=self.headers,
            name="agent/sensors/readings",
        )


@events.quitting.add_listener
def _gate(environment, **_kwargs) -> None:
    """CI-style gate: fail the run on any error or a slow p95."""
    stats = environment.stats.total
    if (stats.num_requests and stats.fail_ratio > 0.0) or stats.get_response_time_percentile(0.95) > 1000:
        environment.process_exit_code = 1
