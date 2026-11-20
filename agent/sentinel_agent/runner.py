"""The agent's main loop: heartbeat → collect → detect → deliver, until asked to stop."""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from sentinel_agent import __version__
from sentinel_agent.client import AgentClient, AuthError, RateLimited, RequestRejected, TransportError
from sentinel_agent.collectors import collect, hostname, os_name, primary_ip
from sentinel_agent.detectors import Detector
from sentinel_agent.spool import Spool
from sentinel_agent.state import AgentState, agent_home, apply_config, save_state

log = logging.getLogger("sentinel_agent")
MAX_BACKOFF = 300
BATCH = 100


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def lifecycle_event(event_type: str, title: str) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "category": "agent",
        "severity": "info",
        "title": title,
        "occurred_at": _now_iso(),
        "raw": {"agent_version": __version__},
    }


class Agent:
    def __init__(
        self, state: AgentState, client: AgentClient | None = None, spool: Spool | None = None
    ) -> None:
        self.state = state
        # `is None` checks: an empty Spool is falsy (it defines __len__).
        self.client = client if client is not None else AgentClient(state.server_url, state.device_token)
        self.spool = spool if spool is not None else Spool(agent_home() / "spool.jsonl")
        thresholds = state.config.get("thresholds", {})
        self.detector = Detector(
            thresholds=dict(thresholds),
            known_ports=set(state.known_ports) if state.known_ports is not None else None,
        )
        self.stop_event = threading.Event()
        self.revoked = False

    # ----------------------------------------------------------------------------- delivery
    def deliver(self, events: list[dict[str, Any]]) -> None:
        """Send spooled + new events; on a transport failure keep them for the next cycle."""
        pending = self.spool.load() + events
        if not pending:
            return
        sent = 0
        try:
            for i in range(0, len(pending), BATCH):
                result = self.client.send_events(pending[i : i + BATCH])
                sent = i + BATCH
                if result.get("rejected"):
                    log.warning(
                        "server rejected %d event(s): %s", len(result["rejected"]), result["rejected"]
                    )
            self.spool.clear()
        except RequestRejected as exc:
            log.error("event batch refused, discarding it: %s", exc)
            self.spool.clear()
        except (TransportError, RateLimited) as exc:
            remaining = pending[sent:]
            self.spool.clear()
            dropped = self.spool.push(remaining)
            log.warning("could not deliver %d event(s), spooled for retry (%s)", len(remaining), exc)
            if dropped:
                log.warning("spool full: dropped %d oldest event(s)", dropped)
            raise

    # ----------------------------------------------------------------------------- one cycle
    def cycle(self) -> None:
        telemetry = collect(self.state.config.get("collectors", []))
        payload = {
            "agent_version": __version__,
            "config_version": self.state.config_version,
            "hostname": hostname(),
            "os": os_name(),
            "ip_address": primary_ip(),
            "telemetry": telemetry,
        }
        response = self.client.heartbeat(payload)
        self.state.last_heartbeat_at = _now_iso()
        self.state.last_error = None
        if response.get("config_version", self.state.config_version) != self.state.config_version:
            new_config, warnings = apply_config(self.state.config, response.get("config") or {})
            for w in warnings:
                log.warning("config: %s", w)
            self.state.config = new_config
            self.state.config_version = int(response["config_version"])
            self.detector.thresholds = dict(new_config["thresholds"])
            log.info("applied configuration version %s", self.state.config_version)

        events = self.detector.evaluate(telemetry)
        for e in events:
            e.setdefault("occurred_at", _now_iso())
        self.deliver(events)
        self.state.known_ports = (
            sorted(self.detector.known_ports) if self.detector.known_ports is not None else None
        )
        save_state(self.state)

    # ------------------------------------------------------------------------------- run loop
    def run(self, once: bool = False) -> int:
        log.info("agent %s starting for device %s", __version__, self.state.device_id)
        backoff = 0.0
        try:
            self.deliver([lifecycle_event("agent.started", f"Agent {__version__} started on {hostname()}")])
        except (TransportError, RateLimited):
            pass
        except AuthError:
            return self._revoked()

        while not self.stop_event.is_set():
            try:
                self.cycle()
                backoff = 0.0
                wait = float(self.state.config.get("heartbeat_interval_seconds", 60))
            except AuthError:
                return self._revoked()
            except RateLimited as exc:
                wait = exc.retry_after
            except TransportError as exc:
                backoff = min(MAX_BACKOFF, max(5.0, backoff * 2))
                wait = backoff
                self.state.last_error = str(exc)
                save_state(self.state)
                log.warning("server unreachable, retrying in %.0fs: %s", wait, exc)
            if once:
                break
            self.stop_event.wait(wait)

        if not once:
            try:
                self.deliver([lifecycle_event("agent.stopped", f"Agent stopped on {hostname()}")])
            except Exception:  # best effort on shutdown
                log.info("could not report shutdown")
        save_state(self.state)
        log.info("agent stopped")
        return 0

    def _revoked(self) -> int:
        self.revoked = True
        self.state.last_error = "credential rejected: device revoked or credential rotated elsewhere"
        save_state(self.state)
        log.error("%s. Re-enroll with a new enrollment token.", self.state.last_error)
        return 3

    def stop(self) -> None:
        self.stop_event.set()
