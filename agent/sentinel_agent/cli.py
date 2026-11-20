"""Command line: sentinel-agent enroll | run | status | rotate-credentials | unenroll"""

from __future__ import annotations

import argparse
import json
import shutil
import signal
import sys
from datetime import UTC, datetime

from sentinel_agent import __version__
from sentinel_agent.client import AgentClient, AgentError, AuthError, normalize_server_url
from sentinel_agent.collectors import hostname, os_name, primary_ip, primary_mac
from sentinel_agent.logs import setup_logging
from sentinel_agent.runner import Agent
from sentinel_agent.spool import Spool
from sentinel_agent.state import AgentState, agent_home, delete_state, load_state, save_state


def _require_state() -> AgentState:
    state = load_state()
    if state is None:
        print(
            "This device is not enrolled. Run: sentinel-agent enroll --server URL --token TOKEN",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return state


def cmd_enroll(args: argparse.Namespace) -> int:
    if load_state() is not None and not args.force:
        print("Already enrolled. Use 'sentinel-agent unenroll' first, or pass --force.", file=sys.stderr)
        return 2
    try:
        server = normalize_server_url(args.server, allow_http=args.allow_http)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    facts = {
        "name": args.name or hostname(),
        "hostname": hostname(),
        "os": os_name(),
        "agent_version": __version__,
        "ip_address": primary_ip(),
        "mac_address": primary_mac(),
    }
    try:
        result = AgentClient(server).enroll(args.token, facts)
    except AuthError as exc:
        print(f"Enrollment refused: {exc}", file=sys.stderr)
        return 3
    except AgentError as exc:
        print(f"Enrollment failed: {exc}", file=sys.stderr)
        return 1
    state = AgentState(
        server_url=server,
        device_id=result["device_id"],
        organization_id=result["organization_id"],
        device_token=result["device_token"],
        config=result["config"],
        config_version=result["config_version"],
        enrolled_at=datetime.now(UTC).isoformat(),
    )
    path = save_state(state)
    print(f"Enrolled as device {state.device_id}. Credential stored in {path}")
    print("Start the agent with: sentinel-agent run")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    setup_logging(args.verbose)
    agent = Agent(_require_state())

    def _stop(*_: object) -> None:
        agent.stop()

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)
    if hasattr(signal, "SIGBREAK"):  # Windows Ctrl+Break / service stop
        signal.signal(signal.SIGBREAK, _stop)
    return agent.run(once=args.once)


def cmd_status(_: argparse.Namespace) -> int:
    state = load_state()
    if state is None:
        print(json.dumps({"enrolled": False, "home": str(agent_home())}, indent=2))
        return 1
    print(
        json.dumps(
            {
                "enrolled": True,
                "home": str(agent_home()),
                "server": state.server_url,
                "device_id": state.device_id,
                "organization_id": state.organization_id,
                "config_version": state.config_version,
                "config": state.config,
                "last_heartbeat_at": state.last_heartbeat_at,
                "last_error": state.last_error,
                "spooled_events": len(Spool(agent_home() / "spool.jsonl")),
            },
            indent=2,
        )
    )
    return 0


def cmd_rotate(_: argparse.Namespace) -> int:
    state = _require_state()
    try:
        state.device_token = AgentClient(state.server_url, state.device_token).rotate_credentials()
    except AgentError as exc:
        print(f"Rotation failed: {exc}", file=sys.stderr)
        return 1
    save_state(state)
    print("Device credential rotated.")
    return 0


def cmd_unenroll(args: argparse.Namespace) -> int:
    state = load_state()
    if state is not None:
        try:
            AgentClient(state.server_url, state.device_token).unenroll()
            print("Device unenrolled on the server.")
        except AuthError:
            print("Server already considers this device revoked.")
        except AgentError as exc:
            print(
                f"Warning: could not reach the server ({exc}). Revoke the device in the console.",
                file=sys.stderr,
            )
        delete_state()
        print("Local credential deleted.")
    if args.purge and agent_home().exists():
        shutil.rmtree(agent_home(), ignore_errors=True)
        print(f"Removed {agent_home()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel-agent", description="SENTINEL X local security agent")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("enroll", help="register this device with an enrollment token")
    p.add_argument("--server", required=True, help="API URL, e.g. https://api.example.com")
    p.add_argument("--token", required=True, help="enrollment token from the console (sxe.…)")
    p.add_argument("--name", help="display name (default: hostname)")
    p.add_argument(
        "--allow-http", action="store_true", help="allow plain HTTP to a non-local server (labs only)"
    )
    p.add_argument("--force", action="store_true", help="replace an existing enrollment")
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("run", help="run the agent (Ctrl+C to stop)")
    p.add_argument("--once", action="store_true", help="run a single cycle and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_run)

    sub.add_parser("status", help="show enrollment and health").set_defaults(func=cmd_status)
    sub.add_parser("rotate-credentials", help="replace the device credential").set_defaults(func=cmd_rotate)

    p = sub.add_parser("unenroll", help="unregister this device and delete its credential")
    p.add_argument("--purge", action="store_true", help="also delete logs and the agent data directory")
    p.set_defaults(func=cmd_unenroll)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))
