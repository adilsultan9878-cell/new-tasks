"""Local agent state: where it lives, how it is protected, and the configuration allow-list."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ALLOWED_COLLECTORS = ("network", "ports", "system")
DEFAULT_CONFIG: dict[str, Any] = {
    "heartbeat_interval_seconds": 60,
    "collectors": list(ALLOWED_COLLECTORS),
    "thresholds": {"cpu_percent": 90, "memory_percent": 90, "disk_percent": 90},
}


def agent_home() -> Path:
    """Per-user data directory (no administrator rights needed). Override with SENTINEL_AGENT_HOME."""
    override = os.environ.get("SENTINEL_AGENT_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "SentinelX" / "agent"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "SentinelX" / "agent"
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "sentinel-x-agent"


@dataclass
class AgentState:
    server_url: str
    device_id: str
    organization_id: str
    device_token: str
    config: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_CONFIG))
    config_version: int = 1
    known_ports: list[int] | None = None  # baseline for new-listening-port detection
    enrolled_at: str = ""
    last_heartbeat_at: str | None = None
    last_error: str | None = None

    @property
    def path(self) -> Path:
        return agent_home() / "state.json"


def state_path() -> Path:
    return agent_home() / "state.json"


def load_state() -> AgentState | None:
    path = state_path()
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return AgentState(**{k: v for k, v in data.items() if k in AgentState.__dataclass_fields__})


def save_state(state: AgentState) -> Path:
    """Write atomically and restrict permissions: the file holds the device credential."""
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
    if os.name == "posix":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def delete_state() -> bool:
    path = state_path()
    if path.exists():
        path.unlink()
        return True
    return False


def apply_config(current: dict[str, Any], incoming: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Validate configuration from the server against a strict allow-list.

    Returns (new_config, warnings). Unknown keys and out-of-range values are ignored, never
    interpreted — there is no key that could make the agent run anything.
    """
    warnings: list[str] = []
    result = json.loads(json.dumps(current))  # deep copy

    for key in incoming:
        if key not in DEFAULT_CONFIG:
            warnings.append(f"ignored unsupported config key {key!r}")

    interval = incoming.get("heartbeat_interval_seconds")
    if interval is not None:
        if isinstance(interval, int) and not isinstance(interval, bool) and 15 <= interval <= 3600:
            result["heartbeat_interval_seconds"] = interval
        else:
            warnings.append("ignored invalid heartbeat_interval_seconds")

    collectors = incoming.get("collectors")
    if collectors is not None:
        if isinstance(collectors, list) and all(c in ALLOWED_COLLECTORS for c in collectors):
            result["collectors"] = sorted(set(collectors))
        else:
            warnings.append("ignored invalid collectors list")

    thresholds = incoming.get("thresholds")
    if thresholds is not None:
        if isinstance(thresholds, dict):
            for name, value in thresholds.items():
                if name not in DEFAULT_CONFIG["thresholds"]:
                    warnings.append(f"ignored unsupported threshold {name!r}")
                elif isinstance(value, int | float) and not isinstance(value, bool) and 50 <= value <= 100:
                    result["thresholds"][name] = value
                else:
                    warnings.append(f"ignored invalid threshold {name!r}")
        else:
            warnings.append("ignored invalid thresholds")
    return result, warnings
