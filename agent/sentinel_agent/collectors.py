"""Approved, read-only telemetry. Each collector can be switched off by configuration."""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import sys
import time
from typing import Any

import psutil

log = logging.getLogger("sentinel_agent.collectors")
_SAFE = re.compile(r"[^\w .,:;()/+@#\-]")


def _clean(text: str, limit: int) -> str:
    return _SAFE.sub("", " ".join(text.split()))[:limit]


def os_name() -> str:
    return _clean(f"{platform.system()} {platform.release()}", 80)


def hostname() -> str:
    return _clean(socket.gethostname(), 255) or "unknown-host"


def _system_drive() -> str:
    if sys.platform == "win32":
        return (os.environ.get("SYSTEMDRIVE") or "C:") + "\\"
    return "/"


def collect_system() -> dict[str, Any]:
    return {
        "cpu_percent": round(psutil.cpu_percent(interval=0.5), 1),
        "memory_percent": round(psutil.virtual_memory().percent, 1),
        "disk_percent": round(psutil.disk_usage(_system_drive()).percent, 1),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "process_count": len(psutil.pids()),
    }


def collect_network() -> dict[str, Any]:
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        ips = [
            a.address.split("%")[0]
            for a in addrs
            if a.family in (socket.AF_INET, socket.AF_INET6) and not a.address.startswith(("127.", "::1"))
        ]
        if ips:
            interfaces.append({"name": _clean(name, 64), "addresses": ips[:8]})
    return {"interfaces": interfaces[:32]}


def collect_ports() -> dict[str, Any]:
    """TCP ports in LISTEN state. Needs no admin rights on Windows/Linux; skipped if denied."""
    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, PermissionError):
        log.warning("listening-port collection needs more privileges on this OS; skipped")
        return {}
    ports = sorted({c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN and c.laddr})
    return {"listening_ports": ports[:512]}


def primary_ip() -> str | None:
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                return a.address
    return None


def primary_mac() -> str | None:
    link = getattr(psutil, "AF_LINK", None)
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == link and a.address and a.address not in ("00:00:00:00:00:00", "00-00-00-00-00-00"):
                mac = a.address.replace("-", ":").lower()
                if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                    return mac
    return None


COLLECTORS = {"system": collect_system, "network": collect_network, "ports": collect_ports}


def collect(enabled: list[str]) -> dict[str, Any]:
    telemetry: dict[str, Any] = {}
    for name in enabled:
        fn = COLLECTORS.get(name)
        if fn is None:
            continue
        try:
            telemetry.update(fn())
        except Exception as exc:  # a broken collector must not stop the agent
            log.warning("collector %s failed: %s", name, exc)
    return telemetry
