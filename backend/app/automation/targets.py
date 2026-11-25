"""Where outgoing webhooks may go (server-side request forgery guard).

* ``https://`` only, unless private targets are allowed (a local n8n usually speaks plain http).
* No user:password in the URL (credentials do not belong in configuration).
* The host must resolve to public addresses only — checked when the webhook is saved *and* before
  every delivery, so a DNS change cannot point an approved webhook at an internal service. Loopback,
  RFC 1918, link-local (cloud metadata), multicast and reserved ranges are refused unless
  ``AUTOMATION_ALLOW_PRIVATE_TARGETS=true``.
* Redirects are never followed by the dispatcher.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.intel.addresses import classify

Resolver = Callable[[str, int], list[str]]


class TargetRefused(ValueError):
    pass


def _system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


resolver: Resolver = _system_resolver  # tests replace this


def parse(url: str) -> tuple[str, str, int]:
    """Syntax checks only. Returns (scheme, host, port)."""
    allow_private = get_settings().automation_allow_private_targets
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        raise TargetRefused("Not a valid URL") from None
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise TargetRefused("Use an https:// URL")
    if scheme == "http" and not allow_private:
        raise TargetRefused("Use an https:// URL (plain http is only allowed for private targets)")
    if parts.username or parts.password:
        raise TargetRefused("Do not put a username or password in the URL")
    host = (parts.hostname or "").lower()
    if not host:
        raise TargetRefused("The URL has no host")
    if parts.fragment:
        raise TargetRefused("The URL must not contain a #fragment")
    return scheme, host, port or (443 if scheme == "https" else 80)


def check(url: str) -> list[str]:
    """Full check including DNS. Returns the resolved addresses; raises TargetRefused."""
    _scheme, host, port = parse(url)
    allow_private = get_settings().automation_allow_private_targets
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        addresses = [str(literal)]
    except ValueError:
        internal = host == "localhost" or host.endswith((".localhost", ".local", ".internal"))
        if internal and not allow_private:
            raise TargetRefused("Internal host names are not allowed") from None
        try:
            addresses = resolver(host, port)
        except OSError:
            raise TargetRefused(f"Could not resolve {host}") from None
        if not addresses:
            raise TargetRefused(f"Could not resolve {host}") from None
    if not allow_private:
        for a in addresses:
            kind = classify(ipaddress.ip_address(a))
            if kind != "public":
                raise TargetRefused(f"{host} points to a {kind} address; only public targets are allowed")
    return addresses


def display_host(url: str) -> str:
    try:
        return urlsplit(url).netloc.rsplit("@", 1)[-1]
    except ValueError:
        return ""
