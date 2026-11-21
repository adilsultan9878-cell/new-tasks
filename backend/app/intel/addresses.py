"""Address classification shared by the IP analyzer and the network monitor."""

from __future__ import annotations

import ipaddress

_PRIVATE_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_PRIVATE_V6 = (ipaddress.ip_network("fc00::/7"),)


def is_private_network(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """RFC 1918 / unique-local ranges only — what an organization can genuinely own privately.

    (Python's ``is_private`` also includes documentation and other reserved ranges.)
    """
    pools = _PRIVATE_V4 if net.version == 4 else _PRIVATE_V6
    return any(net.subnet_of(p) for p in pools)  # type: ignore[arg-type]


def classify(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if is_private_network(ipaddress.ip_network(addr)):
        return "private"
    return "public" if addr.is_global else "reserved"
