"""Authorized-scope network monitoring: scopes, Nmap XML import, asset inventory.

The platform never scans anything itself. Operators run their own scanner (e.g. Nmap) against
ranges they are authorized to assess and import the results; hosts outside the organization's
declared scopes are discarded on import.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from defusedxml import ElementTree
from fastapi import Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.intel.addresses import is_private_network
from app.models import NetworkAsset, NetworkScope
from app.schemas.events import EventIn
from app.services import audit
from app.services import events as event_service

MAX_HOSTS = 4096
RISKY_SERVICES = {
    21: "ftp",
    23: "telnet",
    135: "msrpc",
    139: "netbios-ssn",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    2375: "docker-api",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    4444: "backdoor",
    31337: "backdoor",
}


def parse_scope(cidr: str, attest_public: bool) -> tuple[str, bool]:
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_scope", "Enter a CIDR such as 192.168.1.0/24"
        ) from None
    min_prefix = 16 if net.version == 4 else 48
    if net.prefixlen < min_prefix:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "scope_too_large",
            f"Scopes larger than /{min_prefix} are not accepted (no internet-wide assessments)",
        )
    private = is_private_network(net)
    if not private and not attest_public:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "attestation_required",
            "Public ranges require confirming that your organization owns or is authorized to assess them",
        )
    return str(net), private


def load_scopes(db: Session, org_id: uuid.UUID) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [
        ipaddress.ip_network(s)
        for s in db.scalars(select(NetworkScope.cidr).where(NetworkScope.organization_id == org_id))
    ]


def in_scope(scopes: list[Any], ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in scopes)


def parse_nmap(xml_text: str) -> list[dict[str, Any]]:
    try:
        root = ElementTree.fromstring(xml_text)  # defusedxml: no entity expansion / external entities
    except Exception:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_scan", "Not a valid Nmap XML file (use nmap -oX)"
        ) from None
    if root.tag != "nmaprun":
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "invalid_scan",
            "Not an Nmap XML report (<nmaprun> missing)",
        )
    hosts = []
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip_addr = mac = vendor = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip_addr = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac, vendor = addr.get("addr"), addr.get("vendor")
        if not ip_addr:
            continue
        hn = host.find("hostnames/hostname")
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            ports.append(
                {
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "service": (svc.get("name") if svc is not None else None),
                    "product": " ".join(filter(None, [svc.get("product"), svc.get("version")]))
                    if svc is not None
                    else None,
                }
            )
        hosts.append(
            {
                "ip": ip_addr,
                "mac": mac,
                "vendor": vendor,
                "hostname": hn.get("name") if hn is not None else None,
                "ports": ports[:1024],
            }
        )
        if len(hosts) > MAX_HOSTS:
            raise AppError(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "scan_too_large",
                f"More than {MAX_HOSTS} hosts in one import",
            )
    return hosts


def import_scan(
    db: Session, request: Request, *, org_id: uuid.UUID, user_id: uuid.UUID, filename: str, xml_text: str
) -> dict[str, Any]:
    hosts = parse_nmap(xml_text)
    scopes = load_scopes(db, org_id)
    if not scopes:
        raise AppError(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "no_scopes",
            "Declare at least one authorized scope before importing scan results",
        )
    now = datetime.now(UTC)
    summary = {
        "hosts_in_file": len(hosts),
        "imported": 0,
        "out_of_scope": 0,
        "new_assets": 0,
        "new_services": 0,
        "events": 0,
    }
    events: list[EventIn] = []
    for h in hosts:
        if not in_scope(scopes, h["ip"]):
            summary["out_of_scope"] += 1
            continue
        ip_norm = str(ipaddress.ip_address(h["ip"]))
        asset = db.scalar(
            select(NetworkAsset).where(
                NetworkAsset.organization_id == org_id, NetworkAsset.ip_address == ip_norm
            )
        )
        previous = set(asset.open_ports) if asset else set()
        is_new = asset is None
        if asset is None:
            asset = NetworkAsset(
                id=uuid.uuid4(),
                organization_id=org_id,
                ip_address=ip_norm,
                first_seen_at=now,
                open_ports=[],
                services=[],
            )
            db.add(asset)
            summary["new_assets"] += 1
        ports = sorted({p["port"] for p in h["ports"]})
        asset.open_ports = ports
        asset.services = h["ports"]
        asset.hostname = h["hostname"] or asset.hostname
        asset.mac_address = h["mac"] or asset.mac_address or None
        asset.vendor = h["vendor"] or asset.vendor
        asset.in_authorized_scope = True
        asset.source = "nmap"
        asset.last_seen_at = now
        summary["imported"] += 1
        if is_new:
            events.append(
                EventIn(
                    event_type="network.asset_discovered",
                    category="network",
                    severity="info",
                    title=f"Network asset discovered: {ip_norm} ({len(ports)} open ports)",
                    dedup_key=f"asset:{ip_norm}",
                    raw={"ip": ip_norm, "ports": ports, "source": filename},
                )
            )
        for p in h["ports"]:
            port = p["port"]
            risky = port in RISKY_SERVICES
            # Report risky services the first time they are seen; other services only when they
            # newly appear on an already-known asset (the first import is the baseline).
            if port in previous or (is_new and not risky):
                continue
            name = p["service"] or RISKY_SERVICES.get(port, "unknown")
            summary["new_services"] += 1
            events.append(
                EventIn(
                    event_type="network.exposed_service" if risky else "network.new_exposed_service",
                    category="network",
                    severity="high" if risky else "medium",
                    title=f"{'Risky service exposed' if risky else 'New service exposed'}: {name} on {ip_norm}:{port}",
                    dedup_key=f"svc:{ip_norm}:{port}",
                    raw={"ip": ip_norm, "port": port, "service": name, "product": p["product"]},
                )
            )
    if events:
        outcome = event_service.ingest(db, org_id, events[:500], source="network")
        summary["events"] = outcome.accepted + outcome.deduplicated
    audit.record(
        db,
        "network.scan_import",
        request=request,
        actor_id=user_id,
        org_id=org_id,
        target_type="network_scan",
        details={"filename": filename[:120], **summary},
    )
    return summary


def record_agent_ports(
    db: Session, org_id: uuid.UUID, device_id: uuid.UUID, ip: str | None, ports: list[int] | None
) -> None:
    """Keep the asset inventory in sync with what enrolled agents report about themselves."""
    if not ip or ports is None:
        return
    now = datetime.now(UTC)
    asset = db.scalar(
        select(NetworkAsset).where(NetworkAsset.organization_id == org_id, NetworkAsset.ip_address == ip)
    )
    if asset is None:
        asset = NetworkAsset(
            id=uuid.uuid4(),
            organization_id=org_id,
            ip_address=ip,
            first_seen_at=now,
            services=[],
            source="agent",
        )
        db.add(asset)
    asset.device_id = device_id
    asset.open_ports = sorted(set(ports))[:512]
    asset.in_authorized_scope = in_scope(load_scopes(db, org_id), ip)
    asset.last_seen_at = now
