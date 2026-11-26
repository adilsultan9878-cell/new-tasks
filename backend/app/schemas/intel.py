from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.common import APIModel

SubjectType = Literal["url", "domain", "ip", "hash", "email"]
IndicatorType = Literal["ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256"]


class InvestigationCreate(APIModel):
    subject_type: SubjectType
    subject: str = Field(min_length=1, max_length=200_000)

    @field_validator("subject")
    @classmethod
    def _limit(cls, value: str, info: Any) -> str:
        if info.data.get("subject_type") != "email" and len(value) > 2048:
            raise ValueError("at most 2048 characters")
        return value


class InvestigationOut(APIModel):
    id: uuid.UUID
    subject_type: str
    subject: str
    title: str
    status: str
    verdict: str
    risk_score: int | None
    created_at: datetime
    completed_at: datetime | None


class InvestigationDetail(InvestigationOut):
    summary: str | None
    verified_findings: list[dict[str, Any]]
    ai_assessment: str | None
    timeline: list[dict[str, Any]]
    details: dict[str, Any]


class IndicatorOut(APIModel):
    id: uuid.UUID
    indicator_type: str
    value: str
    verdict: str
    confidence: int
    source: str
    is_verified: bool
    first_seen_at: datetime
    last_seen_at: datetime
    context: dict[str, Any]


_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HEX = {"md5": 32, "sha1": 40, "sha256": 64}


class IndicatorCreate(APIModel):
    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=2048)
    verdict: Literal["benign", "suspicious", "malicious"] = "malicious"
    note: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _value_matches_type(self) -> IndicatorCreate:
        """A watchlist entry must be what its type says (found by fuzzing: "0" was a "domain")."""
        v = self.value.strip().lower()
        t = self.indicator_type
        ok = False
        if t in ("ipv4", "ipv6"):
            try:
                ok = ipaddress.ip_address(v).version == (4 if t == "ipv4" else 6)
            except ValueError:
                ok = False
        elif t == "domain":
            ok = bool(_DOMAIN.match(v))
        elif t == "url":
            ok = v.startswith(("http://", "https://")) and len(v) > 10
        elif t == "email":
            ok = bool(re.fullmatch(r"[^@\s]{1,64}@[^@\s]{3,253}", v))
        else:
            ok = bool(re.fullmatch(rf"[0-9a-f]{{{_HEX[t]}}}", v))
        if not ok:
            raise ValueError(f"value is not a valid {t}")
        return self


class ProviderOut(APIModel):
    key: str
    name: str
    covers: list[str]
    requires_key: str | None
    optional_key: str | None = None
    url: str | None
    configured: bool
    enabled: bool


class VulnerabilityOut(APIModel):
    cve_id: str
    title: str | None
    vendor: str | None
    product: str | None
    cvss_score: float | None
    severity: str | None
    in_cisa_kev: bool
    kev_date_added: datetime | None
    known_ransomware_use: bool


class VulnerabilityDetail(VulnerabilityOut):
    description: str | None
    cvss_vector: str | None
    published_at: datetime | None
    last_modified_at: datetime | None
    kev_due_date: datetime | None
    kev_required_action: str | None
    cwes: list[Any]
    references: list[Any]
    source: str
    fetched_at: datetime
    nvd_error: str | None = None


class VulnerabilityStats(APIModel):
    total: int
    kev_total: int
    ransomware_total: int
    last_kev_sync: datetime | None


class KevSyncResult(APIModel):
    catalog_version: str | None
    total: int
    added: int
    updated: int


class ScopeCreate(APIModel):
    cidr: str = Field(min_length=3, max_length=64)
    label: str = Field(min_length=1, max_length=120)
    attest_authorized: bool = False


class ScopeOut(APIModel):
    id: uuid.UUID
    cidr: str
    label: str
    is_private: bool
    created_at: datetime


class ScanImport(APIModel):
    filename: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=5_000_000)


class ScanImportResult(APIModel):
    hosts_in_file: int
    imported: int
    out_of_scope: int
    new_assets: int
    new_services: int
    events: int


class AssetOut(APIModel):
    id: uuid.UUID
    ip_address: str
    hostname: str | None
    mac_address: str | None
    vendor: str | None
    open_ports: list[Any]
    services: list[Any]
    in_authorized_scope: bool
    source: str
    device_id: uuid.UUID | None
    first_seen_at: datetime
    last_seen_at: datetime
