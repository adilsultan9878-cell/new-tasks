from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import EmailStr, Field, field_validator

from app.schemas.auth import _clean_name
from app.schemas.common import APIModel, no_nulls

SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])$")
INDUSTRIES = (
    "education",
    "research",
    "finance",
    "healthcare",
    "government",
    "technology",
    "manufacturing",
    "retail",
    "energy",
    "other",
)


def _check_industry(value: str | None) -> str | None:
    if value is not None and value not in INDUSTRIES:
        raise ValueError(f"Industry must be one of: {', '.join(INDUSTRIES)}")
    return value


class OrganizationCreate(APIModel):
    name: str = Field(min_length=2, max_length=120)
    slug: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=1000)
    industry: str | None = None

    _n = field_validator("name")(_clean_name)

    @field_validator("slug")
    @classmethod
    def _slug(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        value = value.lower()
        if not SLUG_RE.match(value):
            raise ValueError("Slug must be 3-64 chars of lowercase letters, digits and hyphens")
        return value

    _i = field_validator("industry")(_check_industry)


class OrganizationUpdate(APIModel):
    _no_nulls = no_nulls("name")
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    industry: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, value: str | None) -> str | None:
        return _clean_name(value) if value is not None else None

    _i = field_validator("industry")(_check_industry)


class RoleOut(APIModel):
    key: str
    name: str
    description: str | None
    rank: int


class RoleWithPermissions(RoleOut):
    permissions: list[str]


class OrganizationOut(APIModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    industry: str | None
    plan: str
    created_at: datetime


class MembershipOut(APIModel):
    """An organization as seen by the current user (with their role and permissions)."""

    organization: OrganizationOut
    role: RoleOut
    permissions: list[str]
    member_count: int


class MemberOut(APIModel):
    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    full_name: str
    role: RoleOut
    status: str
    joined_at: datetime


class MemberAdd(APIModel):
    email: EmailStr
    role: str = "viewer"


class MemberUpdate(APIModel):
    role: str
