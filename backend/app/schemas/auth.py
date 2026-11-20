from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import EmailStr, Field, field_validator

from app.schemas.common import APIModel


def _clean_name(value: str) -> str:
    value = " ".join(value.split())
    if not value:
        raise ValueError("Name must not be empty")
    if any(ch in value for ch in "<>{}"):
        raise ValueError("Name contains invalid characters")
    return value


class RegisterRequest(APIModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    full_name: str = Field(min_length=1, max_length=120)

    _n = field_validator("full_name")(_clean_name)


class LoginRequest(APIModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(APIModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class UpdateProfileRequest(APIModel):
    full_name: str = Field(min_length=1, max_length=120)

    _n = field_validator("full_name")(_clean_name)


class UserOut(APIModel):
    id: uuid.UUID
    email: str
    full_name: str
    email_verified: bool = False
    created_at: datetime
    last_login_at: datetime | None = None


class TokenResponse(APIModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class SessionOut(APIModel):
    id: uuid.UUID
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    current: bool = False
