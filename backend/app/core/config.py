"""Application settings, loaded from environment variables (and an optional .env file).

Secrets are never hardcoded: every credential comes from the environment. In production the
application refuses to start with a missing or placeholder JWT secret.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_PLACEHOLDER_SECRETS = {"", "change-me", "changeme", "CHANGE_ME_TO_A_LONG_RANDOM_STRING"}


def normalize_database_url(url: str) -> str:
    """Accept the URL formats Supabase/Render/Heroku hand out and pin the psycopg 3 driver."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- General -------------------------------------------------------------------------
    app_name: str = "SENTINEL X — AEGIS NEXUS"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"

    # --- Database --------------------------------------------------------------------------
    # Runtime connection. In production this should be a dedicated, non-superuser role so
    # PostgreSQL Row-Level Security policies are enforced (see docs/SECURITY.md).
    database_url: str = "sqlite:///./sentinel_dev.db"
    # Optional privileged connection used only by Alembic migrations. Defaults to database_url.
    migration_database_url: str | None = None
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_echo: bool = False

    # --- Auth ------------------------------------------------------------------------------
    jwt_secret: str = Field(default="", repr=False)
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "sentinel-x"
    jwt_audience: str = "sentinel-x-api"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 14
    # A rotated refresh token replayed within this window is treated as a benign race (two tabs
    # refreshing at once) rather than theft. Set to 0 for strict reuse detection.
    refresh_reuse_grace_seconds: int = 20
    refresh_cookie_name: str = "sx_refresh"
    refresh_cookie_secure: bool = False
    refresh_cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    refresh_cookie_domain: str | None = None
    password_min_length: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    allow_registration: bool = True

    # --- HTTP ------------------------------------------------------------------------------
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    rate_limit_enabled: bool = True
    rate_limit_auth_per_minute: int = 10
    # Refresh tokens are unguessable (384-bit), so this only guards against abuse; it must be
    # generous enough for many users behind one NAT reloading pages.
    rate_limit_refresh_per_minute: int = 120
    rate_limit_default_per_minute: int = 300

    # --- Devices, agents & ingestion (Phase 2) ---------------------------------------------
    enrollment_token_max_hours: int = 168
    device_offline_after_seconds: int = 180
    device_sweep_interval_seconds: int = 60
    agent_default_heartbeat_seconds: int = 60
    rate_limit_agent_per_minute: int = 120  # per device
    ingest_max_events_per_batch: int = 100
    ingest_max_raw_bytes: int = 16_384  # per event
    event_dedup_window_minutes: int = 10
    event_max_clock_skew_seconds: int = 300
    event_max_age_days: int = 7
    bruteforce_threshold: int = 5
    bruteforce_window_minutes: int = 5

    # --- Threat intelligence (Phase 3) ------------------------------------------------------
    # Optional API keys. Without them the related providers report "not configured" — results
    # never pretend a source was consulted.
    abusech_auth_key: str = Field(default="", repr=False)  # URLhaus, MalwareBazaar, ThreatFox
    abuseipdb_api_key: str = Field(default="", repr=False)
    virustotal_api_key: str = Field(default="", repr=False)
    nvd_api_key: str = Field(default="", repr=False)  # optional: raises NVD rate limits
    intel_http_timeout_seconds: float = 8.0
    intel_offline: bool = False  # disable all outbound intel calls (air-gapped labs)
    rate_limit_investigations_per_minute: int = 20

    # --- Security Brain (Phase 4) -----------------------------------------------------------
    # "none" = deterministic engine only. No model provider ships in this release; the value is
    # validated so a typo cannot silently pretend an AI model is analysing your data.
    ai_provider: Literal["none"] = "none"
    brain_auto_triage: bool = True  # analyse every new alert automatically (deterministic, cheap)
    brain_lookback_days: int = Field(default=7, ge=1, le=90)
    rate_limit_brain_per_minute: int = 30

    # --- Realtime ----------------------------------------------------------------------------
    ws_auth_timeout_seconds: int = 10
    ws_ping_interval_seconds: int = 25
    ws_revalidate_seconds: int = 300

    @field_validator("database_url", "migration_database_url")
    @classmethod
    def _normalize_db_url(cls, value: str | None) -> str | None:
        return normalize_database_url(value) if value else value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [o.strip().rstrip("/") for o in value.split(",") if o.strip()]
        return value

    @model_validator(mode="after")
    def _validate_security(self) -> Settings:
        if self.environment == "production":
            if self.jwt_secret in _PLACEHOLDER_SECRETS or len(self.jwt_secret) < 32:
                raise ValueError(
                    "JWT_SECRET must be set to a random value of at least 32 characters in production"
                )
            if self.database_url.startswith("sqlite"):
                raise ValueError("SQLite is for local development only; set a PostgreSQL DATABASE_URL")
            if not self.refresh_cookie_secure:
                raise ValueError("REFRESH_COOKIE_SECURE must be true in production")
            if "*" in self.cors_origins:
                raise ValueError("Wildcard CORS origins are not allowed with credentialed requests")
        if self.refresh_cookie_samesite == "none" and not self.refresh_cookie_secure:
            raise ValueError("REFRESH_COOKIE_SAMESITE=none requires REFRESH_COOKIE_SECURE=true")
        return self

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def effective_jwt_secret(self) -> str:
        """Development falls back to a per-process random secret (tokens die on restart)."""
        if self.jwt_secret and self.jwt_secret not in _PLACEHOLDER_SECRETS:
            return self.jwt_secret
        return _dev_secret()


@lru_cache
def _dev_secret() -> str:
    import secrets

    return secrets.token_urlsafe(48)


@lru_cache
def get_settings() -> Settings:
    return Settings()
