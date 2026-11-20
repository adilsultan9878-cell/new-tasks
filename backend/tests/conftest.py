"""Test harness.

* Default: a throwaway SQLite database (fast, no services needed).
* Set TEST_DATABASE_URL to a PostgreSQL *admin* URL to run against PostgreSQL. A fresh database
  is created, migrated as the admin role, and the API then connects as the least-privileged
  ``sentinel_app`` role — so Row-Level Security is genuinely enforced during the whole suite.

Either way the schema is built by running the real Alembic migrations.
"""

from __future__ import annotations

import os
import secrets
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

BACKEND_DIR = Path(__file__).resolve().parents[1]
ADMIN_URL = os.environ.get("TEST_DATABASE_URL", "")
APP_ROLE_PASSWORD = "test-app-role-" + secrets.token_hex(6)

if ADMIN_URL:
    from app.core.config import normalize_database_url

    base = make_url(normalize_database_url(ADMIN_URL))
    test_db = f"sx_test_{secrets.token_hex(4)}"
    with create_engine(base, isolation_level="AUTOCOMMIT").connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{test_db}"'))
    MIGRATION_URL = base.set(database=test_db).render_as_string(hide_password=False)
    RUNTIME_URL = base.set(
        database=test_db, username="sentinel_app", password=APP_ROLE_PASSWORD
    ).render_as_string(hide_password=False)
    IS_POSTGRES = True
else:
    _tmp = Path(tempfile.mkdtemp()) / "sentinel_test.db"
    MIGRATION_URL = RUNTIME_URL = f"sqlite:///{_tmp}"
    IS_POSTGRES = False

os.environ.update(
    {
        "ENVIRONMENT": "test",
        "DATABASE_URL": RUNTIME_URL,
        "MIGRATION_DATABASE_URL": MIGRATION_URL,
        "JWT_SECRET": "test-secret-" + "x" * 40,
        "RATE_LIMIT_ENABLED": "true",
        "RATE_LIMIT_AUTH_PER_MINUTE": "1000",
        "RATE_LIMIT_DEFAULT_PER_MINUTE": "100000",
        "LOG_LEVEL": "WARNING",
    }
)


def _migrate() -> None:
    from alembic.config import Config

    from alembic import command

    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.attributes["url"] = MIGRATION_URL
    command.upgrade(cfg, "head")

    if IS_POSTGRES:
        engine = create_engine(MIGRATION_URL, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            exists = conn.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app'"))
            # DDL cannot take bound parameters; the password is generated hex, so it is safe inline.
            verb = "ALTER" if exists else "CREATE"
            conn.execute(
                text(f"{verb} ROLE sentinel_app LOGIN PASSWORD '{APP_ROLE_PASSWORD}' NOSUPERUSER NOBYPASSRLS")
            )
            conn.execute(text("GRANT USAGE ON SCHEMA public TO sentinel_app"))
            conn.execute(
                text("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app")
            )
            conn.execute(text("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO sentinel_app"))
        engine.dispose()


_migrate()

from fastapi.testclient import TestClient  # noqa: E402

from app.core.rate_limit import limiter  # noqa: E402
from app.main import app  # noqa: E402

PRESERVED = {"roles", "permissions", "role_permissions", "alembic_version"}


@pytest.fixture(scope="session")
def admin_engine():
    engine = create_engine(MIGRATION_URL)
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def _clean_state(admin_engine) -> Iterator[None]:
    limiter.reset()
    yield
    from app.db.base import Base

    tables = [t.name for t in reversed(Base.metadata.sorted_tables) if t.name not in PRESERVED]
    # DELETE (not TRUNCATE ... CASCADE, which would also wipe the seeded system roles that
    # reference organizations) in reverse dependency order.
    with admin_engine.begin() as conn:
        for name in tables:
            conn.execute(text(f"DELETE FROM {name}"))


def make_client() -> TestClient:
    return TestClient(app, headers={"user-agent": "pytest"})


@pytest.fixture
def client() -> TestClient:
    return make_client()


STRONG_PASSWORD = "Correct-Horse-Battery-42"


class Account:
    """A registered user with their own cookie jar and bearer token."""

    def __init__(self, email: str, full_name: str = "Test User", password: str = STRONG_PASSWORD):
        self.client = make_client()
        self.email = email
        self.password = password
        resp = self.client.post(
            "/api/v1/auth/register", json={"email": email, "password": password, "full_name": full_name}
        )
        assert resp.status_code == 201, resp.text
        self.token = resp.json()["access_token"]
        self.user = resp.json()["user"]

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, url: str, **kw: Any):
        return self.client.get(url, headers=self.headers, **kw)

    def post(self, url: str, **kw: Any):
        return self.client.post(url, headers=self.headers, **kw)

    def patch(self, url: str, **kw: Any):
        return self.client.patch(url, headers=self.headers, **kw)

    def delete(self, url: str, **kw: Any):
        return self.client.delete(url, headers=self.headers, **kw)

    def create_org(self, name: str = "Acme Security Lab", **extra: Any) -> dict[str, Any]:
        resp = self.post("/api/v1/organizations", json={"name": name, **extra})
        assert resp.status_code == 201, resp.text
        return resp.json()


@pytest.fixture
def account_factory():
    def _make(prefix: str = "user", **kw: Any) -> Account:
        return Account(f"{prefix}-{uuid.uuid4().hex[:8]}@example.com", **kw)

    return _make


@pytest.fixture
def postgres_only():
    if not IS_POSTGRES:
        pytest.skip("requires PostgreSQL (set TEST_DATABASE_URL)")


def pytest_sessionfinish(session, exitstatus) -> None:
    from app.db.session import get_engine

    get_engine().dispose()
    if IS_POSTGRES:
        url = make_url(MIGRATION_URL)
        with create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT").connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)'))
