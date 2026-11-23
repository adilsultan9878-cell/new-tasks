"""PostgreSQL Row-Level Security: the database itself enforces tenant isolation, even for a
query that forgets its WHERE clause. Runs only against PostgreSQL (TEST_DATABASE_URL)."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app.core.config import get_settings


@pytest.fixture
def app_engine(postgres_only):
    engine = create_engine(get_settings().database_url)  # the least-privileged runtime role
    yield engine
    engine.dispose()


def _insert_device(conn, org_id):
    now = datetime.now(UTC)
    conn.execute(
        text(
            "INSERT INTO devices (id, organization_id, name, device_type, status, enrollment_status, "
            "location, tags, attributes, is_simulated, created_at, updated_at) VALUES "
            "(:id, :org, 'dev', 'server', 'online', 'enrolled', '{}', '[]', '{}', false, :now, :now)"
        ),
        {"id": uuid.uuid4(), "org": org_id, "now": now},
    )


def _ctx(conn, org_id=None, user_id=None):
    conn.execute(
        text(
            "SELECT set_config('app.current_context', 'api', true), "
            "set_config('app.current_org_id', :o, true), "
            "set_config('app.current_user_id', :u, true)"
        ),
        {"o": str(org_id or ""), "u": str(user_id or "")},
    )


def test_runtime_role_is_not_privileged(app_engine):
    with app_engine.connect() as conn:
        assert (
            conn.scalar(text("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user"))
            is False
        )


def test_rls_scopes_rows_to_current_org(app_engine, account_factory):
    alice, bob = account_factory("alice"), account_factory("bob")
    org_a = alice.create_org("Alpha")["organization"]["id"]
    org_b = bob.create_org("Bravo")["organization"]["id"]

    for org in (org_a, org_a, org_b):
        with app_engine.begin() as conn:
            _ctx(conn, org)
            _insert_device(conn, org)

    with app_engine.begin() as conn:
        _ctx(conn, org_a)
        rows = conn.execute(text("SELECT organization_id FROM devices")).scalars().all()  # no WHERE!
        assert len(rows) == 2 and {str(r) for r in rows} == {org_a}

    with app_engine.begin() as conn:
        _ctx(conn, None)
        assert conn.scalar(text("SELECT count(*) FROM devices")) == 0  # no tenant -> nothing


def test_rls_blocks_cross_tenant_writes(app_engine, account_factory):
    alice, bob = account_factory("alice"), account_factory("bob")
    org_a = alice.create_org("Alpha")["organization"]["id"]
    org_b = bob.create_org("Bravo")["organization"]["id"]
    with pytest.raises(ProgrammingError, match="row-level security"), app_engine.begin() as conn:
        _ctx(conn, org_a)
        _insert_device(conn, org_b)


def test_identity_tables_hidden_outside_api_context(app_engine, account_factory):
    account_factory()
    with app_engine.connect() as conn:
        assert conn.scalar(text("SELECT count(*) FROM users")) == 0
    with app_engine.begin() as conn:
        _ctx(conn)
        assert conn.scalar(text("SELECT count(*) FROM users")) == 1


def test_audit_log_is_append_only(app_engine, admin_engine, account_factory):
    alice = account_factory()
    org = alice.create_org("Alpha")["organization"]["id"]
    with app_engine.begin() as conn:
        _ctx(conn, org)
        changed = conn.execute(text("UPDATE audit_logs SET action = 'tampered'")).rowcount
        deleted = conn.execute(text("DELETE FROM audit_logs")).rowcount
        assert changed == 0 and deleted == 0  # RLS grants no UPDATE/DELETE at all
    # Even the table owner is stopped by the trigger.
    with pytest.raises(DBAPIError, match="append-only"), admin_engine.begin() as conn:
        conn.execute(text("UPDATE audit_logs SET action = 'tampered'"))


def test_every_tenant_table_has_forced_rls_policy(app_engine, admin_engine):
    """Guard rail: a new tenant table without RLS fails the build."""
    from app.models import TENANT_TABLES

    with admin_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
                "EXISTS (SELECT 1 FROM pg_policies p "
                "WHERE p.tablename = c.relname AND p.policyname = 'tenant_isolation') "
                "FROM pg_class c WHERE c.relname = ANY(:t)"
            ),
            {"t": list(TENANT_TABLES)},
        ).all()
    assert {r[0] for r in rows} == set(TENANT_TABLES)
    assert all(r[1] and r[2] and r[3] for r in rows), [r for r in rows if not (r[1] and r[2] and r[3])]


def test_security_functions_pin_search_path(postgres_only, admin_engine):
    """Guard rail (Supabase lint 0011): every function in public has a fixed search_path, so a
    shadowing object on the caller's path cannot subvert an RLS policy."""
    with admin_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT p.proname, p.proconfig FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'"
            )
        ).all()
    names = {r[0] for r in rows}
    assert {"app_current_org", "app_current_user", "app_api_context", "audit_logs_append_only"} <= names
    unpinned = [r[0] for r in rows if not any(c.startswith("search_path=") for c in (r[1] or []))]
    assert unpinned == []
