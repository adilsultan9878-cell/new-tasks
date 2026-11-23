"""Pin search_path on the RLS helper and audit trigger functions

Without a fixed search_path, a role that can create objects in a schema earlier on the
caller's path could shadow ``current_setting``/``to_jsonb`` and subvert the policies that call
these functions (Supabase linter 0011). Their bodies only use pg_catalog built-ins, which
are always resolved first, so an empty search_path is safe. A pinned SQL function is no longer
inlined, but it stays STABLE and is still used as an index condition by the RLS predicates.

PostgreSQL only; SQLite has neither functions nor RLS.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-23
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

FUNCTIONS = (
    "app_current_org()",
    "app_current_user()",
    "app_api_context()",
    "audit_logs_append_only()",
)

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_context().dialect.name != "postgresql":
        return
    for fn in FUNCTIONS:
        op.execute(f"ALTER FUNCTION {fn} SET search_path = ''")


def downgrade() -> None:
    if op.get_context().dialect.name != "postgresql":
        return
    for fn in FUNCTIONS:
        op.execute(f"ALTER FUNCTION {fn} RESET search_path")
