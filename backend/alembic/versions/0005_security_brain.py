"""Phase 4: Security Brain (deterministic orchestrator and agents)

* ``agent_runs``: subject (alert / device / organization), creator, weighted risk score with its
  factor breakdown and data coverage, the read-only tool trace and the generated report
* ``agent_decisions``: the agent that made each decision and a severity for findings
* new permissions brain:read (all roles) and brain:run (owner, admin, analyst)

Both tables already have RLS (tenant_isolation) from 0001. Offline-safe: renders with
``alembic upgrade 0004:0005 --sql``.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-23
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

NEW_PERMISSIONS = {
    "brain:read": ("View Security Brain analyses, agent decisions and reports", ["owner", "admin", "analyst", "viewer"]),
    "brain:run": ("Run Security Brain analyses", ["owner", "admin", "analyst"]),
}

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    with op.batch_alter_table('agent_decisions') as batch:
        batch.add_column(sa.Column('agent_name', sa.String(length=64), nullable=True))
        batch.add_column(sa.Column('severity', sa.String(length=16), nullable=True))

    with op.batch_alter_table('agent_runs') as batch:
        batch.add_column(sa.Column('subject_type', sa.String(length=24), nullable=True))
        batch.add_column(sa.Column('subject_id', sa.Uuid(), nullable=True))
        batch.add_column(sa.Column('subject_label', sa.String(length=255), nullable=True))
        batch.add_column(sa.Column('created_by', sa.Uuid(), nullable=True))
        batch.add_column(sa.Column('risk_score', sa.Integer(), nullable=True))
        batch.add_column(sa.Column('risk_level', sa.String(length=16), nullable=True))
        batch.add_column(sa.Column('coverage', sa.Integer(), nullable=True))
        batch.add_column(sa.Column('factors', _json(), server_default=sa.text("'[]'"), nullable=False))
        batch.add_column(sa.Column('trace', _json(), server_default=sa.text("'[]'"), nullable=False))
        batch.add_column(sa.Column('report', sa.Text(), nullable=True))
        batch.create_foreign_key(
            op.f('fk_agent_runs_created_by_users'), 'users', ['created_by'], ['id'], ondelete='SET NULL'
        )
        batch.create_check_constraint(
            op.f('ck_agent_runs_subject_type'), "subject_type IN ('alert', 'device', 'organization')"
        )
        batch.create_check_constraint(
            op.f('ck_agent_runs_risk_score'), 'risk_score IS NULL OR (risk_score BETWEEN 0 AND 100)'
        )
        batch.create_check_constraint(
            op.f('ck_agent_runs_coverage'), 'coverage IS NULL OR (coverage BETWEEN 0 AND 100)'
        )
        batch.create_index('ix_agent_runs_org_subject', ['organization_id', 'subject_type', 'subject_id'])

    dialect = op.get_context().dialect.name  # works online and in offline (--sql) mode
    if dialect == "postgresql":
        # Identity tables are FORCE RLS-gated on the API context; seed inside that context.
        op.execute("SELECT set_config('app.current_context', 'api', true)")

    # Seed with plain SQL (no reads), so the migration also renders as an offline SQL script.
    for key, (description, role_keys) in NEW_PERMISSIONS.items():
        pid = uuid.uuid4()
        pid_value = pid.hex if dialect == "sqlite" else str(pid)  # SQLAlchemy's Uuid storage per dialect
        pid_expr = "CAST(:pid AS UUID)" if dialect == "postgresql" else ":pid"
        op.execute(sa.text(
            f"INSERT INTO permissions (id, key, description, created_at) VALUES ({pid_expr}, :key, :description, CURRENT_TIMESTAMP)"
        ).bindparams(pid=pid_value, key=key, description=description))
        role_list = ", ".join(f"'{r}'" for r in role_keys)  # constants defined above
        op.execute(sa.text(
            f"INSERT INTO role_permissions (role_id, permission_id) SELECT id, {pid_expr} FROM roles "
            f"WHERE organization_id IS NULL AND key IN ({role_list})"
        ).bindparams(pid=pid_value))


def downgrade() -> None:
    if op.get_context().dialect.name == "postgresql":
        op.execute("SELECT set_config('app.current_context', 'api', true)")
    keys = ", ".join(f"'{k}'" for k in NEW_PERMISSIONS)  # constants defined above
    op.execute(f"DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE key IN ({keys}))")
    op.execute(f"DELETE FROM permissions WHERE key IN ({keys})")

    with op.batch_alter_table('agent_runs') as batch:
        batch.drop_index('ix_agent_runs_org_subject')
        batch.drop_constraint(op.f('ck_agent_runs_coverage'), type_='check')
        batch.drop_constraint(op.f('ck_agent_runs_risk_score'), type_='check')
        batch.drop_constraint(op.f('ck_agent_runs_subject_type'), type_='check')
        batch.drop_constraint(op.f('fk_agent_runs_created_by_users'), type_='foreignkey')
        for col in ('report', 'trace', 'factors', 'coverage', 'risk_level', 'risk_score', 'created_by',
                    'subject_label', 'subject_id', 'subject_type'):
            batch.drop_column(col)

    with op.batch_alter_table('agent_decisions') as batch:
        batch.drop_column('severity')
        batch.drop_column('agent_name')
