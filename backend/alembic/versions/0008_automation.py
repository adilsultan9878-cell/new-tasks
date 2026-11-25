"""Phase 8: automation (workflows, approval-gated runs, signed webhooks)

* ``integrations`` become webhook destinations: ``secret_version`` (secrets are derived from
  AUTOMATION_SIGNING_KEY, never stored), consecutive ``failure_count``, ``last_error``, status CHECK
* ``automation_workflows``: allow-listed ``steps``, inbound ``secret_version``, ``next_run_at``,
  ``last_status``, trigger_type CHECK
* new ``automation_runs`` (history and approvals) and ``webhook_deliveries`` (outbox), both RLS
  tenant_isolation and revoked from the Supabase Data API roles
* new permission ``automation:read`` (all roles); configuring uses the existing
  ``integrations:manage``, approving uses ``responses:approve``

Offline-safe: renders with ``alembic upgrade 0007:0008 --sql``.

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-25
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0008'
down_revision: str | None = '0007'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_TABLES = ("automation_runs", "webhook_deliveries")
NEW_PERMISSIONS = {
    "automation:read": ("View workflows, webhooks and automation history", ["owner", "admin", "analyst", "viewer"]),
}
RUN_STATUSES = ("awaiting_approval", "succeeded", "failed", "rejected", "expired", "skipped")
TRIGGERS = ("event", "schedule", "manual", "webhook")


def _json() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.execute("UPDATE integrations SET status = 'disabled' WHERE status NOT IN ('active', 'disabled')")
    with op.batch_alter_table('integrations') as batch:
        batch.add_column(sa.Column('secret_version', sa.Integer(), server_default='1', nullable=False))
        batch.add_column(sa.Column('failure_count', sa.Integer(), server_default='0', nullable=False))
        batch.add_column(sa.Column('last_error', sa.Text(), nullable=True))
        batch.create_check_constraint(op.f('ck_integrations_status'), "status IN ('active', 'disabled')")

    op.execute("UPDATE automation_workflows SET trigger_type = 'manual' WHERE trigger_type NOT IN ('event', 'schedule', 'manual', 'webhook')")
    with op.batch_alter_table('automation_workflows') as batch:
        batch.add_column(sa.Column('steps', _json(), server_default=sa.text("'[]'"), nullable=False))
        batch.add_column(sa.Column('secret_version', sa.Integer(), server_default='1', nullable=False))
        batch.add_column(sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column('last_status', sa.String(length=24), nullable=True))
        batch.create_check_constraint(op.f('ck_automation_workflows_trigger_type'), _in('trigger_type', TRIGGERS))

    op.create_table('automation_runs',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('workflow_id', sa.Uuid(), nullable=False),
    sa.Column('workflow_name', sa.String(length=120), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('trigger_kind', sa.String(length=16), nullable=False),
    sa.Column('trigger_label', sa.String(length=255), nullable=False),
    sa.Column('context', _json(), nullable=False),
    sa.Column('steps', _json(), nullable=False),
    sa.Column('requested_by', sa.Uuid(), nullable=True),
    sa.Column('decided_by', sa.Uuid(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('decision_comment', sa.Text(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('dedupe_key', sa.String(length=64), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('is_simulated', sa.Boolean(), server_default=sa.false(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint(_in('status', RUN_STATUSES), name=op.f('ck_automation_runs_status')),
    sa.CheckConstraint(_in('trigger_kind', TRIGGERS), name=op.f('ck_automation_runs_trigger_kind')),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_automation_runs_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['workflow_id'], ['automation_workflows.id'], name=op.f('fk_automation_runs_workflow_id_automation_workflows'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name=op.f('fk_automation_runs_requested_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['decided_by'], ['users.id'], name=op.f('fk_automation_runs_decided_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_automation_runs')),
    sa.UniqueConstraint('workflow_id', 'dedupe_key', name=op.f('uq_automation_runs_workflow_id_dedupe_key'))
    )
    op.create_index('ix_automation_runs_org_created', 'automation_runs', ['organization_id', 'created_at'])
    op.create_index('ix_automation_runs_org_status', 'automation_runs', ['organization_id', 'status'])

    op.create_table('webhook_deliveries',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('integration_id', sa.Uuid(), nullable=False),
    sa.Column('run_id', sa.Uuid(), nullable=True),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('payload', _json(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
    sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_status_code', sa.Integer(), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('response_ms', sa.Integer(), nullable=True),
    sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('is_simulated', sa.Boolean(), server_default=sa.false(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'delivered', 'failed')", name=op.f('ck_webhook_deliveries_status')),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_webhook_deliveries_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['integration_id'], ['integrations.id'], name=op.f('fk_webhook_deliveries_integration_id_integrations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['run_id'], ['automation_runs.id'], name=op.f('fk_webhook_deliveries_run_id_automation_runs'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_webhook_deliveries'))
    )
    op.create_index('ix_webhook_deliveries_due', 'webhook_deliveries', ['status', 'next_attempt_at'])
    op.create_index('ix_webhook_deliveries_integration', 'webhook_deliveries', ['integration_id', 'created_at'])

    dialect = op.get_context().dialect.name  # works online and in offline (--sql) mode
    if dialect == "postgresql":
        for table in NEW_TABLES:
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(
                f"CREATE POLICY tenant_isolation ON {table} "
                "USING (organization_id = app_current_org()) WITH CHECK (organization_id = app_current_org())"
            )
        op.execute("""
            DO $$
            DECLARE r text;
            BEGIN
                FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                        EXECUTE 'REVOKE ALL ON automation_runs, webhook_deliveries FROM ' || quote_ident(r);
                    END IF;
                END LOOP;
            END $$;
        """)
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

    op.drop_index('ix_webhook_deliveries_integration', table_name='webhook_deliveries')
    op.drop_index('ix_webhook_deliveries_due', table_name='webhook_deliveries')
    op.drop_table('webhook_deliveries')
    op.drop_index('ix_automation_runs_org_status', table_name='automation_runs')
    op.drop_index('ix_automation_runs_org_created', table_name='automation_runs')
    op.drop_table('automation_runs')
    with op.batch_alter_table('automation_workflows') as batch:
        batch.drop_constraint(op.f('ck_automation_workflows_trigger_type'), type_='check')
        for col in ('last_status', 'next_run_at', 'secret_version', 'steps'):
            batch.drop_column(col)
    with op.batch_alter_table('integrations') as batch:
        batch.drop_constraint(op.f('ck_integrations_status'), type_='check')
        for col in ('last_error', 'failure_count', 'secret_version'):
            batch.drop_column(col)
