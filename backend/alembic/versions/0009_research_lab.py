"""Phase 9: Research Lab (frozen labelled datasets, reproducible rule experiments)

* ``lab_datasets`` and ``lab_experiments`` (RLS tenant_isolation, revoked from the Data API roles)
* PostgreSQL trigger: a dataset's rows and hash, and an experiment's rule, hashes and results, can
  never change once written (delete is allowed, edit is not)
* new permissions ``lab:read`` (all roles) and ``lab:run`` (owner, admin, analyst)

Offline-safe: renders with ``alembic upgrade 0008:0009 --sql``.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-25
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0009'
down_revision: str | None = '0008'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_TABLES = ("lab_datasets", "lab_experiments")
NEW_PERMISSIONS = {
    "lab:read": ("View Research Lab datasets and experiments", ["owner", "admin", "analyst", "viewer"]),
    "lab:run": ("Build datasets and run Research Lab experiments", ["owner", "admin", "analyst"]),
}


def _json() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql')


def upgrade() -> None:
    op.create_table('lab_datasets',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('params', _json(), nullable=False),
    sa.Column('rows', _json(), nullable=False),
    sa.Column('row_count', sa.Integer(), nullable=False),
    sa.Column('label_counts', _json(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('includes_simulated', sa.Boolean(), server_default=sa.false(), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("source IN ('events', 'upload')", name=op.f('ck_lab_datasets_source')),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_lab_datasets_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_lab_datasets_created_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_lab_datasets'))
    )
    op.create_index('ix_lab_datasets_org_created', 'lab_datasets', ['organization_id', 'created_at'])
    op.create_table('lab_experiments',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('dataset_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('rule', _json(), nullable=False),
    sa.Column('rule_sha256', sa.String(length=64), nullable=False),
    sa.Column('dataset_sha256', sa.String(length=64), nullable=False),
    sa.Column('engine_version', sa.String(length=16), nullable=False),
    sa.Column('results', _json(), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_lab_experiments_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['dataset_id'], ['lab_datasets.id'], name=op.f('fk_lab_experiments_dataset_id_lab_datasets'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_lab_experiments_created_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_lab_experiments'))
    )
    op.create_index('ix_lab_experiments_org_created', 'lab_experiments', ['organization_id', 'created_at'])

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
                        EXECUTE 'REVOKE ALL ON lab_datasets, lab_experiments FROM ' || quote_ident(r);
                    END IF;
                END LOOP;
            END $$;
        """)
        op.execute("""
            CREATE OR REPLACE FUNCTION lab_immutable() RETURNS trigger LANGUAGE plpgsql
            SET search_path = '' AS $$
            BEGIN
                RAISE EXCEPTION 'research lab records are immutable (%)', TG_TABLE_NAME;
            END $$;
            CREATE TRIGGER lab_datasets_immutable BEFORE UPDATE ON lab_datasets
                FOR EACH ROW EXECUTE FUNCTION lab_immutable();
            CREATE TRIGGER lab_experiments_immutable BEFORE UPDATE ON lab_experiments
                FOR EACH ROW EXECUTE FUNCTION lab_immutable();
        """)
        op.execute("REVOKE ALL ON FUNCTION lab_immutable() FROM PUBLIC")
        op.execute("""
            DO $$
            DECLARE r text;
            BEGIN
                FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                        EXECUTE 'REVOKE ALL ON FUNCTION lab_immutable() FROM ' || quote_ident(r);
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
        op.execute("DROP TRIGGER IF EXISTS lab_experiments_immutable ON lab_experiments")
        op.execute("DROP TRIGGER IF EXISTS lab_datasets_immutable ON lab_datasets")
        op.execute("DROP FUNCTION IF EXISTS lab_immutable()")
    keys = ", ".join(f"'{k}'" for k in NEW_PERMISSIONS)  # constants defined above
    op.execute(f"DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE key IN ({keys}))")
    op.execute(f"DELETE FROM permissions WHERE key IN ({keys})")
    op.drop_index('ix_lab_experiments_org_created', table_name='lab_experiments')
    op.drop_table('lab_experiments')
    op.drop_index('ix_lab_datasets_org_created', table_name='lab_datasets')
    op.drop_table('lab_datasets')
