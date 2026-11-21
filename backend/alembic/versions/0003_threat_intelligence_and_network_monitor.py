"""Phase 3: threat intelligence and network monitor

* ``network_scopes`` (RLS tenant_isolation): ranges an organization is authorized to assess
* ``investigations.timeline`` / ``investigations.details``; ``network_assets.source``
* new permissions intel:read/manage and network:read/manage linked to the system roles

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-21
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

NEW_PERMISSIONS = {
    "intel:read": ("View threat intelligence, indicators and vulnerabilities", ["owner", "admin", "analyst", "viewer"]),
    "intel:manage": ("Manage the indicator watchlist and refresh vulnerability feeds", ["owner", "admin", "analyst"]),
    "network:read": ("View network assets and authorized scopes", ["owner", "admin", "analyst", "viewer"]),
    "network:manage": ("Manage authorized scopes and import network scans", ["owner", "admin", "analyst"]),
}

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('network_scopes',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('cidr', sa.String(length=64), nullable=False),
    sa.Column('label', sa.String(length=120), nullable=False),
    sa.Column('is_private', sa.Boolean(), nullable=False),
    sa.Column('attested_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['attested_by'], ['users.id'], name=op.f('fk_network_scopes_attested_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_network_scopes_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_network_scopes')),
    sa.UniqueConstraint('organization_id', 'cidr', name=op.f('uq_network_scopes_organization_id_cidr'))
    )
    op.add_column('investigations', sa.Column('timeline', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), server_default=sa.text("'[]'"), nullable=False))
    op.add_column('investigations', sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), server_default=sa.text("'{}'"), nullable=False))
    op.add_column('network_assets', sa.Column('source', sa.String(length=16), server_default='import', nullable=False))
    op.add_column('vulnerability_records', sa.Column('title', sa.String(length=255), nullable=True))
    op.add_column('vulnerability_records', sa.Column('vendor', sa.String(length=120), nullable=True))
    op.add_column('vulnerability_records', sa.Column('product', sa.String(length=120), nullable=True))
    op.add_column('vulnerability_records', sa.Column('kev_due_date', sa.DateTime(timezone=True), nullable=True))
    op.add_column('vulnerability_records', sa.Column('kev_required_action', sa.Text(), nullable=True))
    op.add_column('vulnerability_records', sa.Column('known_ransomware_use', sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column('vulnerability_records', sa.Column('cwes', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), server_default=sa.text("'[]'"), nullable=False))
    op.create_index('ix_vulnerability_records_kev', 'vulnerability_records', ['in_cisa_kev', 'kev_date_added'], unique=False)

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE network_scopes ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE network_scopes FORCE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY tenant_isolation ON network_scopes "
            "USING (organization_id = app_current_org()) WITH CHECK (organization_id = app_current_org())"
        )
        op.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                    REVOKE ALL ON network_scopes FROM anon;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                    REVOKE ALL ON network_scopes FROM authenticated;
                END IF;
            END $$;
        """)
        # Identity tables are FORCE RLS-gated on the API context; seed inside that context.
        op.execute("SELECT set_config('app.current_context', 'api', true)")

    permissions = sa.table("permissions", sa.column("id", sa.Uuid()), sa.column("key", sa.String()),
                           sa.column("description", sa.String()), sa.column("created_at", sa.DateTime(timezone=True)))
    role_permissions = sa.table("role_permissions", sa.column("role_id", sa.Uuid()), sa.column("permission_id", sa.Uuid()))
    roles = {key: rid for rid, key in bind.execute(
        sa.text("SELECT id, key FROM roles WHERE organization_id IS NULL")).all()}
    now = datetime.now(UTC)
    for key, (description, role_keys) in NEW_PERMISSIONS.items():
        pid = uuid.uuid4()
        op.bulk_insert(permissions, [{"id": pid, "key": key, "description": description, "created_at": now}])
        op.bulk_insert(role_permissions, [
            {"role_id": uuid.UUID(str(roles[r])) if not isinstance(roles[r], uuid.UUID) else roles[r], "permission_id": pid}
            for r in role_keys if r in roles
        ])


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("SELECT set_config('app.current_context', 'api', true)")
    keys = list(NEW_PERMISSIONS)
    bind.execute(sa.text(
        "DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE key IN :k)"
    ).bindparams(sa.bindparam("k", expanding=True)), {"k": keys})
    bind.execute(sa.text("DELETE FROM permissions WHERE key IN :k").bindparams(sa.bindparam("k", expanding=True)), {"k": keys})
    op.drop_index('ix_vulnerability_records_kev', table_name='vulnerability_records')
    for col in ('cwes', 'known_ransomware_use', 'kev_required_action', 'kev_due_date', 'product', 'vendor', 'title'):
        op.drop_column('vulnerability_records', col)
    op.drop_column('network_assets', 'source')
    op.drop_column('investigations', 'details')
    op.drop_column('investigations', 'timeline')
    op.drop_table('network_scopes')
