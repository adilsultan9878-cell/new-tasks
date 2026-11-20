"""Phase 2: device enrollment tokens, agent telemetry/config, event de-duplication

* new tenant table ``enrollment_tokens`` (RLS tenant_isolation, like every tenant table)
* ``devices``: credential rotation time, latest telemetry, desired agent config + version
* ``security_events``: occurrence counter and last occurrence for de-duplicated events

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-20
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('enrollment_tokens',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('label', sa.String(length=120), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('device_type', sa.String(length=24), nullable=False),
    sa.Column('max_uses', sa.Integer(), nullable=False),
    sa.Column('use_count', sa.Integer(), server_default='0', nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint('max_uses BETWEEN 1 AND 1000', name=op.f('ck_enrollment_tokens_max_uses')),
    sa.CheckConstraint('use_count >= 0', name=op.f('ck_enrollment_tokens_use_count')),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_enrollment_tokens_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_enrollment_tokens_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_enrollment_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_enrollment_tokens_token_hash'))
    )
    op.create_index('ix_enrollment_tokens_org_created', 'enrollment_tokens', ['organization_id', 'created_at'], unique=False)
    op.add_column('devices', sa.Column('credential_rotated_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('devices', sa.Column('telemetry', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), server_default=sa.text("'{}'"), nullable=False))
    op.add_column('devices', sa.Column('config', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), server_default=sa.text("'{}'"), nullable=False))
    op.add_column('devices', sa.Column('config_version', sa.Integer(), server_default='1', nullable=False))
    op.add_column('security_events', sa.Column('occurrence_count', sa.Integer(), server_default='1', nullable=False))
    op.add_column('security_events', sa.Column('last_occurred_at', sa.DateTime(timezone=True), nullable=True))

    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY tenant_isolation ON enrollment_tokens "
            "USING (organization_id = app_current_org()) "
            "WITH CHECK (organization_id = app_current_org())"
        )
        # Supabase Data API roles never get access (mirrors 0001).
        op.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                    REVOKE ALL ON enrollment_tokens FROM anon;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                    REVOKE ALL ON enrollment_tokens FROM authenticated;
                END IF;
            END $$;
        """)


def downgrade() -> None:
    op.drop_column('security_events', 'last_occurred_at')
    op.drop_column('security_events', 'occurrence_count')
    op.drop_column('devices', 'config_version')
    op.drop_column('devices', 'config')
    op.drop_column('devices', 'telemetry')
    op.drop_column('devices', 'credential_rotated_at')
    op.drop_index('ix_enrollment_tokens_org_created', table_name='enrollment_tokens')
    op.drop_table('enrollment_tokens')
