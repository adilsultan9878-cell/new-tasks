"""Phase 10: e-mail link tokens and invitations

* ``email_tokens``: single-use password-reset / verification tokens (SHA-256 only, expiring)
* ``invitations``: invitations to an organization by e-mail address (token hash, role, expiry)
* both are identity tables like ``user_sessions``: FORCE RLS with the ``api_access`` policy (only
  reachable from an API transaction) and revoked from the Supabase Data API roles

Offline-safe: renders with ``alembic upgrade 0009:0010 --sql``.

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-26
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0010'
down_revision: str | None = '0009'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_TABLES = ("email_tokens", "invitations")


def upgrade() -> None:
    op.create_table('email_tokens',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('purpose', sa.String(length=16), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("purpose IN ('reset', 'verify')", name=op.f('ck_email_tokens_purpose')),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_email_tokens_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_email_tokens')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_email_tokens_token_hash'))
    )
    op.create_index('ix_email_tokens_user', 'email_tokens', ['user_id', 'purpose'])
    op.create_table('invitations',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('role_id', sa.Uuid(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('invited_by', sa.Uuid(), nullable=True),
    sa.Column('emailed', sa.Boolean(), server_default=sa.false(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('accepted_by', sa.Uuid(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_invitations_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_invitations_role_id_roles'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['invited_by'], ['users.id'], name=op.f('fk_invitations_invited_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['accepted_by'], ['users.id'], name=op.f('fk_invitations_accepted_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_invitations')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_invitations_token_hash'))
    )
    op.create_index('ix_invitations_org', 'invitations', ['organization_id', 'accepted_at'])
    op.create_index('ix_invitations_email', 'invitations', ['email'])

    if op.get_context().dialect.name != "postgresql":
        return
    for table in NEW_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY api_access ON {table} USING (app_api_context()) WITH CHECK (app_api_context())")
    op.execute("""
        DO $$
        DECLARE r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE 'REVOKE ALL ON email_tokens, invitations FROM ' || quote_ident(r);
                END IF;
            END LOOP;
        END $$;
    """)


def downgrade() -> None:
    op.drop_index('ix_invitations_email', table_name='invitations')
    op.drop_index('ix_invitations_org', table_name='invitations')
    op.drop_table('invitations')
    op.drop_index('ix_email_tokens_user', table_name='email_tokens')
    op.drop_table('email_tokens')
