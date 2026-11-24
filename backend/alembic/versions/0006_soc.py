"""Phase 5: SENTINEL X SOC (incidents, response actions, evidence vault, reports)

* ``incidents.timeline`` (append-only history) and a unique reference per organization
* ``alerts.acknowledged_at`` for time-to-acknowledge metrics
* ``response_actions``: title, reason, reversible flag, allow-listed ``action_type``
* ``evidence``: title, filename, content type; new ``evidence_blobs`` table (RLS tenant_isolation)
* PostgreSQL triggers: stored evidence bytes are immutable; an evidence item's hash, size and
  type cannot change and its chain of custody can only grow

All permissions used by this phase (incidents, responses, evidence, reports) were seeded in 0001.
Offline-safe: renders with ``alembic upgrade 0005:0006 --sql``.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-24
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

ACTION_TYPES = ("notify_team", "heighten_monitoring", "block_indicator", "revoke_device", "suspend_member")

revision: str = '0006'
down_revision: str | None = '0005'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('evidence_blobs',
    sa.Column('evidence_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['evidence_id'], ['evidence.id'], name=op.f('fk_evidence_blobs_evidence_id_evidence'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_evidence_blobs_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('evidence_id', name=op.f('pk_evidence_blobs'))
    )
    with op.batch_alter_table('alerts') as batch:
        batch.add_column(sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table('evidence') as batch:
        batch.add_column(sa.Column('title', sa.String(length=255), nullable=True))
        batch.add_column(sa.Column('filename', sa.String(length=255), nullable=True))
        batch.add_column(sa.Column('content_type', sa.String(length=120), nullable=True))
    with op.batch_alter_table('incidents') as batch:
        batch.add_column(sa.Column(
            'timeline', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'),
            server_default=sa.text("'[]'"), nullable=False,
        ))
        batch.create_unique_constraint(op.f('uq_incidents_organization_id_reference'), ['organization_id', 'reference'])
    with op.batch_alter_table('response_actions') as batch:
        batch.add_column(sa.Column('title', sa.String(length=255), nullable=True))
        batch.add_column(sa.Column('reason', sa.Text(), nullable=True))
        batch.add_column(sa.Column('reversible', sa.Boolean(), server_default=sa.false(), nullable=False))
        batch.create_check_constraint(
            op.f('ck_response_actions_action_type'),
            "action_type IN (" + ", ".join(f"'{a}'" for a in ACTION_TYPES) + ")",
        )
        batch.create_index('ix_response_actions_incident', ['incident_id'])

    if op.get_context().dialect.name != "postgresql":
        return
    op.execute("ALTER TABLE evidence_blobs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE evidence_blobs FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON evidence_blobs "
        "USING (organization_id = app_current_org()) WITH CHECK (organization_id = app_current_org())"
    )
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                REVOKE ALL ON evidence_blobs FROM anon;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                REVOKE ALL ON evidence_blobs FROM authenticated;
            END IF;
        END $$;
    """)
    op.execute("""
        CREATE OR REPLACE FUNCTION evidence_blobs_immutable() RETURNS trigger LANGUAGE plpgsql
        SET search_path = '' AS $$
        BEGIN
            RAISE EXCEPTION 'evidence content is immutable';
        END $$;
        CREATE TRIGGER evidence_blobs_immutable BEFORE UPDATE ON evidence_blobs
            FOR EACH ROW EXECUTE FUNCTION evidence_blobs_immutable();

        CREATE OR REPLACE FUNCTION evidence_integrity() RETURNS trigger LANGUAGE plpgsql
        SET search_path = '' AS $$
        BEGIN
            IF NEW.sha256 IS DISTINCT FROM OLD.sha256
               OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
               OR NEW.evidence_type IS DISTINCT FROM OLD.evidence_type
               OR NEW.collected_at IS DISTINCT FROM OLD.collected_at THEN
                RAISE EXCEPTION 'evidence hash, size, type and collection time are immutable';
            END IF;
            IF jsonb_array_length(NEW.chain_of_custody) < jsonb_array_length(OLD.chain_of_custody)
               OR NEW.chain_of_custody -> 0 IS DISTINCT FROM OLD.chain_of_custody -> 0 THEN
                RAISE EXCEPTION 'chain of custody is append-only';
            END IF;
            RETURN NEW;
        END $$;
        CREATE TRIGGER evidence_integrity BEFORE UPDATE ON evidence
            FOR EACH ROW EXECUTE FUNCTION evidence_integrity();
    """)
    # Trigger functions are never called directly; firing a trigger does not check EXECUTE.
    op.execute("REVOKE ALL ON FUNCTION evidence_blobs_immutable(), evidence_integrity() FROM PUBLIC")
    # Supabase grants EXECUTE on new functions to its Data API roles by default: take it back.
    op.execute("""
        DO $$
        DECLARE r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE 'REVOKE ALL ON FUNCTION evidence_blobs_immutable(), evidence_integrity() FROM ' || quote_ident(r);
                END IF;
            END LOOP;
        END $$;
    """)


def downgrade() -> None:
    if op.get_context().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS evidence_integrity ON evidence")
        op.execute("DROP FUNCTION IF EXISTS evidence_integrity()")
        op.execute("DROP TRIGGER IF EXISTS evidence_blobs_immutable ON evidence_blobs")
        op.execute("DROP FUNCTION IF EXISTS evidence_blobs_immutable()")
    with op.batch_alter_table('response_actions') as batch:
        batch.drop_index('ix_response_actions_incident')
        batch.drop_constraint(op.f('ck_response_actions_action_type'), type_='check')
        batch.drop_column('reversible')
        batch.drop_column('reason')
        batch.drop_column('title')
    with op.batch_alter_table('incidents') as batch:
        batch.drop_constraint(op.f('uq_incidents_organization_id_reference'), type_='unique')
        batch.drop_column('timeline')
    with op.batch_alter_table('evidence') as batch:
        batch.drop_column('content_type')
        batch.drop_column('filename')
        batch.drop_column('title')
    with op.batch_alter_table('alerts') as batch:
        batch.drop_column('acknowledged_at')
    op.drop_table('evidence_blobs')
