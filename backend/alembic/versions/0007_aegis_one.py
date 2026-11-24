"""Phase 6: AEGIS ONE (IoT sensors, actuators and cameras)

* ``sensors``: stable ``sensor_key`` per hub, actuator rules, breach state
* ``sensor_readings`` time series (RLS tenant_isolation)
* ``cameras``: stable ``camera_key`` per device, blur_people, last_event_at, retention bounds
* ``camera_snapshots`` (RLS tenant_isolation): stills, only while privacy mode is off, with expiry

Offline-safe: renders with ``alembic upgrade 0006:0007 --sql``.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-24
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NEW_TABLES = ("sensor_readings", "camera_snapshots")


def upgrade() -> None:
    op.create_table('sensor_readings',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('sensor_id', sa.Uuid(), nullable=False),
    sa.Column('value', sa.Float(), nullable=False),
    sa.Column('recorded_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_sensor_readings_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['sensor_id'], ['sensors.id'], name=op.f('fk_sensor_readings_sensor_id_sensors'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sensor_readings'))
    )
    op.create_index('ix_sensor_readings_sensor_time', 'sensor_readings', ['sensor_id', 'recorded_at'])
    op.create_table('camera_snapshots',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('camera_id', sa.Uuid(), nullable=False),
    sa.Column('event_type', sa.String(length=32), nullable=False),
    sa.Column('content_type', sa.String(length=32), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.Column('captured_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['camera_id'], ['cameras.id'], name=op.f('fk_camera_snapshots_camera_id_cameras'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_camera_snapshots_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_camera_snapshots'))
    )
    op.create_index('ix_camera_snapshots_camera_time', 'camera_snapshots', ['camera_id', 'captured_at'])

    with op.batch_alter_table('sensors') as batch:
        batch.add_column(sa.Column('sensor_key', sa.String(length=64), nullable=True))
        batch.add_column(sa.Column(
            'actuator_rules', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'),
            server_default=sa.text("'[]'"), nullable=False,
        ))
        batch.add_column(sa.Column('in_breach', sa.Boolean(), server_default=sa.false(), nullable=False))
        batch.create_unique_constraint(op.f('uq_sensors_organization_id_device_id_sensor_key'),
                                       ['organization_id', 'device_id', 'sensor_key'])
    with op.batch_alter_table('cameras') as batch:
        batch.add_column(sa.Column('camera_key', sa.String(length=64), nullable=True))
        batch.add_column(sa.Column('blur_people', sa.Boolean(), server_default=sa.true(), nullable=False))
        batch.add_column(sa.Column('last_event_at', sa.DateTime(timezone=True), nullable=True))
        batch.create_unique_constraint(op.f('uq_cameras_organization_id_device_id_camera_key'),
                                       ['organization_id', 'device_id', 'camera_key'])
        batch.create_check_constraint(op.f('ck_cameras_retention_days'), 'retention_days BETWEEN 1 AND 90')

    if op.get_context().dialect.name != "postgresql":
        return
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
                    EXECUTE 'REVOKE ALL ON sensor_readings, camera_snapshots FROM ' || quote_ident(r);
                END IF;
            END LOOP;
        END $$;
    """)


def downgrade() -> None:
    with op.batch_alter_table('cameras') as batch:
        batch.drop_constraint(op.f('ck_cameras_retention_days'), type_='check')
        batch.drop_constraint(op.f('uq_cameras_organization_id_device_id_camera_key'), type_='unique')
        batch.drop_column('last_event_at')
        batch.drop_column('blur_people')
        batch.drop_column('camera_key')
    with op.batch_alter_table('sensors') as batch:
        batch.drop_constraint(op.f('uq_sensors_organization_id_device_id_sensor_key'), type_='unique')
        batch.drop_column('in_breach')
        batch.drop_column('actuator_rules')
        batch.drop_column('sensor_key')
    op.drop_index('ix_camera_snapshots_camera_time', table_name='camera_snapshots')
    op.drop_table('camera_snapshots')
    op.drop_index('ix_sensor_readings_sensor_time', table_name='sensor_readings')
    op.drop_table('sensor_readings')
