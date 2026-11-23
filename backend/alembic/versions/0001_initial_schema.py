"""initial schema: identity, tenancy, RBAC, audit and security-operations tables

Besides the tables this migration installs the PostgreSQL security layer:
  * Row-Level Security on every table (tenant isolation keyed on app.current_org_id)
  * an append-only trigger on audit_logs
  * revocation of Supabase Data API roles (anon / authenticated) when they exist
and seeds the system roles and permissions (frozen snapshot of app/rbac/catalog.py).

Revision ID: 0001
Revises: 
Create Date: 2026-11-20 19:07:39.116622
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# --- Frozen RBAC snapshot (never import app code from migrations) ----------------------------
PERMISSIONS = {
    "org:read": "View organization profile",
    "org:update": "Edit organization profile and settings",
    "members:read": "View organization members",
    "members:manage": "Add, remove and change roles of members",
    "audit:read": "View the organization audit log",
    "dashboard:read": "View the Command Center",
    "devices:read": "View devices, cameras and sensors",
    "devices:manage": "Enroll, update and revoke devices",
    "events:read": "View security events",
    "events:ingest": "Submit security events",
    "alerts:read": "View alerts",
    "alerts:manage": "Triage and resolve alerts",
    "incidents:read": "View incidents",
    "incidents:manage": "Create and manage incidents",
    "investigations:run": "Run threat investigations",
    "responses:propose": "Propose defensive response actions",
    "responses:approve": "Approve or reject high-impact response actions",
    "evidence:manage": "Collect and manage forensic evidence",
    "integrations:manage": "Configure external integrations and workflows",
    "reports:read": "View reports",
    "reports:manage": "Generate and manage reports",
}
_READ = [p for p in PERMISSIONS if p.endswith(":read")]
ROLES = {
    "owner": ("Owner", 100, "Full control of the organization, including ownership transfer.",
              list(PERMISSIONS)),
    "admin": ("Administrator", 80, "Manages members, settings, integrations and approvals.",
              list(PERMISSIONS)),
    "analyst": ("Security Analyst", 50,
                "Investigates and responds to security events. Cannot manage members.",
                _READ + ["devices:manage", "events:ingest", "alerts:manage", "incidents:manage",
                         "investigations:run", "responses:propose", "evidence:manage",
                         "reports:manage"]),
    "viewer": ("Viewer", 10, "Read-only access to the organization's security data.", _READ),
}

TENANT_TABLES = (
    "devices", "cameras", "sensors", "network_assets", "security_events", "incidents", "alerts",
    "investigations", "threat_indicators", "evidence", "agent_runs", "agent_decisions",
    "response_actions", "approvals", "integrations", "automation_workflows", "reports",
)
# Shared/identity tables: readable only from an API transaction (app.current_context = 'api').
CONTEXT_TABLES = (
    "users", "organizations", "organization_members", "roles", "permissions", "role_permissions",
    "user_sessions", "vulnerability_records",
)

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('permissions',
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_permissions')),
    sa.UniqueConstraint('key', name=op.f('uq_permissions_key'))
    )
    op.create_table('users',
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('full_name', sa.String(length=120), nullable=False),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('failed_login_count', sa.Integer(), server_default='0', nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('email', name=op.f('uq_users_email'))
    )
    op.create_table('vulnerability_records',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.Column('cvss_vector', sa.String(length=255), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_modified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('in_cisa_kev', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('kev_date_added', sa.DateTime(timezone=True), nullable=True),
    sa.Column('references', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint('cvss_score IS NULL OR (cvss_score BETWEEN 0 AND 10)', name=op.f('ck_vulnerability_records_cvss_score')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_vulnerability_records')),
    sa.UniqueConstraint('cve_id', name=op.f('uq_vulnerability_records_cve_id'))
    )
    op.create_table('organizations',
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('slug', sa.String(length=80), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('industry', sa.String(length=80), nullable=True),
    sa.Column('plan', sa.String(length=32), server_default='free', nullable=False),
    sa.Column('settings', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_organizations_created_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_organizations')),
    sa.UniqueConstraint('slug', name=op.f('uq_organizations_slug'))
    )
    op.create_table('user_sessions',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('family_id', sa.Uuid(), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_reason', sa.String(length=64), nullable=True),
    sa.Column('replaced_by_id', sa.Uuid(), nullable=True),
    sa.Column('ip_address', sa.String(length=45), nullable=True),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_sessions_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user_sessions')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_user_sessions_token_hash'))
    )
    op.create_index('ix_user_sessions_family', 'user_sessions', ['family_id'], unique=False)
    op.create_index('ix_user_sessions_user', 'user_sessions', ['user_id'], unique=False)
    op.create_table('audit_logs',
    sa.Column('organization_id', sa.Uuid(), nullable=True),
    sa.Column('actor_user_id', sa.Uuid(), nullable=True),
    sa.Column('actor_type', sa.String(length=16), nullable=False),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('target_type', sa.String(length=48), nullable=True),
    sa.Column('target_id', sa.String(length=64), nullable=True),
    sa.Column('outcome', sa.String(length=16), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=True),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.Column('request_id', sa.String(length=64), nullable=True),
    sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("actor_type IN ('user', 'system', 'agent', 'device')", name=op.f('ck_audit_logs_actor_type')),
    sa.CheckConstraint("outcome IN ('success', 'failure', 'denied')", name=op.f('ck_audit_logs_outcome')),
    sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], name=op.f('fk_audit_logs_actor_user_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_audit_logs_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_logs'))
    )
    op.create_index('ix_audit_logs_actor_created', 'audit_logs', ['actor_user_id', 'created_at'], unique=False)
    op.create_index('ix_audit_logs_org_created', 'audit_logs', ['organization_id', 'created_at'], unique=False)
    op.create_table('devices',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('device_type', sa.String(length=24), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.Column('ip_address', sa.String(length=45), nullable=True),
    sa.Column('mac_address', sa.String(length=17), nullable=True),
    sa.Column('os', sa.String(length=80), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('enrollment_status', sa.String(length=16), nullable=False),
    sa.Column('health_score', sa.Integer(), nullable=True),
    sa.Column('risk_score', sa.Integer(), nullable=True),
    sa.Column('agent_version', sa.String(length=32), nullable=True),
    sa.Column('credential_hash', sa.String(length=255), nullable=True),
    sa.Column('enrolled_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('location', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('tags', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('attributes', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('is_simulated', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("device_type IN ('workstation', 'server', 'mobile', 'iot', 'camera', 'sensor_hub', 'network', 'other')", name=op.f('ck_devices_device_type')),
    sa.CheckConstraint("enrollment_status IN ('pending', 'enrolled', 'revoked')", name=op.f('ck_devices_enrollment_status')),
    sa.CheckConstraint("status IN ('online', 'offline', 'degraded', 'unknown', 'decommissioned')", name=op.f('ck_devices_status')),
    sa.CheckConstraint('health_score IS NULL OR (health_score BETWEEN 0 AND 100)', name=op.f('ck_devices_health_score')),
    sa.CheckConstraint('risk_score IS NULL OR (risk_score BETWEEN 0 AND 100)', name=op.f('ck_devices_risk_score')),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_devices_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_devices'))
    )
    op.create_index('ix_devices_org_status', 'devices', ['organization_id', 'status'], unique=False)
    op.create_table('incidents',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('reference', sa.String(length=32), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('assigned_to', sa.Uuid(), nullable=True),
    sa.Column('opened_by', sa.Uuid(), nullable=True),
    sa.Column('opened_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('is_simulated', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name=op.f('ck_incidents_severity')),
    sa.CheckConstraint("status IN ('open', 'investigating', 'contained', 'eradicated', 'recovered', 'closed')", name=op.f('ck_incidents_status')),
    sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], name=op.f('fk_incidents_assigned_to_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['opened_by'], ['users.id'], name=op.f('fk_incidents_opened_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_incidents_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_incidents'))
    )
    op.create_index('ix_incidents_org_status', 'incidents', ['organization_id', 'status'], unique=False)
    op.create_table('integrations',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('provider', sa.String(length=48), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('config', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('secret_ref', sa.String(length=120), nullable=True),
    sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_integrations_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_integrations_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_integrations')),
    sa.UniqueConstraint('organization_id', 'name', name=op.f('uq_integrations_organization_id_name'))
    )
    op.create_table('notifications',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('organization_id', sa.Uuid(), nullable=True),
    sa.Column('kind', sa.String(length=48), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('body', sa.Text(), nullable=True),
    sa.Column('link', sa.String(length=255), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name=op.f('ck_notifications_severity')),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_notifications_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_notifications_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_notifications'))
    )
    op.create_index('ix_notifications_user_created', 'notifications', ['user_id', 'created_at'], unique=False)
    op.create_table('roles',
    sa.Column('organization_id', sa.Uuid(), nullable=True),
    sa.Column('key', sa.String(length=48), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('rank', sa.Integer(), nullable=False),
    sa.Column('is_system', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_roles_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_roles')),
    sa.UniqueConstraint('organization_id', 'key', name=op.f('uq_roles_organization_id_key'))
    )
    op.create_table('threat_indicators',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('indicator_type', sa.String(length=16), nullable=False),
    sa.Column('value', sa.String(length=2048), nullable=False),
    sa.Column('verdict', sa.String(length=16), nullable=False),
    sa.Column('confidence', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=64), nullable=False),
    sa.Column('is_verified', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('context', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("indicator_type IN ('ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256')", name=op.f('ck_threat_indicators_indicator_type')),
    sa.CheckConstraint("verdict IN ('unknown', 'benign', 'suspicious', 'malicious')", name=op.f('ck_threat_indicators_verdict')),
    sa.CheckConstraint('confidence BETWEEN 0 AND 100', name=op.f('ck_threat_indicators_confidence')),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_threat_indicators_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_threat_indicators')),
    sa.UniqueConstraint('organization_id', 'indicator_type', 'value', name=op.f('uq_threat_indicators_organization_id_indicator_type_value'))
    )
    op.create_table('automation_workflows',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('integration_id', sa.Uuid(), nullable=True),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('trigger_type', sa.String(length=16), nullable=False),
    sa.Column('trigger_config', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('external_workflow_id', sa.String(length=120), nullable=True),
    sa.Column('enabled', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('requires_approval', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_automation_workflows_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['integration_id'], ['integrations.id'], name=op.f('fk_automation_workflows_integration_id_integrations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_automation_workflows_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_automation_workflows'))
    )
    op.create_index('ix_automation_workflows_org', 'automation_workflows', ['organization_id'], unique=False)
    op.create_table('cameras',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('device_id', sa.Uuid(), nullable=True),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('stream_secret_ref', sa.String(length=120), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('privacy_mode', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('detection_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('retention_days', sa.Integer(), server_default='7', nullable=False),
    sa.Column('zones', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('last_frame_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('is_simulated', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("status IN ('online', 'offline', 'degraded', 'unknown', 'decommissioned')", name=op.f('ck_cameras_status')),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], name=op.f('fk_cameras_device_id_devices'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_cameras_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_cameras'))
    )
    op.create_index('ix_cameras_org', 'cameras', ['organization_id'], unique=False)
    op.create_table('network_assets',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('device_id', sa.Uuid(), nullable=True),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('mac_address', sa.String(length=17), nullable=True),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.Column('vendor', sa.String(length=120), nullable=True),
    sa.Column('open_ports', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('services', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('in_authorized_scope', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], name=op.f('fk_network_assets_device_id_devices'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_network_assets_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_network_assets')),
    sa.UniqueConstraint('organization_id', 'ip_address', name=op.f('uq_network_assets_organization_id_ip_address'))
    )
    op.create_table('organization_members',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('role_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=16), server_default='active', nullable=False),
    sa.Column('invited_by', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("status IN ('active', 'suspended')", name=op.f('ck_organization_members_status')),
    sa.ForeignKeyConstraint(['invited_by'], ['users.id'], name=op.f('fk_organization_members_invited_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_organization_members_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_organization_members_role_id_roles'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_organization_members_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_organization_members')),
    sa.UniqueConstraint('organization_id', 'user_id', name=op.f('uq_organization_members_organization_id_user_id'))
    )
    op.create_index('ix_organization_members_user', 'organization_members', ['user_id'], unique=False)
    op.create_table('reports',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('incident_id', sa.Uuid(), nullable=True),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('report_type', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('content', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('is_ai_generated', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('generated_by', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("status IN ('draft', 'generating', 'ready', 'failed')", name=op.f('ck_reports_status')),
    sa.ForeignKeyConstraint(['generated_by'], ['users.id'], name=op.f('fk_reports_generated_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_reports_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_reports_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_reports'))
    )
    op.create_index('ix_reports_org_created', 'reports', ['organization_id', 'created_at'], unique=False)
    op.create_table('role_permissions',
    sa.Column('role_id', sa.Uuid(), nullable=False),
    sa.Column('permission_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], name=op.f('fk_role_permissions_permission_id_permissions'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], name=op.f('fk_role_permissions_role_id_roles'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('role_id', 'permission_id', name=op.f('pk_role_permissions'))
    )
    op.create_table('security_events',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('device_id', sa.Uuid(), nullable=True),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('category', sa.String(length=32), nullable=False),
    sa.Column('event_type', sa.String(length=64), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('fingerprint', sa.String(length=64), nullable=True),
    sa.Column('raw', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('normalized', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ingested_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('is_simulated', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name=op.f('ck_security_events_severity')),
    sa.CheckConstraint("status IN ('new', 'triaged', 'closed')", name=op.f('ck_security_events_status')),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], name=op.f('fk_security_events_device_id_devices'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_security_events_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_security_events'))
    )
    op.create_index('ix_security_events_fingerprint', 'security_events', ['organization_id', 'fingerprint'], unique=False)
    op.create_index('ix_security_events_org_occurred', 'security_events', ['organization_id', 'occurred_at'], unique=False)
    op.create_index('ix_security_events_org_status', 'security_events', ['organization_id', 'status'], unique=False)
    op.create_table('sensors',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('device_id', sa.Uuid(), nullable=True),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('sensor_type', sa.String(length=48), nullable=False),
    sa.Column('unit', sa.String(length=16), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('thresholds', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('last_value', sa.Float(), nullable=True),
    sa.Column('last_reading_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('is_simulated', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("status IN ('online', 'offline', 'degraded', 'unknown', 'decommissioned')", name=op.f('ck_sensors_status')),
    sa.ForeignKeyConstraint(['device_id'], ['devices.id'], name=op.f('fk_sensors_device_id_devices'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_sensors_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sensors'))
    )
    op.create_index('ix_sensors_org', 'sensors', ['organization_id'], unique=False)
    op.create_table('alerts',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('event_id', sa.Uuid(), nullable=True),
    sa.Column('incident_id', sa.Uuid(), nullable=True),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('risk_score', sa.Integer(), nullable=True),
    sa.Column('detection_rule', sa.String(length=120), nullable=True),
    sa.Column('assigned_to', sa.Uuid(), nullable=True),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('is_simulated', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name=op.f('ck_alerts_severity')),
    sa.CheckConstraint("status IN ('open', 'acknowledged', 'resolved', 'false_positive')", name=op.f('ck_alerts_status')),
    sa.CheckConstraint('risk_score IS NULL OR (risk_score BETWEEN 0 AND 100)', name=op.f('ck_alerts_risk_score')),
    sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], name=op.f('fk_alerts_assigned_to_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['event_id'], ['security_events.id'], name=op.f('fk_alerts_event_id_security_events'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_alerts_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_alerts_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_alerts'))
    )
    op.create_index('ix_alerts_org_status_severity', 'alerts', ['organization_id', 'status', 'severity'], unique=False)
    op.create_table('investigations',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('incident_id', sa.Uuid(), nullable=True),
    sa.Column('alert_id', sa.Uuid(), nullable=True),
    sa.Column('subject_type', sa.String(length=32), nullable=False),
    sa.Column('subject', sa.String(length=2048), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('verdict', sa.String(length=16), nullable=False),
    sa.Column('risk_score', sa.Integer(), nullable=True),
    sa.Column('summary', sa.Text(), nullable=True),
    sa.Column('verified_findings', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('ai_assessment', sa.Text(), nullable=True),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'running', 'completed', 'failed')", name=op.f('ck_investigations_status')),
    sa.CheckConstraint("verdict IN ('unknown', 'benign', 'suspicious', 'malicious')", name=op.f('ck_investigations_verdict')),
    sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], name=op.f('fk_investigations_alert_id_alerts'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_investigations_created_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_investigations_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_investigations_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_investigations'))
    )
    op.create_index('ix_investigations_org_created', 'investigations', ['organization_id', 'created_at'], unique=False)
    op.create_table('agent_runs',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('investigation_id', sa.Uuid(), nullable=True),
    sa.Column('agent_name', sa.String(length=64), nullable=False),
    sa.Column('trigger', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('model_provider', sa.String(length=32), nullable=True),
    sa.Column('model_name', sa.String(length=64), nullable=True),
    sa.Column('input_summary', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('output_summary', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('tokens_used', sa.Integer(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')", name=op.f('ck_agent_runs_status')),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name=op.f('fk_agent_runs_investigation_id_investigations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_agent_runs_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agent_runs'))
    )
    op.create_index('ix_agent_runs_org_created', 'agent_runs', ['organization_id', 'created_at'], unique=False)
    op.create_table('evidence',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('incident_id', sa.Uuid(), nullable=True),
    sa.Column('investigation_id', sa.Uuid(), nullable=True),
    sa.Column('evidence_type', sa.String(length=32), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('storage_uri', sa.String(length=1024), nullable=True),
    sa.Column('sha256', sa.String(length=64), nullable=True),
    sa.Column('size_bytes', sa.Integer(), nullable=True),
    sa.Column('collected_by', sa.Uuid(), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('chain_of_custody', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['collected_by'], ['users.id'], name=op.f('fk_evidence_collected_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_evidence_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], name=op.f('fk_evidence_investigation_id_investigations'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_evidence_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence'))
    )
    op.create_index('ix_evidence_org_collected', 'evidence', ['organization_id', 'collected_at'], unique=False)
    op.create_table('agent_decisions',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('agent_run_id', sa.Uuid(), nullable=False),
    sa.Column('decision_type', sa.String(length=48), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('rationale', sa.Text(), nullable=True),
    sa.Column('confidence', sa.Integer(), nullable=True),
    sa.Column('is_ai_generated', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('evidence_refs', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint('confidence IS NULL OR (confidence BETWEEN 0 AND 100)', name=op.f('ck_agent_decisions_confidence')),
    sa.ForeignKeyConstraint(['agent_run_id'], ['agent_runs.id'], name=op.f('fk_agent_decisions_agent_run_id_agent_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_agent_decisions_organization_id_organizations'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_agent_decisions'))
    )
    op.create_index('ix_agent_decisions_org_run', 'agent_decisions', ['organization_id', 'agent_run_id'], unique=False)
    op.create_table('response_actions',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('incident_id', sa.Uuid(), nullable=True),
    sa.Column('proposed_by_run_id', sa.Uuid(), nullable=True),
    sa.Column('action_type', sa.String(length=48), nullable=False),
    sa.Column('target', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('impact', sa.String(length=16), nullable=False),
    sa.Column('requires_approval', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('status', sa.String(length=24), nullable=False),
    sa.Column('requested_by', sa.Uuid(), nullable=True),
    sa.Column('result', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('rollback_plan', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('rolled_back_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("impact IN ('low', 'medium', 'high')", name=op.f('ck_response_actions_impact')),
    sa.CheckConstraint("status IN ('proposed', 'pending_approval', 'approved', 'rejected', 'executing', 'succeeded', 'failed', 'rolled_back', 'cancelled')", name=op.f('ck_response_actions_status')),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], name=op.f('fk_response_actions_incident_id_incidents'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_response_actions_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['proposed_by_run_id'], ['agent_runs.id'], name=op.f('fk_response_actions_proposed_by_run_id_agent_runs'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name=op.f('fk_response_actions_requested_by_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_response_actions'))
    )
    op.create_index('ix_response_actions_org_status', 'response_actions', ['organization_id', 'status'], unique=False)
    op.create_table('approvals',
    sa.Column('organization_id', sa.Uuid(), nullable=False),
    sa.Column('response_action_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('requested_by', sa.Uuid(), nullable=True),
    sa.Column('decided_by', sa.Uuid(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'approved', 'rejected', 'expired')", name=op.f('ck_approvals_status')),
    sa.ForeignKeyConstraint(['decided_by'], ['users.id'], name=op.f('fk_approvals_decided_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], name=op.f('fk_approvals_organization_id_organizations'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], name=op.f('fk_approvals_requested_by_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['response_action_id'], ['response_actions.id'], name=op.f('fk_approvals_response_action_id_response_actions'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_approvals'))
    )
    op.create_index('ix_approvals_action', 'approvals', ['response_action_id'], unique=False)
    op.create_index('ix_approvals_org_status', 'approvals', ['organization_id', 'status'], unique=False)
    _seed_rbac()
    if op.get_context().dialect.name == "postgresql":
        _install_postgres_security()


def _seed_rbac() -> None:
    import uuid

    permissions = sa.table("permissions", sa.column("id", sa.Uuid()), sa.column("key", sa.String()),
                           sa.column("description", sa.String()),
                           sa.column("created_at", sa.DateTime(timezone=True)))
    roles = sa.table("roles", sa.column("id", sa.Uuid()), sa.column("organization_id", sa.Uuid()),
                     sa.column("key", sa.String()), sa.column("name", sa.String()),
                     sa.column("description", sa.Text()), sa.column("rank", sa.Integer()),
                     sa.column("is_system", sa.Boolean()))
    role_permissions = sa.table("role_permissions", sa.column("role_id", sa.Uuid()),
                                sa.column("permission_id", sa.Uuid()))
    perm_ids = {key: uuid.uuid4() for key in PERMISSIONS}
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    op.bulk_insert(permissions, [
        {"id": perm_ids[k], "key": k, "description": d, "created_at": now} for k, d in PERMISSIONS.items()
    ])
    role_rows, links = [], []
    for key, (name, rank, description, perms) in ROLES.items():
        rid = uuid.uuid4()
        role_rows.append({"id": rid, "organization_id": None, "key": key, "name": name,
                          "description": description, "rank": rank, "is_system": True})
        links += [{"role_id": rid, "permission_id": perm_ids[p]} for p in perms]
    op.bulk_insert(roles, role_rows)
    op.bulk_insert(role_permissions, links)


def _install_postgres_security() -> None:
    op.execute("""
        CREATE OR REPLACE FUNCTION app_current_org() RETURNS uuid LANGUAGE sql STABLE AS
        $$ SELECT NULLIF(current_setting('app.current_org_id', true), '')::uuid $$;
        CREATE OR REPLACE FUNCTION app_current_user() RETURNS uuid LANGUAGE sql STABLE AS
        $$ SELECT NULLIF(current_setting('app.current_user_id', true), '')::uuid $$;
        CREATE OR REPLACE FUNCTION app_api_context() RETURNS boolean LANGUAGE sql STABLE AS
        $$ SELECT coalesce(current_setting('app.current_context', true), '') = 'api' $$;
    """)
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = app_current_org()) "
            "WITH CHECK (organization_id = app_current_org())"
        )
    for table in CONTEXT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY api_access ON {table} USING (app_api_context()) "
                   "WITH CHECK (app_api_context())")

    # audit_logs: readable per tenant (plus a user's own org-less events); insert-only.
    op.execute("ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY audit_read ON audit_logs FOR SELECT USING ("
               "organization_id = app_current_org() OR "
               "(organization_id IS NULL AND actor_user_id = app_current_user()))")
    op.execute("CREATE POLICY audit_append ON audit_logs FOR INSERT WITH CHECK ("
               "app_api_context() AND (organization_id IS NULL OR organization_id = app_current_org()))")
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_logs_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            -- The only permitted change is the FK action nulling a deleted user's reference.
            IF TG_OP = 'UPDATE'
               AND NEW.actor_user_id IS NULL AND OLD.actor_user_id IS NOT NULL
               AND (to_jsonb(NEW) - 'actor_user_id') = (to_jsonb(OLD) - 'actor_user_id') THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'audit_logs is append-only';
        END $$;
        CREATE TRIGGER audit_logs_append_only BEFORE UPDATE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
    """)

    # notifications: addressed to a user; anyone in the current org context may create one.
    op.execute("ALTER TABLE notifications ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE notifications FORCE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY notification_owner ON notifications USING (user_id = app_current_user()) "
               "WITH CHECK (user_id = app_current_user())")
    op.execute("CREATE POLICY notification_create ON notifications FOR INSERT WITH CHECK ("
               "app_api_context() AND (organization_id IS NULL OR organization_id = app_current_org()))")

    # Alembic's bookkeeping table: owner-only (RLS on, no policies, not forced).
    op.execute("ALTER TABLE alembic_version ENABLE ROW LEVEL SECURITY")

    # Supabase exposes the public schema through its Data API: lock those roles out entirely.
    op.execute("""
        DO $$
        DECLARE r text;
        BEGIN
            FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
                    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ' || quote_ident(r);
                    EXECUTE 'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM ' || quote_ident(r);
                END IF;
            END LOOP;
        END $$;
    """)


def downgrade() -> None:
    if op.get_context().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs")
        op.execute("DROP FUNCTION IF EXISTS audit_logs_append_only()")
    op.drop_index('ix_approvals_org_status', table_name='approvals')
    op.drop_index('ix_approvals_action', table_name='approvals')
    op.drop_table('approvals')
    op.drop_index('ix_response_actions_org_status', table_name='response_actions')
    op.drop_table('response_actions')
    op.drop_index('ix_agent_decisions_org_run', table_name='agent_decisions')
    op.drop_table('agent_decisions')
    op.drop_index('ix_evidence_org_collected', table_name='evidence')
    op.drop_table('evidence')
    op.drop_index('ix_agent_runs_org_created', table_name='agent_runs')
    op.drop_table('agent_runs')
    op.drop_index('ix_investigations_org_created', table_name='investigations')
    op.drop_table('investigations')
    op.drop_index('ix_alerts_org_status_severity', table_name='alerts')
    op.drop_table('alerts')
    op.drop_index('ix_sensors_org', table_name='sensors')
    op.drop_table('sensors')
    op.drop_index('ix_security_events_org_status', table_name='security_events')
    op.drop_index('ix_security_events_org_occurred', table_name='security_events')
    op.drop_index('ix_security_events_fingerprint', table_name='security_events')
    op.drop_table('security_events')
    op.drop_table('role_permissions')
    op.drop_index('ix_reports_org_created', table_name='reports')
    op.drop_table('reports')
    op.drop_index('ix_organization_members_user', table_name='organization_members')
    op.drop_table('organization_members')
    op.drop_table('network_assets')
    op.drop_index('ix_cameras_org', table_name='cameras')
    op.drop_table('cameras')
    op.drop_index('ix_automation_workflows_org', table_name='automation_workflows')
    op.drop_table('automation_workflows')
    op.drop_table('threat_indicators')
    op.drop_table('roles')
    op.drop_index('ix_notifications_user_created', table_name='notifications')
    op.drop_table('notifications')
    op.drop_table('integrations')
    op.drop_index('ix_incidents_org_status', table_name='incidents')
    op.drop_table('incidents')
    op.drop_index('ix_devices_org_status', table_name='devices')
    op.drop_table('devices')
    op.drop_index('ix_audit_logs_org_created', table_name='audit_logs')
    op.drop_index('ix_audit_logs_actor_created', table_name='audit_logs')
    op.drop_table('audit_logs')
    op.drop_index('ix_user_sessions_user', table_name='user_sessions')
    op.drop_index('ix_user_sessions_family', table_name='user_sessions')
    op.drop_table('user_sessions')
    op.drop_table('organizations')
    op.drop_table('vulnerability_records')
    op.drop_table('users')
    op.drop_table('permissions')
    if op.get_context().dialect.name == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS app_current_org()")
        op.execute("DROP FUNCTION IF EXISTS app_current_user()")
        op.execute("DROP FUNCTION IF EXISTS app_api_context()")
