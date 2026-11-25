"""RBAC catalogue — the single source of truth seeded into the roles/permissions tables.

Authorisation checks read the permissions from the database at request time (joined from the
caller's membership), so the tables are authoritative at runtime; this module seeds them.
"""

from __future__ import annotations

PERMISSIONS: dict[str, str] = {
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
    "intel:read": "View threat intelligence, indicators and vulnerabilities",
    "intel:manage": "Manage the indicator watchlist and refresh vulnerability feeds",
    "network:read": "View network assets and authorized scopes",
    "network:manage": "Manage authorized scopes and import network scans",
    "brain:read": "View Security Brain analyses, agent decisions and reports",
    "brain:run": "Run Security Brain analyses",
    "automation:read": "View workflows, webhooks and automation history",
}

_READ = [p for p in PERMISSIONS if p.endswith(":read")]

ROLES: dict[str, dict[str, object]] = {
    "owner": {
        "name": "Owner",
        "rank": 100,
        "description": "Full control of the organization, including ownership transfer.",
        "permissions": list(PERMISSIONS),
    },
    "admin": {
        "name": "Administrator",
        "rank": 80,
        "description": "Manages members, settings, integrations and approvals.",
        "permissions": list(PERMISSIONS),
    },
    "analyst": {
        "name": "Security Analyst",
        "rank": 50,
        "description": "Investigates and responds to security events. Cannot manage members.",
        "permissions": [
            *_READ,
            "devices:manage",
            "events:ingest",
            "alerts:manage",
            "incidents:manage",
            "investigations:run",
            "responses:propose",
            "evidence:manage",
            "reports:manage",
            "intel:manage",
            "network:manage",
            "brain:run",
        ],
    },
    "viewer": {
        "name": "Viewer",
        "rank": 10,
        "description": "Read-only access to the organization's security data.",
        "permissions": _READ,
    },
}

OWNER_ROLE = "owner"
