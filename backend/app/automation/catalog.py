"""What automation may do: the allow-listed triggers, steps, schedules and ready-made recipes.

Nothing outside these lists can be configured. Every step changes data inside this platform only,
except ``send_webhook``, which posts a signed, data-minimised JSON document to a webhook the
organization registered itself. No step runs shell commands, scans networks or touches devices
directly; defensive actions are *proposed* to the SOC queue, where the Phase 5 approval rules apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class EventSpec:
    key: str
    title: str  # "When …" sentence
    description: str
    filters: tuple[str, ...]  # min_severity, include_simulated
    fields: tuple[str, ...]  # template fields available to steps


EVENTS: dict[str, EventSpec] = {
    e.key: e
    for e in (
        EventSpec(
            "alert.created",
            "A new alert is raised",
            "Runs for every new alert at or above the chosen severity.",
            ("min_severity", "include_simulated"),
            ("alert.title", "alert.severity", "alert.rule", "device.name", "event.category"),
        ),
        EventSpec(
            "incident.created",
            "An incident is opened",
            "Runs when someone (not automation) opens an incident at or above the chosen severity.",
            ("min_severity",),
            ("incident.reference", "incident.title", "incident.severity"),
        ),
        EventSpec(
            "device.offline",
            "A device stops reporting",
            "Runs when an enrolled device misses its heartbeats and is marked offline.",
            ("include_simulated",),
            ("device.name", "device.device_type"),
        ),
        EventSpec(
            "action.pending_approval",
            "A response action needs approval",
            "Runs when a medium or high impact response action is waiting for a decision.",
            (),
            ("action.title", "action.impact", "action.action_type"),
        ),
    )
}

SCHEDULES: dict[int, str] = {
    15: "Every 15 minutes",
    60: "Every hour",
    360: "Every 6 hours",
    1440: "Every day",
    10080: "Every week",
}

TRIGGER_TYPES: dict[str, str] = {
    "event": "When something happens",
    "schedule": "On a schedule",
    "manual": "When I press Run",
    "webhook": "When another tool calls (signed webhook)",
}


@dataclass(frozen=True)
class StepSpec:
    key: str
    title: str
    description: str
    risk: str  # low: runs without approval if the workflow allows it; medium: always needs approval
    permission: str | None  # the acting member must hold it when the step runs
    params: tuple[str, ...]
    triggers: tuple[str, ...] = ()  # empty = every trigger type
    events: tuple[str, ...] = ()  # for trigger "event": restrict to these events (empty = all)
    extra: dict[str, Any] = field(default_factory=dict)


STEPS: dict[str, StepSpec] = {
    s.key: s
    for s in (
        StepSpec(
            "notify",
            "Send an in-app notification",
            "Notifies responders (members who manage alerts) or approvers. The message can use fields "
            "such as {{alert.title}}.",
            "low",
            None,
            ("audience", "message"),
            extra={"audiences": {"responders": "alerts:manage", "approvers": "responses:approve"}},
        ),
        StepSpec(
            "send_webhook",
            "Send to a webhook (n8n, Slack, Teams…)",
            "Posts a signed JSON document with the trigger details to one of your webhooks. Delivery "
            "is retried with back-off and logged.",
            "low",
            None,
            ("webhook_id",),
        ),
        StepSpec(
            "create_incident",
            "Open an incident",
            "Opens an incident (linking the alert when there is one). Always waits for approval.",
            "medium",
            "incidents:manage",
            ("title",),
            triggers=("event", "webhook"),
            events=("alert.created",),
        ),
        StepSpec(
            "propose_response",
            "Propose a response action",
            "Adds a block-list entry or heightened monitoring to the SOC approval queue. Nothing is "
            "blocked until a person approves it there.",
            "low",
            "responses:propose",
            ("action_type", "indicator_type", "value"),
            triggers=("event", "webhook", "manual"),
            events=("alert.created", "device.offline"),
            extra={"action_types": ("block_indicator", "heighten_monitoring")},
        ),
        StepSpec(
            "create_event",
            "Record a security event",
            "Turns the incoming webhook body into a security event (title, severity, category…). "
            "High and critical events raise alerts as usual.",
            "low",
            "events:ingest",
            (),
            triggers=("webhook",),
        ),
    )
}

INDICATOR_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")

# Ready-made starting points shown in the console. ``needs`` lists what the user must pick.
RECIPES: list[dict[str, Any]] = [
    {
        "key": "notify-serious-alerts",
        "name": "Tell the team about serious alerts",
        "description": "Every high or critical alert sends an in-app notification to responders.",
        "trigger_type": "event",
        "trigger_config": {"event": "alert.created", "min_severity": "high"},
        "steps": [
            {
                "type": "notify",
                "audience": "responders",
                "message": "{{alert.severity}} alert: {{alert.title}} ({{device.name}})",
            }
        ],
        "requires_approval": False,
        "needs": [],
    },
    {
        "key": "alerts-to-n8n",
        "name": "Send serious alerts to n8n",
        "description": "Forward high and critical alerts to n8n, which can post them to Slack, Teams or email.",
        "trigger_type": "event",
        "trigger_config": {"event": "alert.created", "min_severity": "high"},
        "steps": [{"type": "send_webhook", "webhook_id": None}],
        "requires_approval": False,
        "needs": ["webhook"],
    },
    {
        "key": "incident-for-critical",
        "name": "Open an incident for critical alerts",
        "description": "Prepares an incident for every critical alert; a person approves it first.",
        "trigger_type": "event",
        "trigger_config": {"event": "alert.created", "min_severity": "critical"},
        "steps": [{"type": "create_incident", "title": "{{alert.title}}"}],
        "requires_approval": True,
        "needs": [],
    },
    {
        "key": "daily-summary",
        "name": "Daily summary to n8n",
        "description": "Once a day, send open alerts, incidents and device status to n8n.",
        "trigger_type": "schedule",
        "trigger_config": {"every_minutes": 1440},
        "steps": [{"type": "send_webhook", "webhook_id": None}],
        "requires_approval": False,
        "needs": ["webhook"],
    },
    {
        "key": "approvals-to-chat",
        "name": "Ask for approvals in chat",
        "description": "When a response action waits for approval, send it to n8n so approvers see it in chat.",
        "trigger_type": "event",
        "trigger_config": {"event": "action.pending_approval"},
        "steps": [{"type": "send_webhook", "webhook_id": None}],
        "requires_approval": False,
        "needs": ["webhook"],
    },
    {
        "key": "block-from-n8n",
        "name": "Block what another tool reports",
        "description": 'n8n (or any tool) sends {"value": "203.0.113.7"}; a block is proposed for approval.',
        "trigger_type": "webhook",
        "trigger_config": {},
        "steps": [
            {
                "type": "propose_response",
                "action_type": "block_indicator",
                "indicator_type": "ipv4",
                "value": "{{payload.value}}",
            }
        ],
        "requires_approval": False,
        "needs": [],
    },
    {
        "key": "import-events",
        "name": "Import alerts from another tool",
        "description": 'Another tool posts {"title", "severity", "category"} and it becomes a security event.',
        "trigger_type": "webhook",
        "trigger_config": {},
        "steps": [{"type": "create_event"}],
        "requires_approval": False,
        "needs": [],
    },
]


def severity_at_least(value: str | None, minimum: str | None) -> bool:
    if not minimum:
        return True
    if value not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(value) >= SEVERITY_ORDER.index(minimum)
