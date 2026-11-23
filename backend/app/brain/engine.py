"""Which reasoning engine produced an analysis.

Only the deterministic engine exists in this release. A future model provider would add
*narrative* text on top of the deterministic result — stored separately and flagged
``is_ai_generated`` — and never replace the scores, findings or evidence.
"""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings

ENGINE_VERSION = "brain-rules/1"


def engine_info() -> dict[str, Any]:
    provider = get_settings().ai_provider
    return {
        "provider": provider,
        "mode": "deterministic",
        "model": None,
        "ai_enabled": False,
        "engine_version": ENGINE_VERSION,
        "description": (
            "Deterministic rules engine: weighted risk factors computed from your organization's "
            "own data. No AI model is configured, so nothing in an analysis is AI-generated."
        ),
    }
