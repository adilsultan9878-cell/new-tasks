"""Bounded on-disk queue for events that could not be delivered (server unreachable)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class Spool:
    def __init__(self, path: Path, max_events: int = 1000) -> None:
        self.path = path
        self.max_events = max_events

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                continue  # skip a torn line rather than losing the whole spool
        return events

    def push(self, events: list[dict[str, Any]]) -> int:
        """Append events, keeping only the newest ``max_events``. Returns how many were dropped."""
        merged = self.load() + events
        dropped = max(0, len(merged) - self.max_events)
        self._write(merged[dropped:])
        return dropped

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()

    def _write(self, events: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
        tmp.replace(self.path)

    def __len__(self) -> int:
        return len(self.load())
