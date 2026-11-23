"""SENTINEL X Security Brain (Phase 4).

A deterministic orchestrator that runs specialised analysis agents over an alert, a device or
the whole organization. Agents only read tenant data through :mod:`app.brain.toolbox`; they
cannot write, execute commands or reach the network. Every score is a documented, weighted sum
(:mod:`app.brain.scoring`) and every tool call is recorded in the run trace.

No AI model is used while ``AI_PROVIDER=none`` (the only provider in this release).
"""
