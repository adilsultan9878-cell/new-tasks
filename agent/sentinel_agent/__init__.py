"""SENTINEL X local security agent.

Design rules (enforced by tests):
* it only *reads* approved telemetry and *reports* it — it never executes commands, scripts or
  code received from the server or anywhere else;
* server-side configuration is applied through a strict allow-list;
* it authenticates with a per-device credential over HTTPS and can be removed cleanly.
"""

__version__ = "0.3.0"
