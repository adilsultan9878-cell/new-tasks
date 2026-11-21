"""NEXUS ZERO threat-intelligence engine.

Principles:
* the subject under investigation (URL, domain, IP, file) is **never fetched or executed**;
  only fixed, allow-listed intelligence services are queried about it;
* every finding carries its source and kind — ``intel`` (a trusted external source said so),
  ``heuristic`` (a deterministic local check) or ``context`` (neutral facts);
* a source that is not configured or unreachable is reported as such, never silently skipped.
"""
