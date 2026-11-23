# Roadmap & feature status

Legend: ✅ implemented and covered by automated tests · 🟡 partially implemented · ⬜ pending

## Phase 1 — Foundation ✅ (v0.1.0)

| Feature | Status | Evidence |
|---|---|---|
| System architecture, threat model, database design | ✅ | `docs/` |
| Repository structure, Docker, CI | ✅ | `docker-compose.yml`, `.github/workflows/ci.yml` |
| Full relational schema (27 tables, FKs, indexes, CHECK constraints) | ✅ | `alembic/versions/0001_initial_schema.py` |
| PostgreSQL Row-Level Security on all tables + append-only audit trigger | ✅ | `tests/test_rls.py` |
| Registration, login, logout, logout-everywhere | ✅ | `tests/test_auth.py`, `e2e/platform.spec.ts` |
| Argon2id hashing, password policy, lockout, rate limiting | ✅ | `tests/test_auth.py` |
| Rotating refresh tokens with reuse detection and multi-tab grace window | ✅ | `tests/test_auth.py` |
| Profile update, password change (signs out other sessions), session list | ✅ | `tests/test_auth.py` |
| Organizations: create, list, view, update; slugs | ✅ | `tests/test_organizations.py` |
| Membership: add existing users, change role, remove, leave | ✅ | `tests/test_organizations.py`, e2e |
| RBAC: owner / admin / analyst / viewer, DB-backed permissions, escalation guards, last-owner protection | ✅ | `tests/test_organizations.py` |
| Tenant isolation (API 404 for non-members + DB RLS) | ✅ | `tests/test_tenant_isolation.py`, `tests/test_rls.py`, e2e |
| Audit log (API + UI, filters, pagination), including failures and denials | ✅ | tests + e2e |
| In-app notifications (membership events) | ✅ | `tests/test_organizations.py`, e2e |
| Command Center with real tenant metrics, honest empty states, simulated-data exclusion | ✅ | `tests/test_tenant_isolation.py`, `CommandCenterPage.test.tsx` |
| System health (API, DB latency, RLS posture) and `/health`, `/api/v1/health/ready` | ✅ | `tests/test_health.py` |
| Web console: dark design system, collapsible sidebar, org switcher, Ctrl+K search, notifications, responsive/mobile | ✅ | component tests + e2e |
| Roadmap pages for all not-yet-built modules (no fake controls) | ✅ | `ModulePage.test.tsx` |
| Cloud deployment config (Render blueprint, Cloudflare Pages proxy + headers, Supabase guide) | 🟡 | config + docs written; Pages proxy unit-tested; not yet deployed to live accounts |
| Email verification, password reset, email invitations | ⬜ | needs an email provider (Phase 10) |
| Organization deletion / ownership transfer flow | ⬜ | intentionally deferred (needs re-auth + grace period) |

## Phase 2 — Security Event Engine ✅ (v0.2.0)

| Feature | Status | Evidence |
|---|---|---|
| Enrollment tokens (label, device type, max uses, expiry; shown once, stored hashed; revocable) | ✅ | `tests/test_devices.py`, `DevicesPage.test.tsx` |
| Device enrollment → per-device credential `sxd.<org>.<device>.<secret>` (SHA-256 stored, rotatable) | ✅ | `tests/test_devices.py`, `tests/test_agent_integration.py` |
| Tenant-safe device auth (org resolved from the credential before lookup, so RLS stays on) | ✅ | `test_device_token_cannot_cross_tenants` |
| Heartbeats with bounded telemetry, transparent health score, online/degraded status | ✅ | `test_heartbeat_updates_telemetry_health_and_delivers_config` |
| Allow-listed agent configuration pushed from the console (versioned) | ✅ | `test_config_is_an_allow_list`, agent `test_safety.py` |
| Device revoke (console) and unenroll (agent); revoked agents stop | ✅ | backend + agent integration + e2e |
| Background sweeper marks silent devices offline and records events; recovery on next heartbeat | ✅ | `test_sweeper_marks_silent_devices_offline_and_heartbeat_recovers` |
| Event ingestion API (agents + analysts): validation, size/batch limits, clock-skew/age checks | ✅ | `tests/test_events.py` |
| De-duplication (fingerprint window, occurrence counter) and ECS-style normalization | ✅ | `test_duplicates_fold_into_one_event` |
| Deterministic detection rules → alerts → notifications for responders (severity threshold, brute force) | ✅ | `test_severity_rule_…`, `test_bruteforce_rule_…` |
| Event triage (new → triaged → closed) with audit trail; read-only alert list | ✅ | `test_manual_events_and_triage_rbac` |
| WebSocket stream `/api/v1/ws`: first-message auth, origin check, tenant fan-out after commit, periodic re-validation | ✅ | `tests/test_realtime.py`, `RealtimeProvider.test.tsx` |
| Python local agent: enroll, run, status, rotate, unenroll; collectors; local detections; offline spool; logs | ✅ | `agent/tests/*`, `tests/test_agent_integration.py`, `e2e/devices.spec.ts` |
| Console: Devices page, device detail (telemetry, ports, config push, revoke), Security Events page, live indicator, toasts | ✅ | component tests + e2e |
| WebSocket through Docker nginx and the Cloudflare Pages proxy | 🟡 | nginx verified with Docker Compose; Pages passthrough unit-tested, not yet on a live Cloudflare account |
| Windows Task Scheduler / systemd service setup for the agent | 🟡 | documented in `agent/README.md`; agent itself is tested on Linux and in CI on Windows |
| Cross-instance realtime (Redis / Postgres LISTEN-NOTIFY) | ⬜ | single API instance today |

## Phase 3 — NEXUS ZERO ✅ (v0.3.0)

| Feature | Status | Evidence |
|---|---|---|
| Investigations API (URL, domain, IP, file hash, email) with provenance: every finding has a source and a kind (intel / deterministic / context) | ✅ | `tests/test_intel.py`, `InvestigationView.test.tsx` |
| SSRF-safe intelligence client: only allow-listed provider hosts, HTTPS only, no redirects, size limit; the subject is never fetched | ✅ | `test_ssrf_guard_only_allows_intel_hosts`, `test_url_heuristics_without_any_keys_are_honest` |
| URL & phishing heuristics (brand impersonation and look-alikes incl. HBL, Meezan, JazzCash, Easypaisa, NADRA, FBR; punycode; IP hosts; `@` tricks; risky TLDs; shorteners; executable downloads) | ✅ | `test_lookalike_detection`, e2e `intel.spec.ts` |
| Email header analysis (SPF/DKIM/DMARC, Reply-To and Return-Path mismatch, display-name spoofing, risky attachments, links analysed not opened) | ✅ | `test_email_header_analysis` |
| Domain intelligence: RDAP via IANA bootstrap (newly registered / unregistered), DNS over HTTPS | ✅ | live-verified (google.com → 1997) + mocked tests |
| IP intelligence: precise private/reserved classification, RDAP ownership, AbuseIPDB (key) | ✅ | `test_ip_investigations` (live-verified 8.8.8.8 → GOGL) |
| File hashes: MalwareBazaar (key), VirusTotal (key); in-browser SHA-256 (file never uploaded) | ✅ | `test_hash_investigations`, File & Hash page |
| URLhaus URL/host reputation (key) | ✅ | `test_urlhaus_listing_makes_it_malicious_and_raises_an_alert` |
| Honest results: unconfigured/unavailable sources are listed; "no known threat" instead of "safe" | ✅ | `test_hash_without_sources_is_unknown_not_clean` |
| Risk scoring and verdicts; malicious/suspicious results raise events → alerts → notifications | ✅ | tests + e2e |
| Indicator watchlist (analyst verdicts are never overridden by automation) | ✅ | `test_watchlist_match` |
| Vulnerability intelligence: CISA KEV sync (1,790 entries live), NVD enrichment with 7-day cache, search, ransomware filter | ✅ | `test_kev_sync_search_and_nvd_enrichment` (live-verified) |
| Network Security Monitor: authorized scopes (≤ /16, public ranges need attestation), Nmap XML import (defusedxml), out-of-scope hosts discarded, exposed/risky service events, agent ports feed the inventory | ✅ | `tests/test_network.py`, e2e |
| Optional provider keys tested with real accounts | 🟡 | adapters are unit-tested with recorded responses; live keys not yet configured |
| Zeek / pcap ingestion | ⬜ | planned with the Phase 9 hardening work |

## Phase 4 — Security Brain ✅ (v0.4.0)

Built with `AI_PROVIDER=none`: every score, finding and recommendation comes from deterministic,
published rules over the organization's own data. No AI model is used.

| Feature | Status | Evidence |
|---|---|---|
| Orchestrator with five specialised agents — Alert Triage, Device Risk, Network Exposure, Threat-Intel Correlation, Security Posture — over three subjects (alert, device, organization) | ✅ | `tests/test_brain.py` |
| Read-only, tenant-scoped toolbox (12 tools): explicit organization filter on top of RLS, plain-data snapshots instead of ORM objects, a write guard that aborts the run, and a static check that forbids writes, shell, and network access in agents and tools | ✅ | `test_agents_and_tools_cannot_write_or_reach_out`, `test_toolbox_aborts_a_tool_that_leaves_pending_writes` |
| Published, weighted scoring models (each totals 100 points), data coverage (missing data is reported, never hidden), risk levels and alert priority P1-P4 | ✅ | `test_scoring_levels_coverage_and_clamping`, exact-score end-to-end tests |
| Automatic triage of every new alert, inside a savepoint (a Brain failure never breaks event ingestion); `BRAIN_AUTO_TRIAGE` switch | ✅ | `test_new_alert_is_triaged_automatically`, `test_auto_triage_can_be_disabled` |
| Playbook recommendations: advice only, nothing executed; system-changing advice flagged for human approval | ✅ | tests + UI |
| Run history, decision log (`is_ai_generated = false`), full tool trace, downloadable Markdown report, audit entries, real-time updates | ✅ | `test_decision_history_and_agent_activity`, e2e `brain.spec.ts` |
| Security Brain and Agent Center pages; triage badges on alerts; device risk in the device view | ✅ | `BrainPage.test.tsx`, `RunPage.test.tsx`, e2e |
| AI model provider (Ollama / hosted) | ⬜ | not configured by choice; if added, it would only contribute separately labelled narrative text on top of the deterministic result |
| Asset-to-CVE matching | ⬜ | needs a reliable product/version (CPE) inventory; planned with Phase 9 |

## Phase 5 — SENTINEL X SOC ⬜

- Alerts triage, incident lifecycle, assignment
- Response actions with approvals, rollback plans and emergency stop
- Forensic evidence vault with SHA-256 and chain of custody
- Reports (incident / executive / compliance)

## Phase 6 — AEGIS ONE ⬜

- Camera enrollment, OpenCV motion/object detection, restricted zones, snapshots, privacy controls (no identity recognition)
- ESP32 / Arduino over authenticated MQTT, sensor thresholds, LED/buzzer triggers
- Hardware simulator (records flagged `is_simulated`)

## Phase 7 — Digital Twin ⬜

- Three.js environment of devices, connections, risk and incidents; simulated data clearly labelled

## Phase 8 — Automation ⬜

- n8n integration, signed webhooks, scheduled and event-triggered workflows with approval gates

## Phase 9 — Hardening & testing ⬜

- Load/performance tests, security testing (DAST), Redis rate limiting, Research Lab

## Phase 10 — Deployment ⬜

- Live Supabase + Render + Cloudflare deployment, email provider, public registration policy, monitoring
