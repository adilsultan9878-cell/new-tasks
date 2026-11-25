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

## Phase 5 — SENTINEL X SOC ✅ (v0.5.0)

| Feature | Status | Evidence |
|---|---|---|
| Alert triage (acknowledge, resolve, false positive) and incident lifecycle: created from alerts (`INC-YYYY-NNNN`, severity from the alerts), six statuses, assignment, notes, append-only timeline; closing needs decided actions and resolves linked alerts | ✅ | `tests/test_soc.py`, e2e `soc.spec.ts` |
| Response actions on a fixed allow-list: notify responders (low, runs at once), heighten monitoring and add to block list (medium, approval), revoke device and suspend member (high, second approver) — all executed inside the platform, nothing external | ✅ | `test_low_impact_action_runs_immediately`, `test_high_impact_actions_need_a_second_approver` |
| Separation of duties (sole approver may self-approve, recorded), approval expiry, cancellation, rollback where reversible, guards (no self-suspension, rank, last owner) | ✅ | `test_sole_approver_may_self_approve_and_it_is_recorded`, `test_suspend_member_and_restore`, `test_pending_approvals_expire` |
| Organization-wide emergency stop that holds every execution and rollback | ✅ | `test_emergency_stop_holds_every_execution`, e2e |
| Block-list export (plain text per indicator type) for firewalls / DNS filters | ✅ | `test_block_indicator_needs_approval_feeds_blocklist_and_rolls_back` |
| Evidence vault: files (browser + server SHA-256, must match), notes, external hashes; append-only chain of custody (collected, downloaded, verified); database triggers make stored bytes, hash and custody history immutable | ✅ | `test_evidence_vault_hashes_and_tracks_custody`, `test_evidence_is_immutable_in_the_database` |
| Incident and executive reports (MTTA, MTTR, false-positive rate, actions, riskiest devices, posture), Markdown download, no AI-written text | ✅ | `test_incident_and_executive_reports` |
| Security Brain recommendations become one-click action proposals (still approval-gated) | ✅ | `test_brain_recommendations_become_one_click_proposals` |
| Incident Response, Forensics Lab and Reports pages | ✅ | `IncidentsPage.test.tsx`, `IncidentPage.test.tsx`, e2e |
| PDF export, compliance report templates | ⬜ | Markdown download today; print-to-PDF from the browser works |
| Actions on external systems (firewall API, EDR) | ⬜ | needs explicitly configured integrations — Phase 8 |

## Phase 6 — AEGIS ONE ✅ (v0.6.0)

| Feature | Status | Evidence |
|---|---|---|
| Sensor hubs report with their device credential; sensors register on first report; safe ranges with a severity raise breach / recovery events (high/critical → alerts, auto-triaged) | ✅ | `tests/test_aegis.py` |
| LED and buzzer outputs: switched by per-sensor rules or a timed manual override; the hub receives state, never commands | ✅ | `test_hub_readings_thresholds_events_and_actuators`, `test_manual_actuator_override_wins_until_released` |
| Camera agent (`sentinel-agent camera`): OpenCV MOG2 motion, HOG person shapes (no identity), restricted zones, cooldown; detections only | ✅ | `agent/tests/test_edge.py`, live test in `test_agent_integration.py` |
| Privacy: new cameras start with detection off; snapshots only while privacy mode is off, people pixelated, JPEG/PNG checked, retention + deletion, purge when privacy mode returns, views audited | ✅ | `test_vision_is_off_until_enabled_and_respects_privacy`, `test_retention_purges_old_readings_and_expired_snapshots` |
| MQTT bridge (`sentinel-agent mqtt-bridge`) with validated topics/payloads and retained actuator state; Mosquitto compose profile without anonymous access | ✅ | `test_mqtt_messages_are_validated`, `test_bridge_batches_forwards_and_publishes_actuator_state` |
| ESP32 MicroPython hub firmware (DHT22, analog, digital sensors; LED/buzzer) | ✅ | `agent/tests/test_firmware.py` (CPython with fake hardware — not yet run on a physical board) |
| Hardware simulator: credential-less, labelled hub, sensors and camera; excluded from metrics; removable | ✅ | `test_simulator_is_labelled_excluded_from_metrics_and_clearable`, e2e `aegis.spec.ts` |
| Computer Vision and IoT Security pages (zone editor, privacy switches, outputs, sparklines) | ✅ | `IotPage.test.tsx`, e2e |
| Object classes beyond people (vehicles, packages) | ⬜ | needs a downloadable detection model (e.g. MobileNet-SSD); HOG covers people only |
| Firmware verified on real hardware | ⬜ | test on an ESP32 before production use |

## Phase 7 — Digital Twin ✅ (v0.7.0)

| Feature | Status | Evidence |
|---|---|---|
| Twin read model: devices with status, health, Brain risk, open alerts (worst severity), open incidents, sensors, cameras, saved position; /24 network segments; summary | ✅ | `tests/test_twin.py` |
| Layout: rooms on a 100 × 60 m floor and device positions, validated, audited, `devices:manage` only; the simulated flag of a room is decided by the server | ✅ | `test_layout_is_validated_saved_and_permissioned` |
| Three.js 3D view (lazy-loaded): status colours, risk-height markers, alert pulses, incident beacons, sensor/camera satellites, segment links, orbit, select, drag-to-place in edit mode | ✅ | e2e `twin.spec.ts` (WebGL render) + screenshots |
| Room-by-room list view; automatic fallback when WebGL is unavailable | ✅ | `TwinPage.test.tsx` |
| Real-time refresh on device, alert, incident, sensor and camera changes | ✅ | realtime provider |
| Simulator furnishes a labelled example site (three rooms, four machines) | ✅ | `test_simulator_furnishes_the_twin_and_clearing_keeps_real_areas` |
| Multiple floors / imported floor plans (images, CAD) | ⬜ | one floor per organization today |

## Phase 8 — Automation ✅ (v0.8.0)

| Feature | Status | Evidence |
|---|---|---|
| Workflows from an allow-list: triggers (new alert, incident opened, device offline, approval needed, schedule, manual, signed incoming webhook) and steps (notify, send to webhook, open incident, propose a block or heightened monitoring, record an event) | ✅ | `tests/test_automation.py::test_definitions_are_validated_against_the_allow_list` |
| Approval gates: medium-risk steps always wait; requesters cannot approve their own runs unless sole approver (recorded); approvals expire | ✅ | `test_medium_steps_always_wait_for_an_approver`, `test_manual_run_needs_a_second_person_unless_sole_approver`, `test_pending_runs_expire` |
| Signed outgoing webhooks: HMAC-SHA256 with timestamp, derived (never stored) secrets with rotation, outbox + worker, retries with back-off, no redirects, SSRF guard on every attempt, data-minimised payloads | ✅ | `test_alert_workflow_notifies_and_sends_a_signed_minimal_webhook`, `test_deliveries_retry_transient_errors_and_give_up`, `test_targets_refuse_internal_addresses_and_plain_http` |
| Signed incoming hooks: time window, replay protection, size and rate limits; can only record events or *propose* blocks | ✅ | `test_incoming_hook_is_signed_replay_safe_and_only_proposes` |
| Safety rails: automation never starts automation; the emergency stop pauses runs, approvals and deliveries; removed owners stop permissioned steps | ✅ | `test_imported_events_raise_alerts_but_never_start_more_automation`, `test_emergency_stop_pauses_runs_approvals_and_deliveries`, `test_removed_owner_stops_permissioned_steps` |
| Schedules run once per slot (multi-instance safe) with real counts, simulator data excluded | ✅ | `test_schedules_run_once_per_slot_with_real_counts` |
| Automation console: recipes, three-part builder, workflow cards, approvals and run history, webhooks with test send, deliveries and retry | ✅ | `AutomationPage.test.tsx`, e2e `automation.spec.ts` (real signed delivery verified by a local receiver) |
| n8n kit: compose service, guide, Node.js signer/verifier cross-checked with the Python signer | ✅ | `integrations/n8n/` (`node --test`) |
| Calling n8n's own API (listing or starting n8n workflows by id) | ⬜ | webhooks cover both directions today |

## Phase 9 — Hardening & testing ✅ (v0.9.0)

| Feature | Status | Evidence |
|---|---|---|
| Security sweep over every API operation: anonymous callers refused, other tenants get 404 and never a 2xx with foreign IDs (with a positive control), forged / expired / wrong-audience / device tokens rejected, headers and error hygiene | ✅ | `tests/test_security_sweep.py` |
| API fuzzing (Schemathesis, 8,500+ generated requests): found 3 server errors, all fixed; in CI | ✅ | `scripts/fuzz_api.py`, `test_fuzzer_findings_stay_fixed` |
| DAST (OWASP ZAP API scan, passive + active, 113 rules): 0 Medium/High; in CI | ✅ | `scripts/dast_zap.py`, [SECURITY.md](SECURITY.md#phase-9-security-testing-results) |
| Dependency audits (pip-audit, npm audit) in CI | ✅ | CI |
| Request body limits (1 MB default, sized limits on upload routes) | ✅ | `test_oversized_bodies_are_refused_before_they_are_read` |
| Load tests (Locust: console users + agents) with measured results; found and fixed a concurrency 500 | ✅ | [PERFORMANCE.md](PERFORMANCE.md), `tests/test_concurrency.py` |
| Query budgets: no N+1 on 18 list endpoints (found and fixed two) | ✅ | `tests/test_query_budget.py` |
| Redis rate limiting shared by several API instances, hashed keys, per-instance fallback | ✅ | `tests/test_rate_limit_redis.py` (real Redis) |
| Research Lab: frozen labelled datasets, data-only rule language, backtests vs. the built-in rules, reproducibility checks | ✅ | `tests/test_lab.py`, `LabPage.test.tsx`, e2e `lab.spec.ts` |
| Promote a lab rule to live detection | ⬜ | the lab is deliberately read-only towards production today |
| Realtime fan-out across several API instances (Redis pub/sub) | ⬜ | WebSocket delivery is per instance |

## Phase 10 — Deployment ⬜

- Live Supabase + Render + Cloudflare deployment, email provider, public registration policy, monitoring
