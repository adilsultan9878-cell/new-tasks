# Roadmap & feature status

Legend: ✅ implemented and covered by automated tests · 🟡 partially implemented · ⬜ pending

## Phase 1 — Foundation ✅ (current release, v0.1.0)

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

## Phase 2 — Security Event Engine ⬜

- Device enrollment tokens and per-device credentials (`devices.credential_hash`)
- Event ingestion API with schema validation, size limits, fingerprint de-duplication
- Python local security agent (register, authenticate, approved telemetry, health, safe removal — no remote command execution)
- WebSocket real-time stream per organization (JWT + membership on connect)
- Device Management module UI

## Phase 3 — NEXUS ZERO ⬜

- URL & phishing analysis (deterministic checks, lookalike domains, SPF/DKIM/DMARC header parsing)
- File hash look-ups and static metadata (files never executed)
- IP / domain reputation from legitimate public sources, with attribution
- NVD CVE + CISA KEV synchronisation into `vulnerability_records`
- Authorized-scope network monitor (Nmap/Zeek ingestion; private scopes only)
- Investigation records with verified findings separated from AI assessments

## Phase 4 — AI Brain ⬜

- Pluggable LLM providers (none / Ollama / hosted), configured by environment
- Orchestrator + specialised agents with read-only, tenant-scoped tools
- Risk scoring (deterministic weights + AI confidence), investigation reports
- Agent run / decision history UI

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
