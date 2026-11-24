# Running & deploying SENTINEL X

Three ways to run it, from quickest to production-like:

| Option | Database | Needs | RLS enforced |
|---|---|---|---|
| A. Local quick start | SQLite file | Python 3.11+ and Node 20+ | no (app-layer isolation only) |
| B. Docker Compose | PostgreSQL 16 | Docker Desktop | **yes** |
| C. Cloud | Supabase PostgreSQL | free accounts on Supabase, Render, Cloudflare | **yes** |

---

## A. Local quick start (Windows PowerShell)

Requirements: [Python 3.12](https://www.python.org/downloads/) (tick *Add python.exe to PATH*),
[Node.js 22 LTS](https://nodejs.org/), [Git](https://git-scm.com/download/win).

### 1. Backend (terminal 1)

```powershell
git clone https://github.com/adilsultan9878-cell/new-tasks.git sentinel-x-aegis-nexus
cd sentinel-x-aegis-nexus\backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
Copy-Item .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

If PowerShell refuses to run `Activate.ps1`, allow local scripts once for your user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Check: <http://localhost:8000/health> returns `{"status":"ok"}` and the interactive API docs are at
<http://localhost:8000/docs>.

### 2. Frontend (terminal 2)

```powershell
cd sentinel-x-aegis-nexus\frontend
npm install
npm run dev
```

Open <http://localhost:5173>, create an account, then create your organization. The Vite dev
server proxies `/api` to `http://127.0.0.1:8000`, so no CORS or cookie configuration is needed.

### macOS / Linux

Same steps with `python3 -m venv .venv`, `source .venv/bin/activate` and `cp .env.example .env`.

---

## B. Docker Compose (PostgreSQL + RLS)

```powershell
cd sentinel-x-aegis-nexus
docker compose up --build
```

* Console: <http://localhost:8080> (nginx serves the build and proxies `/api`)
* API: <http://localhost:8000/docs>
* PostgreSQL: `localhost:5432` (`postgres` / `postgres_dev_password`)

On first start the database container creates the least-privileged `sentinel_app` role, and the API
container runs the migrations with the owner role and then serves requests as `sentinel_app`. The
Command Center's *System health* panel should show **Row-Level Security: Enforced**.

`docker compose down -v` stops everything and deletes the database volume.

To run the API outside Docker against this database, put these in `backend/.env`:

```
DATABASE_URL=postgresql://sentinel_app:sentinel_app_dev_password@localhost:5432/sentinel
MIGRATION_DATABASE_URL=postgresql://postgres:postgres_dev_password@localhost:5432/sentinel
```

---

## C. Cloud deployment (free tiers)

```
Browser ──HTTPS──> Cloudflare Pages (console + /api proxy function) ──HTTPS──> Render (API) ──TLS──> Supabase (PostgreSQL)
```

The Pages Function in `frontend/functions/api/[[path]].js` forwards `/api/*` to Render. The
browser therefore talks to a single origin, which keeps the refresh cookie first-party — it keeps
working in browsers that block third-party cookies (Safari, Firefox strict mode, Chrome's
tracking protection).

### Step 1 — Push the code to GitHub

Already done if you are reading this from the repository. Render and Cloudflare deploy from it.

### Step 2 — Supabase (database)

1. Create a project at <https://supabase.com> (choose a region close to your Render region) and save
   the database password.
2. **Project Settings → Database → Connection string → Session pooler** (IPv4, port 5432). It looks
   like `postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres`.
   Use the *session* pooler (not the transaction pooler on 6543).
3. Run the migrations **from your computer** with that owner connection:

   ```powershell
   cd backend
   .\.venv\Scripts\Activate.ps1
   $env:MIGRATION_DATABASE_URL = "postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres"
   alembic upgrade head
   ```

   No direct database connection? Generate the SQL offline and paste it into **SQL Editor** instead.
   For a new database use `alembic upgrade head --sql`; to apply only newer migrations to an
   existing one, give the range, e.g. `alembic upgrade 0003:head --sql` (the current revision is
   in `SELECT version_num FROM alembic_version`).

4. Create the runtime role. In **SQL Editor** run (choose your own long password):

   ```sql
   CREATE ROLE sentinel_app LOGIN PASSWORD 'replace-with-a-long-random-password'
     NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
   GRANT USAGE ON SCHEMA public TO sentinel_app;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app;
   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app;
   GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO sentinel_app;
   ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
   ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO sentinel_app;
   ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO sentinel_app;
   ```

   (With `psql` you can run `backend/scripts/postgres/create_app_role.sql` instead.)
5. The runtime URL is the same pooler URL with the new role:
   `postgresql://sentinel_app.<project-ref>:<app-password>@aws-0-<region>.pooler.supabase.com:5432/postgres`

The migration already revokes the Supabase Data API roles (`anon`, `authenticated`) from these
tables, so nothing is exposed through Supabase's public REST endpoint.

### Step 3 — Render (API)

1. <https://render.com> → **New → Blueprint** → select the repository. Render reads `render.yaml`.
2. Fill in the variables it asks for:

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | the `sentinel_app` pooler URL from step 2.5 |
   | `MIGRATION_DATABASE_URL` | leave empty (you migrated from your computer) |
   | `CORS_ORIGINS` | your Pages URL, e.g. `https://sentinel-x.pages.dev` |

3. `RUN_MIGRATIONS_ON_START` is `false` in the Blueprint (recommended: the owner password then
   never lives in the runtime). If you prefer automatic migrations on deploy, set it to `true`
   **and** provide `MIGRATION_DATABASE_URL` — with `true` and no owner URL the container refuses
   to start. The Blueprint deploys to `singapore`; change `region` in `render.yaml` to the Render
   region closest to your Supabase project.
4. `JWT_SECRET` is generated by Render. Deploy, then open `https://<service>.onrender.com/health`.

### Step 4 — Cloudflare Pages (console)

1. Cloudflare dashboard → **Workers & Pages → Create → Pages → Connect to Git** → pick the repo.
2. Build settings:

   | Setting | Value |
   |---|---|
   | Framework preset | None (or Vite) |
   | Root directory | `frontend` |
   | Build command | `npm run build` |
   | Build output directory | `dist` |

3. Environment variables (Production *and* Preview):

   | Variable | Value |
   |---|---|
   | `NODE_VERSION` | `22` |
   | `API_ORIGIN` | `https://<service>.onrender.com` (used by the `/api` proxy function) |
   | `VITE_API_BASE_URL` | leave **empty** (the console calls `/api/v1` on its own origin) |

4. Deploy and open `https://<project>.pages.dev`. Register, create an organization — the dashboard
   should report **Row-Level Security: Enforced**.

`frontend/public/_headers` applies the console's security headers (CSP, HSTS, framing) and
`_redirects` provides SPA routing.

### Real-time stream and agents in the cloud

* The WebSocket endpoint `/api/v1/ws` works through all three paths: the Vite dev proxy, the
  Docker nginx config, and the Pages Function (which passes `Upgrade: websocket` requests straight to
  Render). Render supports WebSockets on the free plan; a sleeping instance drops the stream, and the
  console reconnects automatically with back-off once the API wakes up.
* Agents use the same public origin as the console:
  `sentinel-agent enroll --server https://<project>.pages.dev --token sxe.…`
  (or the Render URL directly). Only HTTPS is accepted for non-local servers.
* The real-time hub and the offline-device sweeper run inside the API process. Keep a **single API
  instance** until a shared message bus is added (see docs/ARCHITECTURE.md §7).

### Outbound access for threat intelligence

If your API host restricts egress, allow HTTPS to: `services.nvd.nist.gov`, `www.cisa.gov`,
`data.iana.org` and the RDAP servers it lists (e.g. `rdap.verisign.com`, `rdap.arin.net`,
`rdap.db.ripe.net`, `rdap.apnic.net`, `rdap.publicinterestregistry.org`), `cloudflare-dns.com`, and,
for the optional providers, `urlhaus-api.abuse.ch`, `mb-api.abuse.ch`, `api.abuseipdb.com`,
`www.virustotal.com`. Render allows all outbound traffic by default.

After the first deploy, open **Vulnerabilities → Refresh from CISA** once to load the KEV catalogue.

### Alternative: call the API directly (no proxy)

Set `VITE_API_BASE_URL=https://<service>.onrender.com/api/v1`, add that origin to `connect-src`
in `_headers`, and on Render set `REFRESH_COOKIE_SAMESITE=none`. Browsers that block third-party
cookies will then force a sign-in after every reload — prefer the proxy, or put the console and API
on sub-domains of one custom domain (`app.example.com` / `api.example.com`, `SameSite=lax`).

---

## Environment variable reference (API)

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `development` | `production` enables strict start-up checks and HSTS, and hides `/docs` |
| `DATABASE_URL` | `sqlite:///./sentinel_dev.db` | `postgres://` and `postgresql://` are accepted |
| `MIGRATION_DATABASE_URL` | — | owner connection for Alembic only |
| `JWT_SECRET` | random per process (dev) | **required** in production (≥ 32 chars) |
| `ACCESS_TOKEN_TTL_MINUTES` | `15` | |
| `REFRESH_TOKEN_TTL_DAYS` | `14` | |
| `REFRESH_REUSE_GRACE_SECONDS` | `20` | multi-tab race window; `0` = strict |
| `REFRESH_COOKIE_SECURE` | `false` | must be `true` in production |
| `REFRESH_COOKIE_SAMESITE` | `lax` | `none` only for cross-site direct API calls |
| `CORS_ORIGINS` | `http://localhost:5173,…` | comma-separated, no wildcards |
| `ALLOW_REGISTRATION` | `true` | set `false` for invite-only deployments |
| `RATE_LIMIT_AUTH_PER_MINUTE` | `10` | login/register/password change, per IP & path |
| `RATE_LIMIT_REFRESH_PER_MINUTE` | `120` | per IP |
| `RATE_LIMIT_DEFAULT_PER_MINUTE` | `300` | all `/api` traffic, per IP |
| `RUN_MIGRATIONS_ON_START` | `true` | container start-up only |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | proxies trusted for `X-Forwarded-For` |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `5` / `5` | keep small on free database tiers |
| `ENROLLMENT_TOKEN_MAX_HOURS` | `168` | upper bound for enrollment-token lifetime |
| `DEVICE_OFFLINE_AFTER_SECONDS` | `180` | silence before the sweeper marks a device offline |
| `DEVICE_SWEEP_INTERVAL_SECONDS` | `60` | how often the sweeper runs |
| `AGENT_DEFAULT_HEARTBEAT_SECONDS` | `60` | initial agent heartbeat interval |
| `RATE_LIMIT_AGENT_PER_MINUTE` | `120` | per device |
| `INGEST_MAX_EVENTS_PER_BATCH` / `INGEST_MAX_RAW_BYTES` | `100` / `16384` | ingestion limits |
| `EVENT_DEDUP_WINDOW_MINUTES` | `10` | duplicate-folding window |
| `BRUTEFORCE_THRESHOLD` / `BRUTEFORCE_WINDOW_MINUTES` | `5` / `5` | brute-force detection rule |
| `WS_PING_INTERVAL_SECONDS` / `WS_REVALIDATE_SECONDS` | `25` / `300` | WebSocket keep-alive and re-authorization |
| `ABUSECH_AUTH_KEY` | — | URLhaus + MalwareBazaar ([free key](https://auth.abuse.ch/)) |
| `ABUSEIPDB_API_KEY` | — | IP reputation ([free key](https://www.abuseipdb.com/register), 1,000 checks/day) |
| `VIRUSTOTAL_API_KEY` | — | multi-engine verdicts ([free key](https://www.virustotal.com/gui/join-us), ~4 requests/min) |
| `NVD_API_KEY` | — | optional; NVD allows ~5 requests/30 s without a key |
| `INTEL_OFFLINE` | `false` | `true` disables every outbound intelligence call (air-gapped labs, CI) |
| `INTEL_HTTP_TIMEOUT_SECONDS` | `8` | per provider request |
| `RATE_LIMIT_INVESTIGATIONS_PER_MINUTE` | `20` | per user |
| `AI_PROVIDER` | `none` | Security Brain engine; only `none` (deterministic rules, no AI model) is supported — other values are rejected at start-up |
| `BRAIN_AUTO_TRIAGE` | `true` | analyse every new alert automatically |
| `BRAIN_LOOKBACK_DAYS` | `7` | event window the Brain's agents read (1-90) |
| `RATE_LIMIT_BRAIN_PER_MINUTE` | `30` | manual analyses per user |
| `APPROVAL_TTL_HOURS` | `24` | pending approvals of response actions expire after this (1-168) |
| `EVIDENCE_MAX_BYTES` | `5000000` | per evidence file; files live in the database (count them against the Supabase free quota), larger material is registered by hash |

---

## Free-tier limitations (check the providers' current pricing pages)

| Provider | What to expect on the free plan | Production upgrade |
|---|---|---|
| **Render** | the service sleeps after ~15 minutes without traffic; the first request afterwards takes roughly 30–60 s (cold start). Limited RAM/CPU and monthly instance hours. The in-process rate limiter resets on every restart. | paid instance (always on), Redis for shared rate limiting, more instances behind the load balancer |
| **Supabase** | small database size quota; projects are **paused after about a week of inactivity** and must be resumed from the dashboard; limited backups. | Pro plan (no pausing, daily backups / PITR), connection pooling sized for the instance count |
| **Cloudflare Pages** | generous static hosting; Functions (the `/api` proxy) count against the Workers free request quota per day; limited builds per month. | Workers paid plan if the proxy quota becomes a limit, custom domain |

## Production checklist

- [ ] `ENVIRONMENT=production`, long random `JWT_SECRET`, `REFRESH_COOKIE_SECURE=true`
- [ ] API connects as `sentinel_app`; dashboard shows **RLS: Enforced**
- [ ] `CORS_ORIGINS` lists only your console origin(s)
- [ ] `ALLOW_REGISTRATION` decided (public sign-up vs invite-only)
- [ ] Database backups enabled; restore tested
- [ ] Uptime monitor on `/health` (also keeps a free Render instance warm, within the provider's terms)
- [ ] Custom domain with HTTPS for the console
- [ ] Email provider configured before enabling password reset / invitations (Phase 10)
