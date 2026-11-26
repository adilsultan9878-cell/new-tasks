# Go-live runbook (Phase 10)

Everything here uses free tiers: **Supabase** (database), **Render** (API), **Cloudflare Pages**
(console), an **SMTP provider** (e-mail) and **UptimeRobot** (monitoring). Steps that need your own
accounts are marked 👤 — nobody else can (or should) sign in to them for you.

Detailed screens and options for steps 2-4 are in [DEPLOYMENT.md](DEPLOYMENT.md#c-cloud-deployment-free-tiers).

## 0. What is already done

- [x] Supabase project `sentinel-x` (ap-south-1) with every migration applied, RLS on every table,
      Data API roles revoked, and the least-privileged `sentinel_app` role granted.
- [x] `render.yaml` Blueprint with every variable, generated secrets (`JWT_SECRET`,
      `AUTOMATION_SIGNING_KEY`, `METRICS_TOKEN`) and safe defaults (invite-only sign-up).
- [x] Console security headers (`frontend/public/_headers`) and the same-origin `/api` proxy.
- [x] `backend/scripts/verify_deployment.py` and the **Live smoke test** workflow to check the
      result from the outside.

## 1. 👤 Supabase: the runtime password

The API connects as `sentinel_app`, never as the owner. Give it a password **you** choose (a long
random string — keep it in your password manager, never in chat or Git):

**Supabase → SQL Editor**

```sql
ALTER ROLE sentinel_app WITH PASSWORD 'your-long-random-password';
```

Runtime URL for Render (Supabase → Connect → **Session pooler**, replace user and password):

```
postgresql://sentinel_app.<project-ref>:<password>@aws-0-ap-south-1.pooler.supabase.com:5432/postgres
```

## 2. 👤 Render: the API

1. render.com → **New → Blueprint** → choose this GitHub repository → Render reads `render.yaml`.
2. Fill in the variables it asks for:

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | the `sentinel_app` URL from step 1 |
   | `CORS_ORIGINS` | the console address from step 3, e.g. `https://sentinel-x.pages.dev` |
   | `PUBLIC_APP_URL` | the same console address |
   | `EMAIL_FROM`, `SMTP_*` | from step 4 (leave `EMAIL_BACKEND=disabled` until then) |
   | `ALLOWED_EMAIL_DOMAINS` | only for `REGISTRATION_MODE=domains` |

3. Deploy. `https://<service>.onrender.com/health` answers `{"status":"ok"}` when it is up (the
   free instance sleeps after 15 idle minutes; the first request then takes ~50 s).

## 3. 👤 Cloudflare Pages: the console

1. Cloudflare → **Workers & Pages → Create → Pages → Connect to Git** → this repository.
2. Root directory `frontend`, build command `npm run build`, output `dist`.
3. Variables (Production and Preview): `NODE_VERSION=22`, `API_ORIGIN=https://<service>.onrender.com`.
4. Deploy, then put the `https://<project>.pages.dev` address into Render's `CORS_ORIGINS` and
   `PUBLIC_APP_URL` (step 2) and redeploy the API.

## 4. 👤 E-mail (password reset, verification, invitations)

Any SMTP provider works. Two with free tiers:

| Provider | Free tier (check their pricing page) | `SMTP_HOST` | `SMTP_PORT` |
|---|---|---|---|
| Brevo | ~300 e-mails/day | `smtp-relay.brevo.com` | `587` |
| Resend | ~3,000 e-mails/month | `smtp.resend.com` | `587` |

1. Create the account, verify your sending domain (add the SPF/DKIM DNS records they show) or a
   single sender address.
2. Create SMTP credentials and set on Render: `EMAIL_BACKEND=smtp`, `EMAIL_FROM=SENTINEL X
   <alerts@your-domain>`, `SMTP_HOST`, `SMTP_PORT=587`, `SMTP_USERNAME`, `SMTP_PASSWORD`.
3. Without e-mail everything still works: invitation links are shown once to the inviter, and
   "Forgot password" says plainly that it is not configured.

## 5. Sign-up policy

`REGISTRATION_MODE` (Render):

| Value | Who can create an account |
|---|---|
| `invite_only` (Blueprint default) | the very first person (becomes owner), then only people invited from **Users & Roles → Invite by e-mail** |
| `domains` | addresses at `ALLOWED_EMAIL_DOMAINS` (comma-separated), plus invited people |
| `open` | anyone |

`REQUIRE_EMAIL_VERIFICATION=true` (needs e-mail) makes people confirm their address before they
can create an organization.

**First sign-in:** open the console, create your account (you become the owner of the first
organization), then invite your team.

## 6. 👤 Monitoring

1. **UptimeRobot** (free): an HTTP(S) monitor on `https://<service>.onrender.com/api/v1/health/ready`
   (alerts when the database or a background job is down; also keeps the free instance awake within
   the provider's terms) and one on the console address.
2. Optional metrics: Grafana Cloud (free) → Prometheus scrape of `https://<service>.onrender.com/metrics`
   with the header `Authorization: Bearer <METRICS_TOKEN>` (Render → Environment shows the
   generated token).
3. GitHub → **Settings → Secrets and variables → Actions → Variables**: `SENTINEL_API_URL` and
   `SENTINEL_CONSOLE_URL` turn on the daily **Live smoke test**.

## 7. Verify

```bash
python backend/scripts/verify_deployment.py --api https://<service>.onrender.com --console https://<project>.pages.dev
```

or run **Actions → Live smoke test → Run workflow**. Every line should say PASS:
liveness, readiness, database, **Row-Level Security enforced**, security headers, HSTS, hidden
docs, private `/metrics`, CORS (console allowed, others refused), console headers, SPA routes and
the same-origin `/api` proxy.

## 8. After go-live

- [ ] Supabase → Database → Backups: confirm daily backups (and test a restore once).
- [ ] Rotate nothing into chat: secrets live only in Render, Cloudflare and your password manager.
- [ ] Review the audit log weekly (Admin → Audit Log).
