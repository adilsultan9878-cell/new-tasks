# Performance and load testing (Phase 9)

Measured, not estimated. Every number below comes from the runs described here; repeat them with
the same commands. Results depend heavily on the machine — see "What these numbers mean".

## How to run it

```bash
pip install -r perf/requirements.txt
locust -f perf/locustfile.py --host http://127.0.0.1:8000 --headless -u 60 -r 10 -t 2m --csv perf/results/run
```

`perf/locustfile.py` simulates two kinds of clients:

| Client | Share | What it does |
|---|---|---|
| **Console user** | 3 of 5 | signs up, creates an organization, loads simulator data, then every 1-4 s opens the dashboard, events, alerts, incidents, devices, the digital twin, automation or notifications, and sometimes reports an event |
| **Agent** | 2 of 5 | enrolls into a shared fleet organization, then every 2-6 s sends a heartbeat, a batch of 5 events or a sensor reading |

The run fails (exit code 1) on any failed request or a p95 above 1 s.

Every simulated client comes from one address, so the API under test needs higher per-address
limits than production: `RATE_LIMIT_DEFAULT_PER_MINUTE=1000000`, `RATE_LIMIT_AUTH_PER_MINUTE=100000`,
`RATE_LIMIT_AGENT_PER_MINUTE=100000`. Run it against a disposable environment only — it creates accounts.

## Test environment (2026-11-25)

| | |
|---|---|
| Machine | one Linux container, 4 vCPU, 16 GB RAM (Locust, API, PostgreSQL and Redis share it) |
| API | `uvicorn --workers 2`, Python 3.13, v0.9.0 |
| Database | PostgreSQL 16, API connected as the least-privileged `sentinel_app` role (RLS enforced) |
| Rate limiter | Redis 7.0 (`REDIS_URL` set) |
| Duration | 2 minutes per run, 10 new clients per second until the target is reached |

## Results

### 60 concurrent clients (36 console users, 24 agents)

2,486 requests, **0 failures**, ~21 requests/s, median 26 ms, p95 220 ms.

| Endpoint | Requests | Failures | Median ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| POST agent/heartbeat | 402 | 0 | 14 | 34 | 210 |
| POST agent/events (5 events) | 205 | 0 | 30 | 72 | 280 |
| POST agent/sensors/readings | 103 | 0 | 20 | 96 | 230 |
| GET dashboard/summary | 455 | 0 | 43 | 86 | 270 |
| GET events | 302 | 0 | 24 | 38 | 61 |
| GET alerts | 262 | 0 | 24 | 42 | 210 |
| GET incidents | 148 | 0 | 26 | 51 | 170 |
| GET devices | 144 | 0 | 23 | 38 | 260 |
| GET notifications | 144 | 0 | 14 | 34 | 88 |
| GET twin | 63 | 0 | 30 | 52 | 180 |
| GET automation/overview | 65 | 0 | 31 | 140 | 290 |
| POST events (report) | 58 | 0 | 36 | 69 | 210 |
| POST agent/enroll | 24 | 0 | 270 | 460 | 470 |
| POST organizations (create) | 37 | 0 | 180 | 640 | 660 |
| POST auth/register | 37 | 0 | 660 | 970 | 990 |
| POST simulator/run | 36 | 0 | 820 | 1,200 | 1,500 |

### 150 concurrent clients (90 console users, 60 agents)

5,899 requests, **1 failure** (0.02 %), ~49 requests/s, median 35 ms, p95 520 ms.

| Endpoint | Requests | Failures | Median ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|
| POST agent/heartbeat | 954 | 1 | 16 | 250 | 540 |
| POST agent/events (5 events) | 462 | 0 | 35 | 330 | 630 |
| POST agent/sensors/readings | 244 | 0 | 24 | 320 | 550 |
| GET dashboard/summary | 1,061 | 0 | 52 | 390 | 860 |
| GET events | 671 | 0 | 28 | 240 | 720 |
| GET alerts | 622 | 0 | 29 | 260 | 600 |
| GET incidents | 362 | 0 | 32 | 180 | 780 |
| GET devices | 332 | 0 | 29 | 140 | 640 |
| GET notifications | 373 | 0 | 18 | 290 | 600 |
| GET twin | 170 | 0 | 34 | 190 | 850 |
| GET automation/overview | 165 | 0 | 38 | 420 | 830 |
| POST events (report) | 150 | 0 | 46 | 210 | 610 |
| POST agent/enroll | 60 | 0 | 220 | 740 | 920 |
| POST organizations (create) | 91 | 0 | 150 | 950 | 1,000 |
| POST auth/register | 91 | 0 | 630 | 1,000 | 1,200 |
| POST simulator/run | 90 | 0 | 1,100 | 2,500 | 3,000 |

The one failure was a heartbeat whose connection the server had just closed as idle
(`RemoteDisconnected`); the API logged no error for it. A real agent retries on its next beat.

The raw Locust statistics are in [`perf/results/`](../perf/results/).

## What these numbers mean

* At 60 clients everything steady-state (heartbeats, lists, dashboard) answers in under 100 ms at
  p95. At 150 clients on the same 4 vCPU (shared with the database and the load generator) the
  tail grows to 0.3-0.9 s, but nothing fails: the limit of this machine is around there.
* **Sign-up is slow on purpose**: passwords are hashed with Argon2id (memory-hard). ~0.6 s per
  sign-up is the price of making stolen hashes expensive to crack.
* **The simulator** writes a whole demo site (devices, sensors, cameras, events, alerts, Brain runs)
  in one request; it is a one-off action, not a hot path.
* **Render's free tier is much smaller** (a fraction of one CPU, 512 MB RAM) and sleeps when idle;
  expect lower throughput there and a slow first request after a pause. Phase 10 repeats the
  measurement on the deployed stack.

## Problems the tests found (fixed)

| Found by | Problem | Fix |
|---|---|---|
| Load test | Two people creating organizations with the same name at the same moment could get a 500 (both passed the slug check, the unique index refused the second) | The insert runs in a savepoint and retries with a suffix; regression test with 8 real concurrent transactions on PostgreSQL (`tests/test_concurrency.py`) |
| Query budget test | `GET /hubs` ran one query per board and `GET /members` one per member (N+1) | Sensors are loaded once and grouped; members join their users in the same query |

## Query budgets (in CI)

`tests/test_query_budget.py` counts the SQL statements of 18 list endpoints with few records and
again with many more. The count must not grow with the number of rows (no N+1), and no list
endpoint may need more than 40 statements.
