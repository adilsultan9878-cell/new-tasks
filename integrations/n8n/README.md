# n8n ↔ SENTINEL X

SENTINEL X talks to [n8n](https://n8n.io) (or any tool that speaks HTTP) in two directions, always
with signed requests:

| Direction | Use it for | In SENTINEL X |
|---|---|---|
| **SENTINEL X → n8n** | post alerts, daily summaries or approval requests to Slack, Teams, email, tickets | *Automation → Add webhook*, then a workflow step **Send to a webhook** |
| **n8n → SENTINEL X** | import alerts from other tools, propose blocking an indicator another tool reported | *Automation → New workflow → When another tool calls (signed webhook)* |

Nothing n8n sends can change your defences directly: incoming requests can only *record events*
or *propose* a block, and proposed blocks wait for an approver in Incident Response.

## Signatures

Every request in either direction carries two headers:

```
X-Sentinel-Timestamp: 1700000000
X-Sentinel-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>
```

* The secret (`whsec_…`) is the HMAC key. It is shown once when you create a webhook or workflow;
  SENTINEL X does not store it (it is derived from `AUTOMATION_SIGNING_KEY`). Lost it? Make a new one.
* Requests older or newer than 5 minutes are rejected, and the same signed request is accepted once.
* Always sign/verify the **raw bytes**. Parsing and re-serialising JSON changes them.

[`sentinel-signature.js`](sentinel-signature.js) implements `sign()` and `verify()` for Node.js and
n8n Code nodes. Its tests (`node --test integrations/n8n/sentinel-signature.test.js`) include a
fixed vector produced by the Python signer of the API, so both sides are known to agree.

## 1. Start n8n

Local (Docker Compose, from the repository root):

```bash
docker compose --profile automation up -d n8n
```

Open http://localhost:5678 and create the n8n owner account. Inside the compose network the API
reaches n8n at `http://n8n:5678`, which is a private address: the compose file sets
`AUTOMATION_ALLOW_PRIVATE_TARGETS=true` for this local stack only. In production, use an n8n with a
public `https://` address and keep that setting `false`.

## 2. SENTINEL X → n8n (alerts to chat)

1. **n8n:** create a workflow and add a **Webhook** node: method `POST`, path `sentinel`,
   respond *Immediately*. Under *Options* turn on **Raw Body** so the Code node can check the
   signature. Activate the workflow and copy its *Production URL*
   (local compose: `http://n8n:5678/webhook/sentinel`).
2. **SENTINEL X:** *Automation → Add webhook* → kind *n8n* → paste the URL → copy the secret.
   Press **Send test**; the card should say *Test delivered (HTTP 200 …)*.
3. **n8n:** after the Webhook node add a **Code** node (*Run once for all items*) and paste:

   ```js
   const crypto = require('crypto') // allowed via NODE_FUNCTION_ALLOW_BUILTIN=crypto (set in docker-compose.yml)
   const SECRET = 'whsec_…' // paste the secret from SENTINEL X (keep this n8n private)

   const item = $input.first()
   const raw = await this.helpers.getBinaryDataBuffer(0, 'data') // the Raw Body option
   const headers = item.json.headers
   const ts = String(headers['x-sentinel-timestamp'] || '')
   const expected = 'v1=' + crypto.createHmac('sha256', SECRET).update(ts + '.').update(raw).digest('hex')
   const given = String(headers['x-sentinel-signature'] || '')
   const fresh = Math.abs(Date.now() / 1000 - Number(ts)) <= 300
   const valid = fresh && given.split(/[\s,]+/).some((s) => s.length === expected.length
     && crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected)))
   if (!valid) throw new Error('Rejected: not signed by SENTINEL X')
   return [{ json: JSON.parse(raw.toString('utf8')) }]
   ```

   n8n versions differ slightly in how the raw body is exposed. If `getBinaryDataBuffer` finds no
   `data` property, check the binary property name on the Webhook node's output and use that.
4. Add a **Slack**, **Microsoft Teams** or **Send Email** node and use fields such as
   `{{ $json.data.alert.title }}`, `{{ $json.data.alert.severity }}` and `{{ $json.data.device.name }}`.
5. **SENTINEL X:** *New workflow* → recipe **Send serious alerts to n8n** → *Create workflow*.

### What SENTINEL X sends

```json
{
  "id": "5d3c…",                     // same as the X-Sentinel-Delivery header; dedupe on it
  "type": "alert.created",           // test | alert.created | incident.created | device.offline |
                                     // action.pending_approval | workflow.schedule | workflow.manual
  "created_at": "2026-11-25T10:00:00+00:00",
  "simulated": false,                // true only for simulator data (workflows ignore it by default)
  "organization": { "id": "…", "name": "Karachi Blue Team" },
  "workflow": { "id": "…", "name": "Send serious alerts to n8n" },
  "run_id": "…",
  "data": {
    "alert": { "id": "…", "title": "…", "severity": "critical", "status": "open", "rule": "severity-threshold", "link": "/events" },
    "device": { "id": "…", "name": "fin-ws-07", "device_type": "workstation" },
    "event": { "category": "auth", "event_type": "auth.failed_login" }
  }
}
```

Only titles, severities, names and links leave the platform — never raw event payloads, evidence
or credentials. Scheduled and manual runs send `data.summary` (open alerts by severity, open
incidents, device status, pending approvals; simulator data excluded).

Delivery: answered 2xx = delivered. Timeouts, 408, 429 and 5xx are retried after 30 s, 2 min,
10 min, 30 min and 2 h (6 attempts by default); other 4xx answers are not retried. Redirects are
never followed. Every attempt is listed under *Automation → Webhooks → Recent deliveries*.

## 3. n8n → SENTINEL X (block what another tool reports)

1. **SENTINEL X:** *New workflow* → recipe **Block what another tool reports** → *Create workflow*.
   Copy the **URL** and **secret** shown once.
2. **n8n:** add a **Code** node that builds and signs the body:

   ```js
   const crypto = require('crypto')
   const SECRET = 'whsec_…'
   const body = JSON.stringify({ value: $json.ip }) // whatever your previous node found
   const ts = Math.floor(Date.now() / 1000)
   const sig = 'v1=' + crypto.createHmac('sha256', SECRET).update(ts + '.').update(body).digest('hex')
   return [{ json: { body, ts: String(ts), sig } }]
   ```

3. Add an **HTTP Request** node: method `POST`, the URL from step 1, *Send Headers*
   `X-Sentinel-Timestamp = {{ $json.ts }}` and `X-Sentinel-Signature = {{ $json.sig }}`,
   *Send Body* → content type **Raw** (`application/json`) with body `{{ $json.body }}` — the
   exact string that was signed.
4. The answer is `202 {"run_id": "…", "status": "succeeded"}`. The proposal appears in
   *Incident Response → Actions* and waits for an approver.

Other answers: `401` bad or old signature · `409` replayed request or workflow switched off ·
`413` body over 64 KB · `422` body is not a JSON object · `429` too many requests.

### Try it without n8n

Linux / macOS (bash + openssl):

```bash
BODY='{"value":"203.0.113.7"}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SENTINEL_SECRET" -hex | sed 's/^.* //')
curl -X POST "$SENTINEL_HOOK_URL" -H "Content-Type: application/json" \
  -H "X-Sentinel-Timestamp: $TS" -H "X-Sentinel-Signature: v1=$SIG" --data "$BODY"
```

Windows (PowerShell):

```powershell
$body = '{"value":"203.0.113.7"}'
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($env:SENTINEL_SECRET))
$sig = -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$ts.$body")) | ForEach-Object { $_.ToString('x2') })
Invoke-RestMethod -Method Post -Uri $env:SENTINEL_HOOK_URL -ContentType 'application/json' `
  -Headers @{ 'X-Sentinel-Timestamp' = "$ts"; 'X-Sentinel-Signature' = "v1=$sig" } -Body $body
```

Set `SENTINEL_SECRET` and `SENTINEL_HOOK_URL` in your shell first; do not paste secrets into
shared scripts or chat.

## Import alerts from another tool

Recipe **Import alerts from another tool** turns a signed body like
`{"title": "EDR: credential dumping", "severity": "critical", "category": "malware"}` into a
security event (categories: network, auth, malware, phishing, vision, iot, system, agent, policy,
other). High and critical events raise alerts. Events created this way never start other
workflows, so SENTINEL X and n8n cannot loop.

## Verified here vs. on your n8n

* Verified in this repository: the signing scheme (Python ↔ Node.js test vector, the `openssl`
  command above), delivery, retries and signature checks against a local receiver in the
  end-to-end test.
* Not verified here: importing these steps into a specific n8n version. The n8n node options
  named above (Raw Body, HTTP Request raw body) exist in current n8n releases, but menus move
  between versions — follow n8n's documentation if a name differs.
