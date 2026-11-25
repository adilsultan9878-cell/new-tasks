// SENTINEL X webhook signatures (Node.js 18+, also usable inside an n8n Code node).
//
//   X-Sentinel-Timestamp: <unix seconds>
//   X-Sentinel-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>
//
// The secret string (whsec_...) is the HMAC key. Always verify the *raw* bytes you received —
// re-serialising parsed JSON changes them.
'use strict'
const crypto = require('crypto')

const TOLERANCE_SECONDS = 300

function sign(secret, rawBody, timestamp = Math.floor(Date.now() / 1000)) {
  const mac = crypto.createHmac('sha256', secret).update(`${timestamp}.`).update(rawBody).digest('hex')
  return { 'X-Sentinel-Timestamp': String(timestamp), 'X-Sentinel-Signature': `v1=${mac}` }
}

/** Returns null when valid, otherwise a short reason. Header names are case-insensitive. */
function verify(secret, rawBody, headers, now = Date.now() / 1000) {
  const get = (name) => {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name)
    return key === undefined ? undefined : String(headers[key])
  }
  const ts = get('x-sentinel-timestamp')
  const given = get('x-sentinel-signature')
  if (!ts || !given) return 'missing signature headers'
  if (!/^\d+$/.test(ts) || Math.abs(now - Number(ts)) > TOLERANCE_SECONDS) return 'timestamp outside the allowed window'
  const expected = sign(secret, rawBody, ts)['X-Sentinel-Signature']
  const ok = given.split(/[\s,]+/).some((sig) => sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)))
  return ok ? null : 'signature mismatch'
}

module.exports = { sign, verify, TOLERANCE_SECONDS }
