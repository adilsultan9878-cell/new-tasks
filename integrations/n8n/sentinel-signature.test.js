// Run with: node --test integrations/n8n/sentinel-signature.test.js
'use strict'
const assert = require('node:assert/strict')
const test = require('node:test')

const { sign, verify } = require('./sentinel-signature.js')

const secret = 'whsec_example-secret-for-tests-only'
const body = Buffer.from('{"id":"d1","type":"alert.created","data":{"alert":{"title":"Ransomware note"}}}')

test('a signed body verifies', () => {
  assert.equal(verify(secret, body, sign(secret, body)), null)
})

test('tampering, a wrong secret or an old timestamp fail', () => {
  const headers = sign(secret, body)
  assert.equal(verify(secret, Buffer.from(body.toString().replace('Ransomware', 'Nothing')), headers), 'signature mismatch')
  assert.equal(verify('whsec_other', body, headers), 'signature mismatch')
  const old = sign(secret, body, Math.floor(Date.now() / 1000) - 600)
  assert.equal(verify(secret, body, old), 'timestamp outside the allowed window')
  assert.equal(verify(secret, body, {}), 'missing signature headers')
})

test('header names are case-insensitive and rotation lists are accepted', () => {
  const h = sign(secret, body)
  const lower = { 'x-sentinel-timestamp': h['X-Sentinel-Timestamp'], 'x-sentinel-signature': `v1=deadbeef ${h['X-Sentinel-Signature']}` }
  assert.equal(verify(secret, body, lower), null)
})

test('matches the Python implementation (fixed vector)', () => {
  // backend: app.automation.signing.sign("whsec_vector", 1700000000, b'{"a":1}')
  const h = sign('whsec_vector', Buffer.from('{"a":1}'), 1700000000)
  assert.equal(h['X-Sentinel-Signature'], 'v1=5d485af0d9ddc3522d7a396ce60598f0d5fbb3bacdb1924001168092bc407c18')
})
