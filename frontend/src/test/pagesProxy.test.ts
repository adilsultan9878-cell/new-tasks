// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'

// @ts-expect-error — plain JS Cloudflare Pages Function without type declarations
import { onRequest } from '../../functions/api/[[path]].js'

describe('Cloudflare Pages /api proxy', () => {
  it('forwards method, path, query and body to API_ORIGIN and pins X-Forwarded-For', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"ok":true}', { status: 201 }))
    const request = new Request('https://sentinel.pages.dev/api/v1/auth/login?x=1', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': '6.6.6.6', 'CF-Connecting-IP': '203.0.113.7' },
      body: JSON.stringify({ email: 'a@b.c' }),
    })
    const res: Response = await onRequest({ request, env: { API_ORIGIN: 'https://api.example.onrender.com' } })
    expect(res.status).toBe(201)
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('https://api.example.onrender.com/api/v1/auth/login?x=1')
    expect(init!.method).toBe('POST')
    const headers = init!.headers as Headers
    expect(headers.get('X-Forwarded-For')).toBe('203.0.113.7') // spoofed value replaced
    expect(new TextDecoder().decode(init!.body as ArrayBuffer)).toBe('{"email":"a@b.c"}')
  })

  it('fails closed when API_ORIGIN is missing', async () => {
    const res: Response = await onRequest({ request: new Request('https://x.pages.dev/api/v1/health'), env: {} })
    expect(res.status).toBe(502)
  })
})
