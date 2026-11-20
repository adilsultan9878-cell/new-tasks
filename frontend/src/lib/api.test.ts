import { afterEach, describe, expect, it, vi } from 'vitest'

import { jsonResponse } from '@/test/utils'

import { api, ApiError, setAccessToken, setSessionExpiredHandler } from './api'

afterEach(() => {
  setAccessToken(null)
  setSessionExpiredHandler(null)
})

describe('api client', () => {
  it('sends the bearer token and CSRF header, and includes credentials', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse({ ok: true }))
    setAccessToken('abc')
    await api('/auth/me')
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/v1/auth/me')
    expect((init!.headers as Record<string, string>).Authorization).toBe('Bearer abc')
    expect((init!.headers as Record<string, string>)['X-Requested-With']).toBe('sentinel-x')
    expect(init!.credentials).toBe('include')
  })

  it('refreshes once on 401 and retries the request with the new token', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'unauthorized', message: 'x' } }, 401))
      .mockResolvedValueOnce(jsonResponse({ access_token: 'fresh', token_type: 'bearer', expires_in: 900, user: {} }))
      .mockResolvedValueOnce(jsonResponse({ id: 1 }))
    setAccessToken('stale')
    await expect(api('/organizations')).resolves.toEqual({ id: 1 })
    expect(fetchMock.mock.calls[1]![0]).toBe('/api/v1/auth/refresh')
    expect((fetchMock.mock.calls[2]![1]!.headers as Record<string, string>).Authorization).toBe('Bearer fresh')
  })

  it('signs the user out when the refresh also fails', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'unauthorized', message: 'x' } }, 401))
      .mockResolvedValueOnce(jsonResponse({ error: { code: 'invalid_session', message: 'expired' } }, 401))
    const expired = vi.fn()
    setSessionExpiredHandler(expired)
    await expect(api('/organizations')).rejects.toBeInstanceOf(ApiError)
    expect(expired).toHaveBeenCalledOnce()
  })

  it('maps the error envelope, including field details and request id', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ error: { code: 'validation_error', message: 'Request validation failed', request_id: 'r1', details: [{ field: 'name', message: 'too short' }] } }, 422),
    )
    const err = (await api('/organizations', { method: 'POST', body: {}, auth: false }).catch((e) => e)) as ApiError
    expect(err.status).toBe(422)
    expect(err.code).toBe('validation_error')
    expect(err.fieldError('name')).toBe('too short')
    expect(err.requestId).toBe('r1')
  })

  it('reports a friendly error when the API is unreachable', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'))
    await expect(api('/health', { auth: false })).rejects.toMatchObject({ code: 'network_error' })
  })
})
