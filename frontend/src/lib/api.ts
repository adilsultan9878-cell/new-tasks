/**
 * API client.
 * - The short-lived access token lives in memory only (never localStorage).
 * - The refresh token is an HttpOnly cookie the browser sends to /auth/* automatically.
 * - A 401 triggers one single-flight refresh and a retry; if that fails the user is signed out.
 */
import type { TokenResponse } from './types'

export const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, '') || '/api/v1'

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: { field: string; message: string }[] | undefined
  readonly requestId: string | undefined

  constructor(status: number, code: string, message: string, details?: { field: string; message: string }[], requestId?: string) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
  }

  /** First validation message for a field, if the server reported one. */
  fieldError(field: string): string | undefined {
    return this.details?.find((d) => d.field === field)?.message
  }
}

let accessToken: string | null = null
let refreshing: Promise<TokenResponse | null> | null = null
let onSessionExpired: (() => void) | null = null

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function getAccessToken(): string | null {
  return accessToken
}

/** WebSocket endpoint derived from the API base (relative bases use the page's own origin). */
export function websocketUrl(): string {
  const base = /^https?:\/\//.test(API_BASE) ? API_BASE : `${window.location.origin}${API_BASE}`
  return `${base.replace(/^http/, 'ws')}/ws`
}

/** Absolute API base URL, e.g. for agent install commands. */
export function absoluteApiBase(): string {
  return /^https?:\/\//.test(API_BASE) ? API_BASE : `${window.location.origin}${API_BASE}`
}

export function setSessionExpiredHandler(handler: (() => void) | null): void {
  onSessionExpired = handler
}

type Query = Record<string, string | number | boolean | null | undefined>

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'
  body?: unknown
  query?: Query
  auth?: boolean
  signal?: AbortSignal
}

function buildUrl(path: string, query?: Query): string {
  const url = `${API_BASE}${path}`
  if (!query) return url
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== '') params.set(k, String(v))
  }
  const qs = params.toString()
  return qs ? `${url}?${qs}` : url
}

async function toError(res: Response): Promise<ApiError> {
  let payload: unknown = null
  try {
    payload = await res.json()
  } catch {
    /* non-JSON error body */
  }
  const err = (payload as { error?: { code?: string; message?: string; details?: unknown; request_id?: string } } | null)?.error
  const details = Array.isArray(err?.details) ? (err.details as { field: string; message: string }[]) : undefined
  return new ApiError(
    res.status,
    err?.code ?? 'http_error',
    err?.message ?? (res.status >= 500 ? 'The server had a problem. Please try again.' : `Request failed (${res.status})`),
    details,
    err?.request_id ?? res.headers.get('x-request-id') ?? undefined,
  )
}

async function rawRequest(path: string, opts: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = { 'X-Requested-With': 'sentinel-x' }
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (opts.auth !== false && accessToken) headers.Authorization = `Bearer ${accessToken}`
  try {
    return await fetch(buildUrl(path, opts.query), {
      method: opts.method ?? 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      credentials: 'include',
      signal: opts.signal,
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e
    throw new ApiError(0, 'network_error', 'Cannot reach the SENTINEL X API. Check that the backend is running.')
  }
}

/** Exchange the refresh cookie for a new access token. Concurrent callers share one request. */
export function refreshSession(): Promise<TokenResponse | null> {
  refreshing ??= (async () => {
    try {
      const res = await rawRequest('/auth/refresh', { method: 'POST', auth: false })
      if (!res.ok) return null
      const data = (await res.json()) as TokenResponse
      accessToken = data.access_token
      return data
    } catch {
      return null
    } finally {
      queueMicrotask(() => {
        refreshing = null
      })
    }
  })()
  return refreshing
}

export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  let res = await rawRequest(path, opts)
  if (res.status === 401 && opts.auth !== false) {
    const refreshed = await refreshSession()
    if (refreshed) {
      res = await rawRequest(path, opts)
    } else {
      accessToken = null
      onSessionExpired?.()
    }
  }
  if (!res.ok) throw await toError(res)
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}
