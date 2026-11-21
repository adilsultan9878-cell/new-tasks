import { vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { OrgProvider } from '@/org/OrgContext'
import type { Membership } from '@/lib/types'

export const membership = (role: 'owner' | 'viewer' = 'owner', permissions?: string[]): Membership => ({
  organization: {
    id: '11111111-1111-1111-1111-111111111111',
    name: 'Blue Team Lab',
    slug: 'blue-team-lab',
    description: null,
    industry: 'research',
    plan: 'free',
    created_at: '2026-11-20T10:00:00Z',
  },
  role: { key: role, name: role === 'owner' ? 'Owner' : 'Viewer', description: null, rank: role === 'owner' ? 100 : 10 },
  permissions: permissions ?? (role === 'owner' ? ['dashboard:read', 'org:read', 'org:update', 'members:read', 'members:manage', 'audit:read', 'devices:read', 'devices:manage', 'events:read', 'events:ingest', 'alerts:read', 'alerts:manage', 'intel:read', 'intel:manage', 'investigations:run', 'network:read', 'network:manage'] : ['dashboard:read', 'org:read', 'members:read', 'audit:read']),
  member_count: 1,
})

export function renderInOrg(ui: ReactNode, { m = membership(), path = '/org/x' } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <OrgProvider membership={m}>
          <Routes>
            <Route path="*" element={ui} />
          </Routes>
        </OrgProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

export function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/** Route fetch calls by "METHOD path-substring" (or just path-substring for GET). */
export function mockApi(routes: Record<string, unknown | ((body: unknown) => unknown)>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    const keys = Object.keys(routes).sort((a, b) => b.length - a.length)
    for (const key of keys) {
      const [m, path] = key.includes(' ') ? key.split(' ', 2) : ['GET', key]
      if (m === method && url.includes(path!)) {
        const value = routes[key]
        return jsonResponse(typeof value === 'function' ? (value as (b: unknown) => unknown)(body) : value)
      }
    }
    return jsonResponse({ error: { code: 'not_found', message: `unmocked ${method} ${url}` } }, 404)
  })
}
