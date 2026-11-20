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
  permissions: permissions ?? (role === 'owner' ? ['dashboard:read', 'org:read', 'org:update', 'members:read', 'members:manage', 'audit:read'] : ['dashboard:read', 'org:read', 'members:read', 'audit:read']),
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
