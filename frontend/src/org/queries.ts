import { useQuery } from '@tanstack/react-query'

import { api } from '@/lib/api'
import type { Membership } from '@/lib/types'

export const qk = {
  memberships: ['memberships'] as const,
  dashboard: (orgId: string) => ['dashboard', orgId] as const,
  members: (orgId: string) => ['members', orgId] as const,
  roles: ['roles'] as const,
  audit: (orgId: string, params: Record<string, unknown>) => ['audit', orgId, params] as const,
  notifications: ['notifications'] as const,
  sessions: ['sessions'] as const,
}

export function useMemberships(enabled = true) {
  return useQuery({
    queryKey: qk.memberships,
    queryFn: () => api<Membership[]>('/organizations'),
    enabled,
    staleTime: 30_000,
  })
}
