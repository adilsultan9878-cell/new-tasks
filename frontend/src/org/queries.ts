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
  devices: (orgId: string) => ['devices', orgId] as const,
  device: (orgId: string, id: string) => ['devices', orgId, id] as const,
  tokens: (orgId: string) => ['enrollment-tokens', orgId] as const,
  events: (orgId: string, params: Record<string, unknown>) => ['events', orgId, params] as const,
  event: (orgId: string, id: string) => ['events', orgId, 'detail', id] as const,
  alerts: (orgId: string) => ['alerts', orgId] as const,
  investigations: (orgId: string, types: string) => ['investigations', orgId, types] as const,
  investigation: (orgId: string, id: string) => ['investigations', orgId, 'detail', id] as const,
  indicators: (orgId: string, params: Record<string, unknown>) => ['indicators', orgId, params] as const,
  providers: ['intel-providers'] as const,
  vulns: (params: Record<string, unknown>) => ['vulnerabilities', params] as const,
  vulnStats: ['vulnerabilities', 'stats'] as const,
  vuln: (id: string) => ['vulnerabilities', 'detail', id] as const,
  scopes: (orgId: string) => ['network-scopes', orgId] as const,
  assets: (orgId: string) => ['network-assets', orgId] as const,
  brainStatus: ['brain', 'status'] as const,
  brainRuns: (orgId: string, params: Record<string, unknown>) => ['brain', orgId, 'runs', params] as const,
  brainRun: (orgId: string, id: string) => ['brain', orgId, 'run', id] as const,
  brainDecisions: (orgId: string, params: Record<string, unknown>) => ['brain', orgId, 'decisions', params] as const,
  brainActivity: (orgId: string) => ['brain', orgId, 'activity'] as const,
  incidents: (orgId: string, params: Record<string, unknown>) => ['incidents', orgId, 'list', params] as const,
  incident: (orgId: string, id: string) => ['incidents', orgId, 'detail', id] as const,
  actions: (orgId: string, params: Record<string, unknown>) => ['actions', orgId, params] as const,
  responseStatus: (orgId: string) => ['response', orgId] as const,
  evidence: (orgId: string, params: Record<string, unknown>) => ['evidence', orgId, params] as const,
  reports: (orgId: string) => ['reports', orgId, 'list'] as const,
  report: (orgId: string, id: string) => ['reports', orgId, 'detail', id] as const,
}

export function useMemberships(enabled = true) {
  return useQuery({
    queryKey: qk.memberships,
    queryFn: () => api<Membership[]>('/organizations'),
    enabled,
    staleTime: 30_000,
  })
}
