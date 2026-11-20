import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { DashboardSummary } from '@/lib/types'
import { jsonResponse, renderInOrg } from '@/test/utils'

import { CommandCenterPage } from './CommandCenterPage'

const base: DashboardSummary = {
  generated_at: '2026-11-20T10:00:00Z',
  devices_total: 0,
  devices_by_status: [],
  device_health_avg: null,
  active_events: 0,
  events_last_24h: 0,
  open_incidents: 0,
  critical_alerts: 0,
  open_alerts_by_severity: ['critical', 'high', 'medium', 'low', 'info'].map((key) => ({ key, count: 0 })),
  network_activity_24h: [],
  recent_events: [],
  recent_investigations: [],
  recent_agent_runs: [],
  agent_runs_24h_by_status: [],
  members: 1,
  simulated_records_excluded: 0,
  system: {
    api: 'ok', version: '0.1.0', environment: 'test', realtime: 'planned', uptime_seconds: 5,
    database: { status: 'ok', latency_ms: 1.2, engine: 'postgresql', row_level_security: 'enforced' },
  },
}

describe('CommandCenterPage', () => {
  it('shows honest zeros and empty states for a new organization', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(base))
    renderInOrg(<CommandCenterPage />)
    expect(await screen.findByTestId('kpi-Enrolled devices')).toHaveTextContent('0')
    expect(screen.getByText('No open alerts')).toBeInTheDocument()
    expect(screen.getByText('No enrolled devices')).toBeInTheDocument()
    expect(screen.getByText('No agent runs yet')).toBeInTheDocument()
    expect(screen.getByText('Enforced')).toBeInTheDocument()
    expect(screen.queryByText(/simulated records/)).not.toBeInTheDocument()
  })

  it('renders real counts, severity rows and the simulated-data notice', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({
        ...base,
        devices_total: 3,
        devices_by_status: [{ key: 'online', count: 2 }, { key: 'offline', count: 1 }],
        device_health_avg: 81,
        critical_alerts: 2,
        open_alerts_by_severity: [{ key: 'critical', count: 2 }, { key: 'high', count: 1 }, { key: 'medium', count: 0 }, { key: 'low', count: 0 }, { key: 'info', count: 0 }],
        simulated_records_excluded: 4,
      }),
    )
    renderInOrg(<CommandCenterPage />)
    expect(await screen.findByTestId('kpi-Critical alerts')).toHaveTextContent('2')
    expect(screen.getByTestId('kpi-Enrolled devices')).toHaveTextContent('3')
    expect(screen.getByText('2 online')).toBeInTheDocument()
    expect(screen.getByRole('list', { name: 'Open alerts by severity' })).toHaveTextContent('Critical2')
    expect(screen.getByText(/4 simulated records exist/)).toBeInTheDocument()
  })
})
