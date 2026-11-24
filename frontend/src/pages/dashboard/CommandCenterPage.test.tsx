import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { DashboardSummary } from '@/lib/types'
import { mockApi, renderInOrg } from '@/test/utils'

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

const noRuns = { items: [], total: 0, limit: 1, offset: 0 }

describe('CommandCenterPage', () => {
  it('shows honest zeros and empty states for a new organization', async () => {
    mockApi({ '/dashboard/summary': base, '/brain/runs': noRuns, '/alerts': [] })
    renderInOrg(<CommandCenterPage />)
    expect(await screen.findByTestId('kpi-Enrolled devices')).toHaveTextContent('0')
    expect(screen.getByText('No open alerts')).toBeInTheDocument()
    expect(screen.getByText('No enrolled devices')).toBeInTheDocument()
    expect(screen.getByText('Enforced')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Getting started' })).toHaveTextContent('1 of 4 complete')
    expect(await screen.findByText(/Not analysed yet/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Analyze my security/ })).toBeInTheDocument()
    expect(screen.queryByText(/simulated records/)).not.toBeInTheDocument()
  })

  it('renders real counts, the latest posture score, triaged alerts and the simulated-data notice', async () => {
    mockApi({
      '/dashboard/summary': {
        ...base,
        devices_total: 3,
        devices_by_status: [{ key: 'online', count: 2 }, { key: 'offline', count: 1 }],
        device_health_avg: 81,
        critical_alerts: 2,
        open_alerts_by_severity: [{ key: 'critical', count: 2 }, { key: 'high', count: 1 }, { key: 'medium', count: 0 }, { key: 'low', count: 0 }, { key: 'info', count: 0 }],
        simulated_records_excluded: 4,
      },
      '/brain/runs': { ...noRuns, total: 1, items: [{
        id: 'r1', agent_name: 'orchestrator', trigger: 'manual', status: 'succeeded', model_provider: 'none', subject_type: 'organization',
        subject_id: 'o1', subject_label: 'Blue Team Lab', risk_score: 62, risk_level: 'high', coverage: 80, priority: null, summary: 's',
        finding_count: 3, recommendation_count: 2, created_by: null, created_at: new Date().toISOString(), finished_at: null,
      }] },
      '/alerts': [{ id: 'a1', event_id: 'e1', title: 'Backdoor port opened', description: null, severity: 'critical', status: 'open', risk_score: 95,
        detection_rule: 'severity-threshold', created_at: new Date().toISOString(),
        triage: { run_id: 'r9', risk_score: 81, risk_level: 'critical', priority: 'P1', created_at: new Date().toISOString() } }],
    })
    renderInOrg(<CommandCenterPage />)
    expect(await screen.findByTestId('kpi-Critical alerts')).toHaveTextContent('2')
    expect(screen.getByTestId('kpi-Enrolled devices')).toHaveTextContent('3')
    expect(screen.getByText('2 online')).toBeInTheDocument()
    expect(screen.getByRole('list', { name: 'Open alerts by severity' })).toHaveTextContent('Critical2')
    expect(screen.getByText(/4 simulated records exist/)).toBeInTheDocument()
    expect(await screen.findByRole('meter', { name: 'Organization risk score' })).toHaveAttribute('aria-valuenow', '62')
    expect(screen.getByRole('link', { name: /See why/ })).toHaveAttribute('href', '/org/11111111-1111-1111-1111-111111111111/brain/runs/r1')
    expect(await screen.findByRole('link', { name: /P1/ })).toHaveAttribute('href', '/org/11111111-1111-1111-1111-111111111111/brain/runs/r9')
  })
})
