import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { membership, mockApi, renderInOrg } from '@/test/utils'

import { BrainPage } from './BrainPage'

const status = {
  engine: { provider: 'none', mode: 'deterministic', model: null, ai_enabled: false, engine_version: 'brain-rules/1', description: 'Deterministic rules engine.' },
  auto_triage: true, lookback_days: 7,
  agents: [{ name: 'triage', title: 'Alert Triage Agent', description: 'd', subjects: ['alert'], tools: ['alerts.for_device'] }],
  tools: [{ name: 'alerts.for_device', description: 'd' }],
  models: {
    alert: [{ key: 'alert_severity', label: 'Alert severity', max_points: 50, agent: 'triage', description: 'Severity of the rule.' }],
    device: [], organization: [],
  },
}

describe('BrainPage', () => {
  it('lists analyses with their risk and shows the engine and scoring model', async () => {
    mockApi({
      '/brain/status': status,
      '/brain/activity': { runs_total: 3, runs_by_trigger: { alert: 2, manual: 1 }, agents: [] },
      '/brain/runs': { items: [{
        id: 'r1', agent_name: 'orchestrator', trigger: 'alert', status: 'succeeded', model_provider: 'none', subject_type: 'alert',
        subject_id: 'a1', subject_label: 'Outbound connection to a known C2 server', risk_score: 81, risk_level: 'critical',
        coverage: 100, priority: 'P1', summary: 's', finding_count: 5, recommendation_count: 3, created_by: null,
        created_at: new Date().toISOString(), finished_at: null,
      }], total: 1, limit: 50, offset: 0 },
    })
    renderInOrg(<BrainPage />)
    const link = await screen.findByRole('link', { name: /Outbound connection to a known C2 server/ })
    expect(link).toHaveAttribute('href', '/org/11111111-1111-1111-1111-111111111111/brain/runs/r1')
    expect(link).toHaveTextContent('5 findings · 3 recommendations · coverage 100%')
    expect(await screen.findByText('AI provider: none')).toBeInTheDocument()
    expect(screen.getByText('Severity of the rule.', { exact: false })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Analyze organization/ })).toBeInTheDocument()
  })

  it('hides analysis actions from read-only roles', async () => {
    mockApi({ '/brain/status': status, '/brain/activity': { runs_total: 0, runs_by_trigger: {}, agents: [] }, '/brain/runs': { items: [], total: 0, limit: 50, offset: 0 } })
    renderInOrg(<BrainPage />, { m: membership('viewer', ['brain:read']) })
    expect(await screen.findByText('No analyses yet')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Analyze/ })).not.toBeInTheDocument()
  })
})
