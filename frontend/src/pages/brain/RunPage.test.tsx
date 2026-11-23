import { screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { BrainRunDetail } from '@/lib/types'
import { renderInOrg } from '@/test/utils'

import { RunView } from './RunPage'
import { levelForScore, levelStyle } from './shared'

const run: BrainRunDetail = {
  id: 'r1', agent_name: 'orchestrator', trigger: 'alert', status: 'succeeded', model_provider: 'none',
  subject_type: 'alert', subject_id: 'a1', subject_label: 'Outbound connection to a known C2 server',
  risk_score: 81, risk_level: 'critical', coverage: 90, priority: 'P1',
  summary: 'Risk 81/100 (critical), priority P1, with 90% data coverage.',
  finding_count: 2, recommendation_count: 1, created_by: null, created_at: new Date().toISOString(), finished_at: null,
  factors: [
    { key: 'alert_severity', label: 'Alert severity', agent: 'triage', points: 50, max_points: 50, has_data: true, evidence: 'critical' },
    { key: 'asset_condition', label: 'Affected device condition', agent: 'device', points: 0, max_points: 10, has_data: false, evidence: 'The alert is not linked to a device.' },
  ],
  trace: [{ seq: 1, agent: 'orchestrator', tool: 'alerts.get', args: { _: ['a1'] }, rows: 1, duration_ms: 0.4 }],
  recommendations: [{
    code: 'intel.malicious_match', text: 'Block 203.0.113.66 at the firewall / DNS filter.', urgency: 'now',
    changes_system: true, agent: 'intel', because: '203.0.113.66 is on your watchlist as malicious', evidence: [],
  }],
  decisions: [
    { id: 'd1', agent_run_id: 'r1', decision_type: 'finding', agent_name: 'intel', severity: 'critical', summary: '203.0.113.66 is on your watchlist as malicious',
      rationale: 'ipv4 rated malicious', confidence: null, is_ai_generated: false, evidence_refs: [{ type: 'indicator', id: 'i1', label: '203.0.113.66' }], created_at: '' },
    { id: 'd2', agent_run_id: 'r1', decision_type: 'finding', agent_name: 'triage', severity: 'critical', summary: 'Detection rated this alert critical',
      rationale: null, confidence: null, is_ai_generated: false, evidence_refs: [], created_at: '' },
  ],
  agents: ['triage', 'device', 'exposure', 'intel'], lookback_days: 7, engine_version: 'brain-rules/1',
}

describe('RunView', () => {
  it('shows the score breakdown, missing data, advice-only recommendations and the tool trace', () => {
    renderInOrg(<RunView run={run} />)
    expect(screen.getByText(/no AI model/)).toBeInTheDocument()
    expect(screen.getByRole('meter', { name: 'Risk score' })).toHaveAttribute('aria-valuenow', '81')
    expect(screen.getByText('P1')).toBeInTheDocument()
    expect(screen.getByText(/no data · \/10/)).toBeInTheDocument()
    expect(screen.getByText(/the risk is a lower bound/)).toBeInTheDocument()
    expect(screen.getByText(/changes a system · needs approval/)).toBeInTheDocument()
    const intel = screen.getByRole('heading', { name: 'Threat-Intel Correlation' }).parentElement!
    expect(within(intel).getByText('203.0.113.66 is on your watchlist as malicious')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Device Risk' }).parentElement!).toHaveTextContent('Nothing notable.')
    expect(screen.getByText('alerts.get')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Run again/ })).toBeInTheDocument()
  })

  it('maps scores to the backend levels and never crashes on unknown levels', () => {
    expect([0, 10, 25, 50, 75].map(levelForScore)).toEqual(['info', 'low', 'medium', 'high', 'critical'])
    expect(levelStyle('apocalyptic').label).toBe('Info')
  })
})
