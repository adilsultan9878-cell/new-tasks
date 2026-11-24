import { screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { IncidentDetail } from '@/lib/types'
import { mockApi, renderInOrg } from '@/test/utils'

import { IncidentView } from './IncidentPage'

const now = new Date().toISOString()
const incident: IncidentDetail = {
  id: 'i1', reference: 'INC-2026-0007', title: 'Phishing wave against finance', summary: 'Three users clicked.', severity: 'high', status: 'contained',
  assigned_to: null, assignee_name: null, opened_by: 'u1', opened_at: now, closed_at: null, updated_at: now, alert_count: 1, pending_actions: 0,
  timeline: [
    { at: now, kind: 'evidence', text: 'Evidence added: Phishing email (SHA-256 9f86d081884c…)', actor: 'Owner', actor_id: 'u1' },
    { at: now, kind: 'created', text: 'Incident opened (high)', actor: 'Owner', actor_id: 'u1' },
  ],
  alerts: [{ id: 'a1', event_id: 'e1', title: 'Malicious URL investigated', description: null, severity: 'high', status: 'acknowledged', risk_score: 75, detection_rule: 'severity-threshold', created_at: now,
    triage: { run_id: 'r1', risk_score: 58, risk_level: 'high', priority: 'P2', created_at: now } }],
  actions: [],
  evidence: [{ id: 'ev1', incident_id: 'i1', incident_reference: 'INC-2026-0007', evidence_type: 'file', title: 'Phishing email', description: null, filename: 'mail.eml',
    content_type: 'message/rfc822', sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', size_bytes: 2048, stored: true, collected_by: 'u1', collected_at: now,
    chain_of_custody: [{ at: now, action: 'collected', actor: 'Owner' }] }],
  reports: [],
}

describe('IncidentView', () => {
  it('shows the lifecycle, triaged alerts, hashed evidence and the timeline', async () => {
    mockApi({ '/members': [], '/response/status': { emergency_stop: { engaged: false }, pending_approvals: 0, approvers: 1, action_types: [] } })
    renderInOrg(<IncidentView incident={incident} />)
    expect(screen.getByRole('heading', { name: 'Phishing wave against finance' })).toBeInTheDocument()
    const steps = screen.getByRole('list', { name: 'Incident status' })
    expect(within(steps).getByRole('button', { name: 'Contained' })).toHaveAttribute('aria-current', 'step')
    expect(screen.getByRole('link', { name: /P2/ })).toHaveAttribute('href', '/org/11111111-1111-1111-1111-111111111111/brain/runs/r1')
    expect(screen.getByTitle('SHA-256')).toHaveTextContent('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
    expect(screen.getByRole('button', { name: 'Verify hash' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Chain of custody \(1\)/ })).toBeInTheDocument()
    expect(screen.getByText('Incident opened (high)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Generate report/ })).toBeInTheDocument()
  })
})
