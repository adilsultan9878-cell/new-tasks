import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { Incident, ResponseAction } from '@/lib/types'
import { membership, mockApi, renderInOrg } from '@/test/utils'

import { IncidentsPage } from './IncidentsPage'
import { ActionRow } from './shared'

const incident: Incident = {
  id: 'i1', reference: 'INC-2026-0001', title: 'Ransomware on the file share', summary: null, severity: 'critical', status: 'investigating',
  assigned_to: 'u2', assignee_name: 'Sara Analyst', opened_by: 'u1', opened_at: new Date().toISOString(), closed_at: null,
  updated_at: new Date().toISOString(), alert_count: 2, pending_actions: 1,
}

const action: ResponseAction = {
  id: 'a1', incident_id: 'i1', incident_reference: 'INC-2026-0001', proposed_by_run_id: null, action_type: 'revoke_device',
  title: 'Revoke device ws-07', reason: 'Beaconing to C2', impact: 'high', reversible: false, requires_approval: true,
  status: 'pending_approval', target: { device_id: 'd1' }, result: {}, requested_by: 'u2', requested_by_name: 'Sara Analyst',
  executed_at: null, rolled_back_at: null, created_at: new Date().toISOString(),
  approval: { id: 'p1', status: 'pending', requested_by: 'u2', decided_by: null, decided_by_name: null, decided_at: null, comment: null, expires_at: new Date(Date.now() + 3_600_000).toISOString() },
}

const status = {
  emergency_stop: { engaged: true, reason: 'drill', at: new Date().toISOString(), actor: 'Owner' },
  pending_approvals: 1, approvers: 2, action_types: [],
}

describe('IncidentsPage', () => {
  it('lists incidents, the approval queue and an engaged emergency stop', async () => {
    mockApi({
      '/incidents?': { items: [incident], total: 1, limit: 100, offset: 0 },
      '/actions?status=pending_approval': { items: [action], total: 1, limit: 20, offset: 0 },
      '/actions?limit=8': { items: [action], total: 1, limit: 8, offset: 0 },
      '/response/status': status,
    })
    renderInOrg(<IncidentsPage />)
    expect(await screen.findByRole('link', { name: /Ransomware on the file share/ })).toHaveAttribute('href', '/org/11111111-1111-1111-1111-111111111111/incidents/i1')
    expect(screen.getByText(/1 action pending/)).toBeInTheDocument()
    expect(await screen.findByText(/Waiting for approval \(1\)/)).toBeInTheDocument()
    expect(await screen.findByRole('alert')).toHaveTextContent('Emergency stop engaged')
    expect(screen.getByRole('button', { name: /Release emergency stop/ })).toBeInTheDocument()
  })
})

describe('ActionRow', () => {
  it('lets an approver decide and hides decisions from proposers', () => {
    const { unmount } = renderInOrg(<ul><ActionRow action={action} /></ul>, { m: membership('owner', ['responses:propose', 'responses:approve']) })
    expect(screen.getByRole('button', { name: 'Approve' })).toBeInTheDocument()
    expect(screen.getByText('Not reversible once it runs.')).toBeInTheDocument()
    unmount()
    renderInOrg(<ul><ActionRow action={action} /></ul>, { m: membership('owner', ['responses:propose']) })
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
  })

  it('offers rollback only for reversible actions that ran', () => {
    renderInOrg(<ul><ActionRow action={{ ...action, action_type: 'block_indicator', impact: 'medium', reversible: true, status: 'succeeded', approval: null }} /></ul>,
      { m: membership('owner', ['responses:propose', 'responses:approve']) })
    expect(screen.getByRole('button', { name: 'Roll back' })).toBeInTheDocument()
    expect(screen.getByText('Done')).toBeInTheDocument()
  })
})
