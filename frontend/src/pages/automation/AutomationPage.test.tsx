import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { AutomationCatalog, AutomationOverview, AutomationRun, Workflow } from '@/lib/types'
import { membership, mockApi, renderInOrg } from '@/test/utils'

import { AutomationPage } from './AutomationPage'

const MANAGER = ['automation:read', 'integrations:manage', 'responses:approve', 'incidents:read']

const overview: AutomationOverview = {
  workflows: 1, enabled: 1, webhooks: 0, awaiting_approval: 1, runs_today: 2, failed_today: 0,
  deliveries_pending: 0, deliveries_failed: 0, signing_key: 'dedicated', delivery_enabled: true,
  private_targets_allowed: false, emergency_stop: false,
}

const catalog: AutomationCatalog = {
  trigger_types: [
    { key: 'event', title: 'When something happens' },
    { key: 'schedule', title: 'On a schedule' },
    { key: 'manual', title: 'When I press Run' },
    { key: 'webhook', title: 'When another tool calls (signed webhook)' },
  ],
  events: [{ key: 'alert.created', title: 'A new alert is raised', description: '', filters: ['min_severity', 'include_simulated'], fields: ['alert.title'] }],
  schedules: [{ every_minutes: 1440, title: 'Every day' }],
  steps: [
    { key: 'notify', title: 'Send an in-app notification', description: '', risk: 'low', permission: null, triggers: [], events: [] },
    { key: 'create_incident', title: 'Open an incident', description: '', risk: 'medium', permission: 'incidents:manage', triggers: ['event', 'webhook'], events: ['alert.created'] },
  ],
  indicator_types: ['ipv4'],
  audiences: ['responders', 'approvers'],
  recipes: [],
  signature: { header: 'X-Sentinel-Signature', timestamp_header: 'X-Sentinel-Timestamp', algorithm: '', tolerance_seconds: 300 },
}

const workflow: Workflow = {
  id: 'w1', name: 'Incident for critical alerts', description: null, trigger_type: 'event',
  trigger_config: { event: 'alert.created', min_severity: 'critical' }, trigger_label: 'A new alert is raised (critical or above)',
  steps: [{ type: 'create_incident', title: 'Open an incident', risk: 'medium', params: { title: '{{alert.title}}' } }],
  requires_approval: true, approval_forced: true, enabled: true, hook_path: null, next_run_at: null,
  last_run_at: null, last_status: null, owner_name: 'Sara', created_at: '2026-11-25T10:00:00Z', updated_at: '2026-11-25T10:00:00Z',
}

const run = (over: Partial<AutomationRun>): AutomationRun => ({
  id: 'r1', workflow_id: 'w1', workflow_name: 'Incident for critical alerts', status: 'awaiting_approval', trigger_kind: 'event',
  trigger_label: 'Critical alert: Domain admin created', steps: [{ type: 'create_incident', title: 'Open an incident', risk: 'medium', status: 'waiting', detail: null, link: null }],
  context: {}, requested_by_name: null, decided_by_name: null, decided_at: null, decision_comment: null,
  expires_at: new Date(Date.now() + 3_600_000).toISOString(), error: null, is_simulated: false,
  created_at: new Date().toISOString(), finished_at: null, ...over,
})

function routes(extra: Record<string, unknown> = {}) {
  return mockApi({
    '/automation/overview': overview,
    '/automation/catalog': catalog,
    '/automation/workflows': [workflow],
    '/automation/runs': { items: [run({}), run({ id: 'r0', status: 'succeeded', steps: [{ type: 'notify', title: 'Notify responders', risk: 'low', status: 'succeeded', detail: 'Notified 2 member(s)', link: null }] })], total: 2 },
    '/automation/webhooks': [],
    '/automation/deliveries': { items: [], total: 0 },
    ...extra,
  })
}

describe('AutomationPage', () => {
  it('shows each workflow as a readable sentence with its safety level', async () => {
    routes()
    renderInOrg(<AutomationPage />, { m: membership('owner', MANAGER) })
    const card = await screen.findByRole('article', { name: 'Incident for critical alerts' })
    expect(within(card).getByText('A new alert is raised (critical or above)')).toBeInTheDocument()
    expect(within(card).getByText('Open an incident')).toBeInTheDocument()
    expect(within(card).getByText('Needs approval')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /1 waiting for approval/ })).toBeInTheDocument()
  })

  it('lets an approver approve a waiting run', async () => {
    const fetch = routes({ 'POST /runs/r1/decision': run({ status: 'succeeded' }) })
    renderInOrg(<AutomationPage />, { m: membership('owner', MANAGER) })
    await userEvent.click(await screen.findByRole('tab', { name: /Activity/ }))
    expect(screen.getByText('Waiting for approval (1)')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Approve and run' }))
    const call = fetch.mock.calls.find(([url, init]) => String(url).includes('/runs/r1/decision') && init?.method === 'POST')
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ approve: true })
    await userEvent.click(screen.getByRole('button', { name: /1\/1 steps/ }))
    expect(screen.getByText('Notified 2 member(s)')).toBeInTheDocument()
  })

  it('only offers steps that fit the trigger and forces approval for incidents', async () => {
    routes()
    renderInOrg(<AutomationPage />, { m: membership('owner', MANAGER) })
    await userEvent.click(await screen.findByRole('button', { name: 'New workflow' }))
    const dialog = screen.getByRole('dialog', { name: 'New workflow' })
    expect(within(dialog).getByRole('button', { name: 'Open an incident' })).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Open an incident' }))
    expect(within(dialog).getByRole('switch', { name: 'Ask an approver before each run' })).toBeDisabled()
    expect(within(dialog).getByText('Required: this workflow opens incidents.')).toBeInTheDocument()

    await userEvent.click(within(dialog).getByRole('radio', { name: /When I press Run/ }))
    expect(within(dialog).queryByRole('button', { name: 'Open an incident' })).not.toBeInTheDocument()
    expect(within(dialog).getByText('Not available with this trigger — remove it.')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Create workflow' })).toBeDisabled()
  })

  it('is read-only for members without integrations:manage', async () => {
    routes()
    renderInOrg(<AutomationPage />, { m: membership('viewer', ['automation:read']) })
    await screen.findByRole('article', { name: 'Incident for critical alerts' })
    expect(screen.queryByRole('button', { name: 'New workflow' })).not.toBeInTheDocument()
    expect(screen.queryByRole('switch')).not.toBeInTheDocument()
  })
})
