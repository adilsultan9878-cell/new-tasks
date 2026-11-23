import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { SecurityEvent } from '@/lib/types'
import { mockApi, renderInOrg } from '@/test/utils'

import { EventsPage } from './EventsPage'

const event: SecurityEvent = {
  id: 'e1', device_id: 'd1', device_name: 'fin-01', source: 'agent', category: 'network',
  event_type: 'network.new_listening_port', severity: 'high', status: 'new',
  title: 'New listening port 4444 (commonly used by backdoors)', occurred_at: new Date().toISOString(),
  ingested_at: new Date().toISOString(), occurrence_count: 3, last_occurred_at: null, is_simulated: false,
}

describe('EventsPage', () => {
  it('shows events, folded duplicates and open alerts, and opens the detail view', async () => {
    mockApi({
      '/events?': { items: [event], total: 1, limit: 50, offset: 0 },
      '/alerts': [{ id: 'a1', event_id: 'e1', title: 'Backdoor port opened', description: null, severity: 'high',
        status: 'open', risk_score: 75, detection_rule: 'severity-threshold', created_at: new Date().toISOString(),
        triage: { run_id: 'r9', risk_score: 58, risk_level: 'high', priority: 'P2', created_at: new Date().toISOString() } }],
      '/events/e1': { ...event, description: null, raw: { port: 4444 }, normalized: { event: { kind: 'alert' } },
        alerts: [{ id: 'a1', event_id: 'e1', title: 'Backdoor port opened', description: 'High network event.',
          severity: 'high', status: 'open', risk_score: 75, detection_rule: 'severity-threshold', created_at: '' }] },
    })
    renderInOrg(<EventsPage />)
    expect(await screen.findByText(event.title)).toBeInTheDocument()
    expect(screen.getByText('×3')).toBeInTheDocument()
    expect(screen.getByText('Backdoor port opened')).toBeInTheDocument()
    // The Security Brain's automatic triage links to the full analysis.
    expect(screen.getByRole('link', { name: /P2/ })).toHaveAttribute('href', '/org/11111111-1111-1111-1111-111111111111/brain/runs/r9')

    await userEvent.click(screen.getByRole('row', { name: /Open event New listening port/ }))
    expect(await screen.findByText('Alerts raised by this event')).toBeInTheDocument()
    expect(screen.getByText(/"port": 4444/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Mark triaged' })).toBeInTheDocument()
  })
})
