import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { Device } from '@/lib/types'
import { membership, mockApi, renderInOrg } from '@/test/utils'

import { DevicesPage } from './DevicesPage'

const device: Device = {
  id: 'd1', name: 'Finance laptop', device_type: 'workstation', hostname: 'fin-01', os: 'Windows 11',
  ip_address: '10.0.0.5', mac_address: null, status: 'online', enrollment_status: 'enrolled', health_score: 92, risk_score: null,
  agent_version: '0.2.0', enrolled_at: '2026-11-20T10:00:00Z', last_seen_at: new Date().toISOString(),
  is_simulated: false, created_at: '2026-11-20T10:00:00Z',
}

describe('DevicesPage', () => {
  it('lists real devices with live status', async () => {
    mockApi({ '/devices': [device], '/enrollment-tokens': [] })
    renderInOrg(<DevicesPage />)
    const row = await screen.findByRole('row', { name: /Open Finance laptop/ })
    expect(within(row).getByText('Online')).toBeInTheDocument()
    expect(within(row).getByText('92')).toBeInTheDocument()
    expect(within(row).getByText('10.0.0.5')).toBeInTheDocument()
  })

  it('creates an enrollment token and shows it once with install commands', async () => {
    const token = 'sxe.' + 'a'.repeat(32) + '.' + 'b'.repeat(32) + '.secret-value-123456789'
    mockApi({
      '/devices': [],
      '/enrollment-tokens': [],
      'POST /enrollment-tokens': (body: unknown) => ({
        id: 't1', label: (body as { label: string }).label, device_type: 'workstation', max_uses: 1, use_count: 0,
        expires_at: new Date(Date.now() + 86400e3).toISOString(), revoked_at: null, last_used_at: null,
        created_at: new Date().toISOString(), state: 'active', token,
      }),
    })
    renderInOrg(<DevicesPage />)
    await userEvent.click(await screen.findByRole('button', { name: 'Enroll your first device' }))
    await userEvent.type(screen.getByLabelText('Label'), 'Finance laptops')
    await userEvent.click(screen.getByRole('button', { name: 'Create token' }))
    expect(await screen.findByText('Install the agent')).toBeInTheDocument()
    expect(screen.getAllByText(token, { exact: false }).length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/sentinel-agent enroll --server http:\/\/localhost(:\d+)? --token sxe\./)).toBeInTheDocument()
  })

  it('hides enrollment for read-only roles', async () => {
    mockApi({ '/devices': [device] })
    renderInOrg(<DevicesPage />, { m: membership('viewer', ['devices:read']) })
    await screen.findByRole('row', { name: /Open Finance laptop/ })
    expect(screen.queryByRole('button', { name: /Enroll/ })).not.toBeInTheDocument()
  })
})
