import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { Twin } from '@/lib/types'
import { mockApi, renderInOrg } from '@/test/utils'

import { areaAt, clampToFloor, markerHeight, placements } from './layout'
import { TwinPage } from './TwinPage'

// WebGL is not available in jsdom: the 3D view reports it and the page falls back to the list.
vi.mock('./TwinScene', () => ({
  default: ({ onError }: { onError: (m: string) => void }) => {
    onError('3D view is not available in this browser (WebGL is disabled).')
    return null
  },
}))

const twin: Twin = {
  generated_at: new Date().toISOString(),
  floor: { width: 100, depth: 60 },
  areas: [{ id: 'a1', name: 'Server room', x: 4, y: 4, w: 30, h: 22, simulated: true }],
  devices: [
    { id: 'd1', name: 'sim-db-01', device_type: 'server', status: 'degraded', health_score: 54, risk_score: 67, ip_address: '10.20.0.11',
      segment: '10.20.0.0/24', is_simulated: true, position: { x: 12, y: 12, area: 'Server room' }, open_alerts: 2, max_alert_severity: 'critical',
      open_incidents: [{ id: 'i1', reference: 'INC-2026-0003', title: 'Ransomware', severity: 'critical', status: 'open' }], sensors: [], cameras: [] },
    { id: 'd2', name: 'ws-new', device_type: 'workstation', status: 'online', health_score: 95, risk_score: null, ip_address: null,
      segment: null, is_simulated: false, position: null, open_alerts: 0, max_alert_severity: null, open_incidents: [], sensors: [], cameras: [] },
  ],
  segments: [],
  stats: { devices: 2, online: 1, degraded: 1, offline: 0, open_alerts: 2, open_incidents: 1, sensors_in_breach: 0, simulated: 1, placed: 1 },
}

describe('twin layout helpers', () => {
  it('keeps saved positions, lines up unplaced devices and maps points to rooms', () => {
    const p = placements(twin)
    expect(p.d1).toEqual({ x: 12, y: 12, auto: false })
    expect(p.d2?.auto).toBe(true)
    expect(p.d2?.y).toBe(56)
    expect(placements(twin, { d2: { x: 20, y: 10 } }).d2).toEqual({ x: 20, y: 10, auto: false })
    expect(areaAt(twin, 10, 10)).toBe('Server room')
    expect(areaAt(twin, 80, 50)).toBeNull()
    expect(clampToFloor(twin, 120.04, -3)).toEqual({ x: 100, y: 0 })
    expect(markerHeight({ risk_score: 100 })).toBe(7.5)
  })
})

describe('TwinPage', () => {
  it('falls back to the room list without WebGL and opens device details', async () => {
    mockApi({ '/twin': twin })
    renderInOrg(<TwinPage />)
    expect(await screen.findByText(/WebGL is disabled/)).toBeInTheDocument()
    const room = screen.getByRole('region', { name: 'Server room' })
    expect(within(room).getByText('sim-db-01')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Not placed' })).toHaveTextContent('ws-new')
    expect(screen.getByText('1 of 2 placed')).toBeInTheDocument()

    await userEvent.click(within(room).getByRole('button', { name: /sim-db-01/ }))
    expect(screen.getByRole('link', { name: /INC-2026-0003 Ransomware/ })).toHaveAttribute('href', '/org/11111111-1111-1111-1111-111111111111/incidents/i1')
    expect(screen.getByText('In Server room')).toBeInTheDocument()
  })
})
