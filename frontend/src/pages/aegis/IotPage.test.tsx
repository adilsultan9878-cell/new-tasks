import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { Hub, Sensor } from '@/lib/types'
import { membership, mockApi, renderInOrg } from '@/test/utils'

import { IotPage } from './IotPage'
import { VisionPage } from './VisionPage'

const now = new Date().toISOString()
const sensor: Sensor = {
  id: 's1', device_id: 'd1', device_name: 'Simulated sensor hub', sensor_key: 'server_room_gas', name: 'Server Room Gas', sensor_type: 'gas',
  unit: 'ppm', status: 'online', thresholds: { max: 300, severity: 'critical' }, actuator_rules: ['buzzer', 'led'], in_breach: true,
  last_value: 412, last_reading_at: now, is_simulated: true,
}
const hub: Hub = {
  device_id: 'd1', name: 'Simulated sensor hub', status: 'online', is_simulated: true, sensor_count: 1,
  actuators: { led: { on: true, source: 'rule', because: ['Server Room Gas'] }, buzzer: { on: false, source: 'idle', because: [] } },
}

describe('IotPage', () => {
  it('shows live values, out-of-range state, outputs and the simulated label', async () => {
    mockApi({ '/sensors/s1/readings': [{ t: now, v: 120 }, { t: now, v: 412 }], '/sensors': [sensor], '/hubs': [hub] })
    renderInOrg(<IotPage />)
    expect(await screen.findByText('Server Room Gas')).toBeInTheDocument()
    expect(screen.getByText('412')).toBeInTheDocument()
    expect(screen.getByText('Out of range')).toBeInTheDocument()
    expect(screen.getByText(/1 sensor out of range/)).toBeInTheDocument()
    expect(screen.getAllByText('Simulated').length).toBeGreaterThan(0)
    expect(await screen.findByText(/LED on/)).toHaveTextContent('by Server Room Gas')
    expect(screen.getByRole('button', { name: /Run simulator again/ })).toBeInTheDocument()
  })

  it('offers the simulator and the ESP32 guide when there are no sensors, and hides controls from viewers', async () => {
    mockApi({ '/sensors': [], '/hubs': [] })
    renderInOrg(<IotPage />, { m: membership('viewer', ['devices:read']) })
    expect(await screen.findByText('No sensors yet')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Try the simulator/ })).not.toBeInTheDocument()
  })
})

describe('VisionPage', () => {
  it('lists cameras with their privacy state and zones', async () => {
    mockApi({
      '/cameras': [{ id: 'c1', device_id: 'd1', device_name: 'Simulated sensor hub', camera_key: 'lobby_camera', name: 'Simulated lobby camera', status: 'online',
        detection_enabled: true, privacy_mode: true, blur_people: true, retention_days: 7, zones: [{ name: 'Server room door', x: 0.6, y: 0.2, w: 0.3, h: 0.6 }],
        last_frame_at: now, last_event_at: now, snapshot_count: 0, is_simulated: true }],
      '/events?': { items: [], total: 0, limit: 8, offset: 0 },
    })
    renderInOrg(<VisionPage />)
    expect(await screen.findByText('Simulated lobby camera')).toBeInTheDocument()
    expect(screen.getByText('Detection on')).toBeInTheDocument()
    expect(screen.getByText('Snapshots off')).toBeInTheDocument()
    expect(screen.getByLabelText('1 restricted zones')).toHaveTextContent('Server room door')
    expect(screen.getByText('No identity')).toBeInTheDocument()
  })
})
