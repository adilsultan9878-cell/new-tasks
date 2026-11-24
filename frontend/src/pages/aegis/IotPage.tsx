import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BellRing, Cpu, DoorOpen, Droplets, Flame, Lightbulb, Pencil, Thermometer, Wind } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { SpotlightCard } from '@/components/magic/SpotlightCard'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton, StatusDot } from '@/components/ui/Feedback'
import { Field, Input, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime } from '@/lib/format'
import type { Hub, ReadingPoint, Sensor } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { SimulatedBadge, SimulatorControls, Sparkline } from './shared'

const ICON: Record<string, typeof Thermometer> = { temperature: Thermometer, humidity: Droplets, gas: Flame, smoke: Wind, door: DoorOpen }

function display(sensor: Sensor): string {
  if (sensor.last_value === null) return '—'
  if (sensor.sensor_type === 'door') return sensor.last_value >= 0.5 ? 'Open' : 'Closed'
  return `${Number.isInteger(sensor.last_value) ? sensor.last_value : sensor.last_value.toFixed(1)}`
}

export function IotPage() {
  const { orgId } = useOrg()
  const sensors = useQuery({ queryKey: qk.sensors(orgId), queryFn: () => api<Sensor[]>(`/organizations/${orgId}/sensors`), refetchInterval: 30_000 })
  const hubs = useQuery({ queryKey: qk.hubs(orgId), queryFn: () => api<Hub[]>(`/organizations/${orgId}/hubs`), refetchInterval: 30_000 })
  const [editing, setEditing] = useState<Sensor | null>(null)
  const [guide, setGuide] = useState(false)
  const hasSimulated = !!sensors.data?.some((s) => s.is_simulated)
  const alerting = sensors.data?.filter((s) => s.in_breach).length ?? 0

  return (
    <div>
      <PageHeader eyebrow="AEGIS ONE · Protect" title="IoT Security"
        description="Sensors on ESP32 and Arduino boards report here. When a reading leaves its safe range you get an alert, and the board's LED or buzzer can switch on by itself."
        actions={<>
          <Button variant="ghost" icon={<Cpu className="size-4" />} onClick={() => setGuide(true)}>Connect a board</Button>
          <SimulatorControls hasSimulated={hasSimulated} />
        </>}
      />

      {sensors.isPending ? <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-44" />)}</div>
        : sensors.isError ? <ErrorNotice error={sensors.error} />
        : sensors.data.length === 0 ? (
          <Panel>
            <EmptyState icon={Cpu} title="No sensors yet"
              action={<div className="flex flex-wrap justify-center gap-2"><Button onClick={() => setGuide(true)}>Connect an ESP32</Button><SimulatorControls hasSimulated={false} /></div>}>
              Connect a board, or try the simulator to see how alerts and the buzzer work — simulated data is clearly labelled and never counted in your metrics.
            </EmptyState>
          </Panel>
        ) : (
          <>
            <div className="mb-5 flex flex-wrap items-center gap-3 text-sm">
              <span className={cn('flex items-center gap-2 rounded-full border px-3 py-1', alerting ? 'border-critical/40 bg-critical/10 text-[#ff8f93]' : 'border-ok/30 bg-ok/10 text-ok')}>
                <StatusDot tone={alerting ? 'critical' : 'ok'} pulse={alerting > 0} />
                {alerting ? `${alerting} sensor${alerting === 1 ? '' : 's'} out of range` : 'All sensors within range'}
              </span>
              <span className="text-fg-subtle">{sensors.data.length} sensors · {hubs.data?.length ?? 0} board{hubs.data?.length === 1 ? '' : 's'}</span>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {sensors.data.map((s) => <SensorCard key={s.id} sensor={s} onEdit={() => setEditing(s)} />)}
            </div>
            {!!hubs.data?.length && (
              <Panel className="mt-5" title="Boards and outputs" description="LED and buzzer follow the sensor rules; a manual switch wins for the time you choose">
                <ul className="space-y-3">{hubs.data.map((h) => <HubRow key={h.device_id} hub={h} />)}</ul>
              </Panel>
            )}
          </>
        )}

      {editing && <SensorDialog sensor={editing} onClose={() => setEditing(null)} />}
      {guide && <ConnectGuide onClose={() => setGuide(false)} />}
    </div>
  )
}

function SensorCard({ sensor: s, onEdit }: { sensor: Sensor; onEdit: () => void }) {
  const { orgId, can } = useOrg()
  const readings = useQuery({
    queryKey: qk.sensorReadings(orgId, s.id, 2),
    queryFn: () => api<ReadingPoint[]>(`/organizations/${orgId}/sensors/${s.id}/readings`, { query: { hours: 2 } }),
  })
  const Icon = ICON[s.sensor_type] ?? Cpu
  return (
    <SpotlightCard className={cn('p-5', s.in_breach && 'border-critical/40')}>
      <div className="flex items-start gap-3">
        <span className={cn('grid size-10 shrink-0 place-items-center rounded-xl border', s.in_breach ? 'border-critical/40 bg-critical/10 text-critical' : 'border-line-strong bg-ink-850 text-accent')}>
          <Icon className="size-5" aria-hidden />
        </span>
        <div className="min-w-0 flex-1">
          <p className="truncate font-medium text-fg">{s.name}</p>
          <p className="truncate text-xs text-fg-subtle">{s.device_name} · {s.last_reading_at ? relativeTime(s.last_reading_at) : 'no reading yet'}</p>
        </div>
        {s.is_simulated && <SimulatedBadge />}
      </div>
      <div className="mt-4 flex items-end justify-between gap-3">
        <p className={cn('tabular text-4xl font-semibold tracking-tight', s.in_breach ? 'text-[#ff8f93]' : 'text-fg')}>
          {display(s)}<span className="ml-1 text-base font-normal text-fg-subtle">{s.sensor_type === 'door' ? '' : s.unit}</span>
        </p>
        <Badge tone={s.in_breach ? 'critical' : 'ok'}>{s.in_breach ? 'Out of range' : 'Normal'}</Badge>
      </div>
      <div className="mt-3"><Sparkline points={readings.data ?? []} max={s.thresholds.max} min={s.thresholds.min} alert={s.in_breach} /></div>
      <div className="mt-3 flex items-center justify-between gap-2 text-xs text-fg-subtle">
        <span>
          {s.sensor_type === 'door' && s.thresholds.max !== undefined
            ? 'Alert when open'
            : s.thresholds.max !== undefined || s.thresholds.min !== undefined
              ? `Safe: ${s.thresholds.min ?? '−∞'} – ${s.thresholds.max ?? '∞'} ${s.unit ?? ''}`
              : 'No limits set'}
          {s.actuator_rules.length > 0 && ` · switches ${s.actuator_rules.join(' + ')}`}
        </span>
        {can('devices:manage') && <button onClick={onEdit} className="inline-flex items-center gap-1 text-accent hover:underline"><Pencil className="size-3" /> Edit</button>}
      </div>
    </SpotlightCard>
  )
}

function OutputPill({ name, state }: { name: 'led' | 'buzzer'; state: Hub['actuators']['led'] }) {
  const Icon = name === 'led' ? Lightbulb : BellRing
  return (
    <span className={cn('inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs',
      state.on ? (name === 'buzzer' ? 'border-critical/40 bg-critical/10 text-[#ff8f93] shadow-[0_0_18px_-4px_var(--color-critical)]' : 'border-medium/40 bg-medium/10 text-medium shadow-[0_0_18px_-4px_var(--color-medium)]') : 'border-line text-fg-subtle')}>
      <Icon className="size-3.5" aria-hidden />
      {name === 'led' ? 'LED' : 'Buzzer'} {state.on ? 'on' : 'off'}
      <span className="text-fg-subtle">· {state.source === 'manual' ? `manual until ${new Date(state.until ?? '').toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : state.source === 'rule' ? `by ${state.because?.join(', ')}` : 'auto'}</span>
    </span>
  )
}

function HubRow({ hub }: { hub: Hub }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const set = useMutation({
    mutationFn: (body: { actuator: string; state: string; minutes?: number }) => api<Hub>(`/organizations/${orgId}/devices/${hub.device_id}/actuators`, { method: 'POST', body }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['hubs', orgId] }),
  })
  return (
    <li className="rounded-xl border border-line bg-ink-900/50 p-3.5">
      <div className="flex flex-wrap items-center gap-2">
        <StatusDot tone={hub.status === 'online' ? 'ok' : hub.status === 'offline' ? 'critical' : 'idle'} />
        <span className="font-medium text-fg">{hub.name}</span>
        <span className="text-xs text-fg-subtle">{hub.sensor_count} sensor{hub.sensor_count === 1 ? '' : 's'}</span>
        {hub.is_simulated && <SimulatedBadge />}
        <span className="ml-auto flex flex-wrap gap-2">
          <OutputPill name="led" state={hub.actuators.led} />
          <OutputPill name="buzzer" state={hub.actuators.buzzer} />
        </span>
      </div>
      {can('devices:manage') && (
        <div className="mt-3 flex flex-wrap gap-2">
          {(['led', 'buzzer'] as const).map((a) => (
            <span key={a} className="inline-flex items-center gap-1 rounded-lg border border-line p-0.5">
              <span className="px-2 text-xs text-fg-muted">{a === 'led' ? 'LED' : 'Buzzer'}</span>
              <Button size="sm" variant="ghost" disabled={set.isPending} onClick={() => set.mutate({ actuator: a, state: 'on', minutes: 15 })}>On 15 min</Button>
              <Button size="sm" variant="ghost" disabled={set.isPending} onClick={() => set.mutate({ actuator: a, state: 'off', minutes: 15 })}>Off 15 min</Button>
              <Button size="sm" variant="ghost" disabled={set.isPending} onClick={() => set.mutate({ actuator: a, state: 'auto' })}>Auto</Button>
            </span>
          ))}
        </div>
      )}
      {set.isError && <div className="mt-2"><ErrorNotice error={set.error} /></div>}
    </li>
  )
}

function SensorDialog({ sensor, onClose }: { sensor: Sensor; onClose: () => void }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [name, setName] = useState(sensor.name)
  const [min, setMin] = useState(sensor.thresholds.min?.toString() ?? '')
  const [max, setMax] = useState(sensor.thresholds.max?.toString() ?? '')
  const [severity, setSeverity] = useState(sensor.thresholds.severity ?? 'high')
  const [rules, setRules] = useState<Set<string>>(new Set(sensor.actuator_rules))
  const save = useMutation({
    mutationFn: () => api<Sensor>(`/organizations/${orgId}/sensors/${sensor.id}`, {
      method: 'PATCH',
      body: { name: name.trim(), thresholds: { min: min === '' ? undefined : Number(min), max: max === '' ? undefined : Number(max), severity }, actuator_rules: [...rules] },
    }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['sensors', orgId] }); void queryClient.invalidateQueries({ queryKey: ['hubs', orgId] }); onClose() },
  })
  const toggle = (k: string) => setRules((r) => { const n = new Set(r); if (n.has(k)) n.delete(k); else n.add(k); return n })
  return (
    <Dialog open onClose={onClose} title={`Edit ${sensor.name}`} description="Readings outside the safe range raise an event with this severity; high and critical become alerts.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); save.mutate() }} className="space-y-4">
        <Field label="Name">{({ id }) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label={`Minimum${sensor.unit ? ` (${sensor.unit})` : ''}`}>{({ id }) => <Input id={id} type="number" step="any" value={min} onChange={(e) => setMin(e.target.value)} />}</Field>
          <Field label={`Maximum${sensor.unit ? ` (${sensor.unit})` : ''}`}>{({ id }) => <Input id={id} type="number" step="any" value={max} onChange={(e) => setMax(e.target.value)} />}</Field>
          <Field label="Severity">
            {({ id }) => (
              <Select id={id} value={severity} onChange={(e) => setSeverity(e.target.value)}>
                {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
              </Select>
            )}
          </Field>
        </div>
        <fieldset>
          <legend className="mb-1.5 text-[13px] font-medium text-fg-muted">When out of range, switch on</legend>
          <div className="flex gap-2">
            {(['led', 'buzzer'] as const).map((k) => (
              <label key={k} className={cn('flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm', rules.has(k) ? 'border-accent/50 bg-accent-soft text-fg' : 'border-line text-fg-muted')}>
                <input type="checkbox" checked={rules.has(k)} onChange={() => toggle(k)} className="accent-[var(--color-accent)]" />
                {k === 'led' ? 'LED' : 'Buzzer'}
              </label>
            ))}
          </div>
        </fieldset>
        {save.isError && <ErrorNotice error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>Save</Button>
        </div>
      </form>
    </Dialog>
  )
}

function ConnectGuide({ onClose }: { onClose: () => void }) {
  const steps = [
    ['Create an enrollment token', 'Devices → Enrollment tokens → choose “sensor hub”. Copy the token (shown once).'],
    ['Flash MicroPython', 'Install MicroPython on the ESP32 and copy firmware/micropython/main.py and config.py from the project.'],
    ['Fill in config.py', 'Wi-Fi name and password, the server URL, the token and which pins your sensors, LED and buzzer use.'],
    ['Power it on', 'The board enrolls once, then reports every 30 s. Its sensors appear here; set their safe ranges.'],
  ]
  return (
    <Dialog open onClose={onClose} size="lg" title="Connect an ESP32 board" description="Prefer MQTT? Boards can publish to a local broker and the agent's mqtt-bridge forwards them.">
      <ol className="space-y-3">
        {steps.map(([title, text], i) => (
          <li key={title} className="flex gap-3">
            <span className="brand-gradient grid size-7 shrink-0 place-items-center rounded-full text-xs font-semibold text-white">{i + 1}</span>
            <div><p className="font-medium text-fg">{title}</p><p className="text-sm text-fg-muted">{text}</p></div>
          </li>
        ))}
      </ol>
      <p className="mt-4 rounded-lg border border-line bg-ink-900/60 px-3 py-2 text-xs text-fg-muted">
        The board only ever receives the on/off state of its LED and buzzer — never a command.
      </p>
    </Dialog>
  )
}
