import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Box, Boxes, List, Move3d, Plus, Save, Trash2, X } from 'lucide-react'
import { lazy, Suspense, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton, StatusDot } from '@/components/ui/Feedback'
import { Input } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/StatusBadges'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import type { Twin, TwinArea, TwinDevice } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'
import { SimulatedBadge, SimulatorControls } from '@/pages/aegis/shared'
import { AnalyzeButton, levelForScore, RiskBadge } from '@/pages/brain/shared'

import { areaAt, clampToFloor, placements as computePlacements, STATUS_COLOR } from './layout'

const TwinScene = lazy(() => import('./TwinScene'))

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
}

export function TwinPage() {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const [view, setView] = useState<'3d' | 'list'>('3d')
  const [showSimulated, setShowSimulated] = useState(true)
  const [selected, setSelected] = useState<string | null>(null)
  const [editing, setEditing] = useState(false)
  const [moved, setMoved] = useState<Record<string, { x: number; y: number }>>({})
  const [draftAreas, setDraftAreas] = useState<TwinArea[] | null>(null)
  const [sceneError, setSceneError] = useState<string | null>(null)
  const twin = useQuery({
    queryKey: qk.twin(orgId, showSimulated),
    queryFn: () => api<Twin>(`/organizations/${orgId}/twin`, { query: { include_simulated: showSimulated } }),
    refetchInterval: 30_000,
  })
  const data = useMemo(() => (twin.data && draftAreas ? { ...twin.data, areas: draftAreas } : twin.data), [twin.data, draftAreas])
  const places = useMemo(() => (data ? computePlacements(data, moved) : {}), [data, moved])
  const save = useMutation({
    mutationFn: () => api<Twin>(`/organizations/${orgId}/twin/layout`, {
      method: 'PUT',
      body: {
        areas: draftAreas ?? undefined,
        positions: Object.entries(moved).map(([device_id, p]) => ({ device_id, ...p, area: data ? areaAt(data, p.x, p.y) : null })),
      },
    }),
    onSuccess: () => {
      setMoved({})
      setDraftAreas(null)
      setEditing(false)
      void queryClient.invalidateQueries({ queryKey: ['twin', orgId] })
    },
  })
  const cancelEdit = () => { setMoved({}); setDraftAreas(null); setEditing(false) }
  const device = data?.devices.find((d) => d.id === selected) ?? null
  const dirty = Object.keys(moved).length > 0 || draftAreas !== null
  const stats = data?.stats

  return (
    <div>
      <PageHeader eyebrow="AEGIS ONE · Protect" title="Digital Twin"
        description="A live 3D map of your site: every device with its health and risk, open alerts and incidents, sensors and cameras. Arrange it once and watch it change in real time."
        actions={<>
          <div className="flex gap-1 rounded-lg border border-line bg-ink-900/60 p-0.5" role="tablist" aria-label="View">
            {([['3d', '3D', Box], ['list', 'List', List]] as const).map(([key, text, Icon]) => (
              <button key={key} role="tab" aria-selected={view === key} onClick={() => setView(key)}
                className={cn('inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs', view === key ? 'bg-ink-750 text-fg' : 'text-fg-muted hover:text-fg')}>
                <Icon className="size-3.5" aria-hidden />{text}
              </button>
            ))}
          </div>
          {can('devices:manage') && !editing && <Button icon={<Move3d className="size-4" />} onClick={() => { setEditing(true); setView('3d') }}>Edit layout</Button>}
          <SimulatorControls hasSimulated={(twin.data?.stats.simulated ?? 0) > 0} />
        </>}
      />

      {twin.isError && <ErrorNotice error={twin.error} />}
      {stats && (
        <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
          <Chip tone="ok">{stats.online} online</Chip>
          <Chip tone={stats.degraded ? 'warn' : 'idle'}>{stats.degraded} degraded</Chip>
          <Chip tone={stats.offline ? 'critical' : 'idle'}>{stats.offline} offline</Chip>
          <Chip tone={stats.open_alerts ? 'critical' : 'idle'}>{stats.open_alerts} open alerts</Chip>
          <Chip tone={stats.open_incidents ? 'critical' : 'idle'}>{stats.open_incidents} incidents</Chip>
          <Chip tone={stats.sensors_in_breach ? 'warn' : 'idle'}>{stats.sensors_in_breach} sensors out of range</Chip>
          <span className="text-fg-subtle">{stats.placed} of {stats.devices} placed</span>
          <label className="ml-auto inline-flex cursor-pointer items-center gap-2 text-fg-muted">
            <input type="checkbox" checked={showSimulated} onChange={(e) => setShowSimulated(e.target.checked)} className="accent-[var(--color-accent)]" />
            Show simulated
          </label>
        </div>
      )}

      {editing && data && (
        <AreaEditor areas={draftAreas ?? data.areas} floor={data.floor} onChange={setDraftAreas}
          footer={<div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-fg-muted">Drag devices on the floor to place them.{Object.keys(moved).length ? ` ${Object.keys(moved).length} moved.` : ''}</span>
            <span className="ml-auto flex gap-2">
              <Button size="sm" variant="ghost" icon={<X className="size-3.5" />} onClick={cancelEdit}>Cancel</Button>
              <Button size="sm" variant="primary" icon={<Save className="size-3.5" />} disabled={!dirty} loading={save.isPending} onClick={() => save.mutate()}>Save layout</Button>
            </span>
            {save.isError && <div className="w-full"><ErrorNotice error={save.error} /></div>}
          </div>} />
      )}

      {!data ? <Skeleton className="h-[560px]" /> : data.devices.length === 0 && data.areas.length === 0 ? (
        <Panel>
          <EmptyState icon={Boxes} title="Nothing on the map yet" action={<SimulatorControls hasSimulated={false} />}>
            Enroll devices, or run the simulator to see a furnished, clearly labelled example site.
          </EmptyState>
        </Panel>
      ) : (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
          {view === '3d' && !sceneError ? (
            <section className="panel relative h-[560px] overflow-hidden" aria-label="3D site map">
              <Suspense fallback={<Skeleton className="h-full rounded-none" />}>
                <TwinScene twin={data} placements={places} selectedId={selected} editMode={editing} reducedMotion={prefersReducedMotion()}
                  onSelect={setSelected} onError={setSceneError}
                  onMove={(id, x, y) => setMoved((m) => ({ ...m, [id]: clampToFloor(data, x, y) }))} />
              </Suspense>
              <p className="pointer-events-none absolute bottom-3 left-4 text-[11px] text-fg-subtle">Drag to orbit · scroll to zoom · click a device</p>
            </section>
          ) : (
            <TwinList twin={data} onSelect={setSelected} selected={selected} note={sceneError} />
          )}
          <aside className="min-w-0 space-y-5">
            {device ? <DevicePanel device={device} auto={places[device.id]?.auto ?? true} onClose={() => setSelected(null)} /> : <Legend />}
          </aside>
        </div>
      )}
    </div>
  )
}

function Chip({ tone, children }: { tone: 'ok' | 'warn' | 'critical' | 'idle'; children: ReactNode }) {
  return <span className="inline-flex items-center gap-1.5 rounded-full border border-line px-2.5 py-1 text-fg-muted"><StatusDot tone={tone} />{children}</span>
}

function Legend() {
  return (
    <Panel title="How to read the map">
      <ul className="space-y-2.5 text-sm text-fg-muted">
        {Object.entries(STATUS_COLOR).slice(0, 3).map(([k, color]) => (
          <li key={k} className="flex items-center gap-2.5"><span className="size-3 rounded-full" style={{ background: color }} /> {k[0]!.toUpperCase() + k.slice(1)} device</li>
        ))}
        <li className="flex items-center gap-2.5"><span className="h-4 w-3 rounded-sm bg-gradient-to-t from-accent/30 to-accent" /> Taller = higher Security Brain risk</li>
        <li className="flex items-center gap-2.5"><span className="size-3 rounded-full border-2 border-critical" /> Pulsing ring = open alerts</li>
        <li className="flex items-center gap-2.5"><span className="h-4 w-1 rounded bg-critical" /> Red beacon = open incident</li>
        <li className="flex items-center gap-2.5"><span className="size-2.5 rounded-full bg-accent" /> Sensor (red when out of range) · <span className="text-[#a78bfa]">▲</span> camera</li>
        <li className="flex items-center gap-2.5"><span className="w-4 border-t-2 border-dashed border-violet" /> Same network segment</li>
      </ul>
      <p className="mt-3 text-xs text-fg-subtle">Everything shown comes from your own records. Simulated devices and rooms are labelled.</p>
    </Panel>
  )
}

function DevicePanel({ device: d, auto, onClose }: { device: TwinDevice; auto: boolean; onClose: () => void }) {
  const { orgId } = useOrg()
  return (
    <Panel title={d.name} description={`${d.device_type}${d.ip_address ? ` · ${d.ip_address}` : ''}${d.segment ? ` · ${d.segment}` : ''}`}
      actions={<button onClick={onClose} aria-label="Close details" className="rounded p-1 text-fg-subtle hover:text-fg"><X className="size-4" /></button>}>
      <div className="space-y-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={d.status === 'online' ? 'ok' : d.status === 'degraded' ? 'warn' : d.status === 'offline' ? 'critical' : 'neutral'}>{d.status}</Badge>
          {d.risk_score !== null && <RiskBadge level={levelForScore(d.risk_score)} score={d.risk_score} />}
          {d.health_score !== null && <Badge>health {d.health_score}</Badge>}
          {d.is_simulated && <SimulatedBadge />}
        </div>
        {auto && <p className="text-xs text-medium">Not placed yet — use Edit layout and drag it into its room.</p>}
        {!auto && d.position?.area && <p className="text-xs text-fg-subtle">In {d.position.area}</p>}
        <section>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-fg-muted">Alerts & incidents</h3>
          {d.open_alerts === 0 && d.open_incidents.length === 0 ? <p className="text-xs text-fg-subtle">None open.</p> : (
            <ul className="space-y-1.5">
              {d.open_alerts > 0 && <li className="flex items-center gap-2">{d.max_alert_severity && <SeverityBadge severity={d.max_alert_severity} />}<Link className="text-accent hover:underline" to={`/org/${orgId}/events`}>{d.open_alerts} open alert{d.open_alerts === 1 ? '' : 's'}</Link></li>}
              {d.open_incidents.map((i) => (
                <li key={i.id}><Link to={`/org/${orgId}/incidents/${i.id}`} className="text-accent hover:underline"><span className="font-mono text-xs">{i.reference}</span> {i.title}</Link></li>
              ))}
            </ul>
          )}
        </section>
        {d.sensors.length > 0 && (
          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-fg-muted">Sensors</h3>
            <ul className="space-y-1">
              {d.sensors.map((s) => (
                <li key={s.id} className="flex justify-between gap-2"><span className="text-fg-muted">{s.name}</span>
                  <span className={cn('tabular', s.in_breach ? 'text-[#ff8f93]' : 'text-fg')}>{s.last_value ?? '—'} {s.unit ?? ''}</span></li>
              ))}
            </ul>
          </section>
        )}
        {d.cameras.length > 0 && (
          <section>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-fg-muted">Cameras</h3>
            <ul className="space-y-1">{d.cameras.map((c) => <li key={c.id} className="flex justify-between"><span className="text-fg-muted">{c.name}</span><span className="text-xs text-fg-subtle">{c.detection_enabled ? `${c.zones} zones` : 'detection off'}</span></li>)}</ul>
          </section>
        )}
        {!d.is_simulated && <AnalyzeButton subjectType="device" subjectId={d.id} label="Analyze this device" />}
      </div>
    </Panel>
  )
}

function TwinList({ twin, onSelect, selected, note }: { twin: Twin; onSelect: (id: string) => void; selected: string | null; note: string | null }) {
  const groups = new Map<string, TwinDevice[]>()
  for (const d of twin.devices) {
    const key = d.position?.area ?? 'Not placed'
    groups.set(key, [...(groups.get(key) ?? []), d])
  }
  return (
    <Panel title="Site list" description={note ?? 'Every device by room'} flush>
      <div className="divide-y divide-line">
        {[...groups.entries()].map(([area, devices]) => (
          <section key={area} aria-label={area}>
            <h3 className="bg-ink-900/60 px-5 py-2 text-xs font-semibold uppercase tracking-wider text-fg-muted">{area}</h3>
            <ul className="divide-y divide-line">
              {devices.map((d) => (
                <li key={d.id}>
                  <button onClick={() => onSelect(d.id)} className={cn('flex w-full items-center gap-3 px-5 py-2.5 text-left text-sm hover:bg-ink-850/60', selected === d.id && 'bg-accent-soft')}>
                    <span className="size-2.5 rounded-full" style={{ background: STATUS_COLOR[d.status] ?? STATUS_COLOR.unknown }} aria-hidden />
                    <span className="min-w-0 flex-1 truncate text-fg">{d.name}</span>
                    {d.is_simulated && <SimulatedBadge />}
                    {d.open_alerts > 0 && <Badge tone="critical">{d.open_alerts} alert{d.open_alerts === 1 ? '' : 's'}</Badge>}
                    {d.open_incidents.length > 0 && <Badge tone="critical">{d.open_incidents.length} incident</Badge>}
                    {d.risk_score !== null && <RiskBadge level={levelForScore(d.risk_score)} score={d.risk_score} />}
                  </button>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </Panel>
  )
}

function AreaEditor({ areas, floor, onChange, footer }: { areas: TwinArea[]; floor: Twin['floor']; onChange: (a: TwinArea[]) => void; footer: ReactNode }) {
  const [form, setForm] = useState({ name: '', x: '5', y: '5', w: '20', h: '15' })
  const add = (e: FormEvent) => {
    e.preventDefault()
    const [x, y, w, h] = [form.x, form.y, form.w, form.h].map(Number) as [number, number, number, number]
    if (!form.name.trim() || w <= 0 || h <= 0 || x + w > floor.width || y + h > floor.depth) return
    onChange([...areas, { id: crypto.randomUUID(), name: form.name.trim(), x, y, w, h }])
    setForm((f) => ({ ...f, name: '' }))
  }
  const valid = (() => {
    const [x, y, w, h] = [form.x, form.y, form.w, form.h].map(Number) as [number, number, number, number]
    return !!form.name.trim() && w > 0 && h > 0 && x >= 0 && y >= 0 && x + w <= floor.width && y + h <= floor.depth
  })()
  return (
    <Panel className="mb-4 border-accent/30" title="Edit layout" description={`Rooms on a ${floor.width} × ${floor.depth} m floor (x from the left, y from the back)`}>
      <div className="space-y-3">
        <ul className="flex flex-wrap gap-2">
          {areas.map((a) => (
            <li key={a.id} className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs', a.simulated ? 'border-medium/40 text-medium' : 'border-accent/40 text-accent')}>
              {a.name} <span className="text-fg-subtle">{a.w}×{a.h} m</span>
              <button aria-label={`Remove ${a.name}`} onClick={() => onChange(areas.filter((x) => x.id !== a.id))} className="hover:text-fg"><Trash2 className="size-3" /></button>
            </li>
          ))}
          {areas.length === 0 && <li className="text-xs text-fg-subtle">No rooms yet.</li>}
        </ul>
        <form onSubmit={add} className="flex flex-wrap items-end gap-2">
          <Input aria-label="Room name" placeholder="Room name" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} className="h-8 w-40 text-xs" />
          {(['x', 'y', 'w', 'h'] as const).map((k) => (
            <label key={k} className="text-[11px] text-fg-subtle">{k === 'w' ? 'width' : k === 'h' ? 'depth' : k}
              <Input aria-label={`Room ${k}`} type="number" min={0} step="0.5" value={form[k]} onChange={(e) => setForm((f) => ({ ...f, [k]: e.target.value }))} className="mt-0.5 h-8 w-20 text-xs" />
            </label>
          ))}
          <Button type="submit" size="sm" icon={<Plus className="size-3.5" />} disabled={!valid}>Add room</Button>
        </form>
        {footer}
      </div>
    </Panel>
  )
}
