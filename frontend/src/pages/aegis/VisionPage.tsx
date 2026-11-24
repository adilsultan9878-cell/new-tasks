import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Cctv, EyeOff, ScanLine, ShieldCheck, Trash2, Video } from 'lucide-react'
import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { SpotlightCard } from '@/components/magic/SpotlightCard'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton, StatusDot } from '@/components/ui/Feedback'
import { Field, Input } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/StatusBadges'
import { api, fetchObjectUrl } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime } from '@/lib/format'
import type { Camera, Page, SecurityEvent, Snapshot, Zone } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { SimulatedBadge, SimulatorControls } from './shared'

const PRINCIPLES = [
  { icon: Video, title: 'Detections, not video', text: 'Video stays on your site. Only "motion", "person" or "person in zone" is sent.' },
  { icon: EyeOff, title: 'No identity', text: 'There is no face recognition — the detector sees a person shape, never who it is.' },
  { icon: ShieldCheck, title: 'Snapshots off by default', text: 'Stills are sent only if you allow them, with people blurred, and expire automatically.' },
]

export function VisionPage() {
  const { orgId, can } = useOrg()
  const cameras = useQuery({ queryKey: qk.cameras(orgId), queryFn: () => api<Camera[]>(`/organizations/${orgId}/cameras`), refetchInterval: 30_000 })
  const events = useQuery({
    queryKey: qk.events(orgId, { category: 'vision', limit: 8 }),
    queryFn: () => api<Page<SecurityEvent>>(`/organizations/${orgId}/events`, { query: { category: 'vision', limit: 8 } }),
    enabled: can('events:read'),
  })
  const [open, setOpen] = useState<Camera | null>(null)
  const [guide, setGuide] = useState(false)
  const hasSimulated = !!cameras.data?.some((c) => c.is_simulated)

  return (
    <div>
      <PageHeader eyebrow="AEGIS ONE · Protect" title="Computer Vision"
        description="Your cameras watch for motion, people and people inside restricted zones. Everything is analysed on your own computer."
        actions={<>
          <Button variant="ghost" icon={<Cctv className="size-4" />} onClick={() => setGuide(true)}>Connect a camera</Button>
          <SimulatorControls hasSimulated={hasSimulated} />
        </>}
      />

      <div className="mb-5 grid gap-3 md:grid-cols-3">
        {PRINCIPLES.map(({ icon: Icon, title, text }) => (
          <div key={title} className="flex gap-3 rounded-2xl border border-line bg-ink-900/50 p-4">
            <Icon className="mt-0.5 size-5 shrink-0 text-accent" aria-hidden />
            <div><p className="text-sm font-medium text-fg">{title}</p><p className="text-xs text-fg-muted">{text}</p></div>
          </div>
        ))}
      </div>

      {cameras.isPending ? <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{[0, 1].map((i) => <Skeleton key={i} className="h-48" />)}</div>
        : cameras.isError ? <ErrorNotice error={cameras.error} />
        : cameras.data.length === 0 ? (
          <Panel>
            <EmptyState icon={Cctv} title="No cameras yet"
              action={<div className="flex flex-wrap justify-center gap-2"><Button onClick={() => setGuide(true)}>Connect a camera</Button><SimulatorControls hasSimulated={false} /></div>}>
              Run the camera agent on a computer next to the camera, or try the simulator first.
            </EmptyState>
          </Panel>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {cameras.data.map((c) => <CameraCard key={c.id} camera={c} onOpen={() => setOpen(c)} />)}
          </div>
        )}

      {!!events.data?.items.length && (
        <Panel className="mt-5" title="Recent detections">
          <ul className="-my-1 divide-y divide-line">
            {events.data.items.map((e) => (
              <li key={e.id} className="flex items-center gap-2.5 py-2 text-sm">
                <SeverityBadge severity={e.severity} />
                <span className="min-w-0 flex-1 truncate text-fg">{e.title}</span>
                {e.is_simulated && <SimulatedBadge />}
                <span className="text-xs text-fg-subtle">{relativeTime(e.last_occurred_at ?? e.occurred_at)}{e.occurrence_count > 1 ? ` · ×${e.occurrence_count}` : ''}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {open && <CameraDialog camera={cameras.data?.find((c) => c.id === open.id) ?? open} onClose={() => setOpen(null)} />}
      {guide && <CameraGuide onClose={() => setGuide(false)} />}
    </div>
  )
}

function useUpdateCamera(camera: Camera) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Partial<Pick<Camera, 'name' | 'detection_enabled' | 'privacy_mode' | 'blur_people' | 'retention_days' | 'zones'>>) =>
      api<Camera>(`/organizations/${orgId}/cameras/${camera.id}`, { method: 'PATCH', body }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['cameras', orgId] }),
  })
}

function CameraCard({ camera: c, onOpen }: { camera: Camera; onOpen: () => void }) {
  const { can } = useOrg()
  const update = useUpdateCamera(c)
  return (
    <SpotlightCard className="p-5">
      <div className="flex items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-line-strong bg-ink-850 text-accent"><Cctv className="size-5" aria-hidden /></span>
        <div className="min-w-0 flex-1">
          <p className="truncate font-medium text-fg">{c.name}</p>
          <p className="flex items-center gap-1.5 truncate text-xs text-fg-subtle"><StatusDot tone={c.status === 'online' ? 'ok' : 'idle'} /> {c.device_name} · {c.last_frame_at ? `seen ${relativeTime(c.last_frame_at)}` : 'not seen yet'}</p>
        </div>
        {c.is_simulated && <SimulatedBadge />}
      </div>
      <ZonePreview zones={c.zones} className="mt-4" />
      <div className="mt-3 flex flex-wrap gap-1.5">
        <Badge tone={c.detection_enabled ? 'ok' : 'neutral'}>{c.detection_enabled ? 'Detection on' : 'Detection off'}</Badge>
        <Badge tone={c.privacy_mode ? 'info' : 'warn'}>{c.privacy_mode ? 'Snapshots off' : `Snapshots on · ${c.retention_days} d`}</Badge>
        {c.blur_people && <Badge>People blurred</Badge>}
        <Badge>{c.zones.length} zone{c.zones.length === 1 ? '' : 's'}</Badge>
      </div>
      <p className="mt-2 text-xs text-fg-subtle">{c.last_event_at ? `Last detection ${relativeTime(c.last_event_at)}` : 'No detections yet'}</p>
      {can('devices:manage') && (
        <div className="mt-3 flex gap-2">
          <Button size="sm" variant={c.detection_enabled ? 'secondary' : 'primary'} loading={update.isPending} onClick={() => update.mutate({ detection_enabled: !c.detection_enabled })}>
            {c.detection_enabled ? 'Turn detection off' : 'Turn detection on'}
          </Button>
          <Button size="sm" variant="ghost" icon={<ScanLine className="size-3.5" />} onClick={onOpen}>Zones & privacy</Button>
        </div>
      )}
      {update.isError && <div className="mt-2"><ErrorNotice error={update.error} /></div>}
    </SpotlightCard>
  )
}

function ZonePreview({ zones, className }: { zones: Zone[]; className?: string }) {
  return (
    <div className={cn('relative aspect-video overflow-hidden rounded-xl border border-line bg-ink-850', className)} aria-label={`${zones.length} restricted zones`}>
      <div className="dot-pattern absolute inset-0 opacity-60" aria-hidden />
      {zones.map((z) => (
        <div key={z.name} className="absolute rounded-md border border-critical/70 bg-critical/15" style={{ left: `${z.x * 100}%`, top: `${z.y * 100}%`, width: `${z.w * 100}%`, height: `${z.h * 100}%` }}>
          <span className="absolute left-1 top-0.5 truncate text-[10px] font-medium text-[#ff8f93]">{z.name}</span>
        </div>
      ))}
    </div>
  )
}

/** Draw restricted zones by dragging on a 16:9 frame; coordinates are stored as fractions. */
function ZoneEditor({ zones, onChange }: { zones: Zone[]; onChange: (z: Zone[]) => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const [draft, setDraft] = useState<{ x0: number; y0: number; x1: number; y1: number } | null>(null)
  const [name, setName] = useState('')
  const point = (e: ReactPointerEvent) => {
    const r = ref.current!.getBoundingClientRect()
    return { x: Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)), y: Math.min(1, Math.max(0, (e.clientY - r.top) / r.height)) }
  }
  const box = draft && { x: Math.min(draft.x0, draft.x1), y: Math.min(draft.y0, draft.y1), w: Math.abs(draft.x1 - draft.x0), h: Math.abs(draft.y1 - draft.y0) }
  const add = () => {
    if (!box || box.w < 0.02 || box.h < 0.02 || !name.trim()) return
    const round = (v: number) => Math.round(v * 1000) / 1000
    onChange([...zones, { name: name.trim(), x: round(box.x), y: round(box.y), w: round(Math.min(box.w, 1 - box.x)), h: round(Math.min(box.h, 1 - box.y)) }])
    setDraft(null)
    setName('')
  }
  return (
    <div className="space-y-3">
      <div ref={ref} className="relative aspect-video cursor-crosshair touch-none overflow-hidden rounded-xl border border-line bg-ink-850"
        onPointerDown={(e) => { const p = point(e); (e.target as HTMLElement).setPointerCapture?.(e.pointerId); setDraft({ x0: p.x, y0: p.y, x1: p.x, y1: p.y }) }}
        onPointerMove={(e) => { if (draft && e.buttons) { const p = point(e); setDraft({ ...draft, x1: p.x, y1: p.y }) } }}
        aria-label="Drag to draw a restricted zone" role="application">
        <div className="dot-pattern absolute inset-0" aria-hidden />
        {zones.map((z) => (
          <div key={z.name} className="absolute rounded-md border border-critical/70 bg-critical/15" style={{ left: `${z.x * 100}%`, top: `${z.y * 100}%`, width: `${z.w * 100}%`, height: `${z.h * 100}%` }}>
            <span className="absolute left-1 top-0.5 text-[10px] text-[#ff8f93]">{z.name}</span>
          </div>
        ))}
        {box && <div className="absolute rounded-md border-2 border-dashed border-accent bg-accent/10" style={{ left: `${box.x * 100}%`, top: `${box.y * 100}%`, width: `${box.w * 100}%`, height: `${box.h * 100}%` }} />}
        {!zones.length && !box && <p className="absolute inset-0 grid place-items-center text-xs text-fg-subtle">Drag on the frame to draw a zone</p>}
      </div>
      {box && box.w >= 0.02 && (
        <div className="flex gap-2">
          <Input aria-label="Zone name" placeholder="Zone name, e.g. Server room door" value={name} onChange={(e) => setName(e.target.value)} className="h-9" />
          <Button size="sm" variant="primary" onClick={add} disabled={!name.trim()}>Add zone</Button>
        </div>
      )}
      {zones.length > 0 && (
        <ul className="flex flex-wrap gap-2">
          {zones.map((z) => (
            <li key={z.name} className="inline-flex items-center gap-1.5 rounded-full border border-critical/40 bg-critical/10 px-2.5 py-1 text-xs text-[#ff8f93]">
              {z.name}
              <button aria-label={`Remove ${z.name}`} onClick={() => onChange(zones.filter((x) => x.name !== z.name))} className="hover:text-fg"><Trash2 className="size-3" /></button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function CameraDialog({ camera, onClose }: { camera: Camera; onClose: () => void }) {
  const update = useUpdateCamera(camera)
  const [zones, setZones] = useState<Zone[]>(camera.zones)
  const [retention, setRetention] = useState(String(camera.retention_days))
  const dirtyZones = JSON.stringify(zones) !== JSON.stringify(camera.zones)
  return (
    <Dialog open onClose={onClose} size="xl" title={camera.name} description="Restricted zones raise a high-severity alert when a person is detected inside them.">
      <div className="grid gap-6 lg:grid-cols-[1fr_300px]">
        <div className="space-y-3">
          <h3 className="text-sm font-medium text-fg">Restricted zones</h3>
          <ZoneEditor zones={zones} onChange={setZones} />
          <Button variant="primary" size="sm" disabled={!dirtyZones} loading={update.isPending} onClick={() => update.mutate({ zones })}>Save zones</Button>
        </div>
        <div className="space-y-4">
          <h3 className="text-sm font-medium text-fg">Privacy</h3>
          <Toggle label="Detection" detail="Analyse this camera at all" on={camera.detection_enabled} onChange={(v) => update.mutate({ detection_enabled: v })} />
          <Toggle label="Send snapshots" detail="Stills of detections are stored here; turning this off deletes them" on={!camera.privacy_mode} onChange={(v) => update.mutate({ privacy_mode: !v })} />
          <Toggle label="Blur people" detail="Pixelate every person before a snapshot leaves the site" on={camera.blur_people} onChange={(v) => update.mutate({ blur_people: v })} />
          <Field label="Keep snapshots for (days)">
            {({ id }) => <div className="flex gap-2"><Input id={id} type="number" min={1} max={90} value={retention} onChange={(e) => setRetention(e.target.value)} className="h-9 w-24" />
              <Button size="sm" disabled={Number(retention) === camera.retention_days} onClick={() => update.mutate({ retention_days: Number(retention) })}>Save</Button></div>}
          </Field>
          {update.isError && <ErrorNotice error={update.error} />}
        </div>
      </div>
      {!camera.privacy_mode && <Snapshots camera={camera} />}
    </Dialog>
  )
}

function Toggle({ label, detail, on, onChange }: { label: string; detail: string; on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button type="button" role="switch" aria-checked={on} aria-label={label} onClick={() => onChange(!on)} className="flex w-full items-start gap-3 rounded-xl border border-line p-3 text-left hover:border-line-strong">
      <span className={cn('relative mt-0.5 h-5 w-9 shrink-0 rounded-full transition-colors', on ? 'brand-gradient' : 'bg-ink-700')}>
        <span className={cn('absolute top-0.5 size-4 rounded-full bg-white transition-all', on ? 'left-[18px]' : 'left-0.5')} />
      </span>
      <span><span className="block text-sm text-fg">{label}</span><span className="block text-xs text-fg-subtle">{detail}</span></span>
    </button>
  )
}

function Snapshots({ camera }: { camera: Camera }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const list = useQuery({ queryKey: qk.snapshots(orgId, camera.id), queryFn: () => api<Snapshot[]>(`/organizations/${orgId}/cameras/${camera.id}/snapshots`) })
  const remove = useMutation({
    mutationFn: (id: string) => api(`/organizations/${orgId}/snapshots/${id}`, { method: 'DELETE' }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['cameras', orgId] }) },
  })
  return (
    <section className="mt-6">
      <h3 className="mb-2 text-sm font-medium text-fg">Snapshots <span className="font-normal text-fg-subtle">· viewing is recorded in the audit log</span></h3>
      {list.isPending ? <Skeleton className="h-24" /> : !list.data?.length ? <p className="text-xs text-fg-subtle">No snapshots.</p> : (
        <ul className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {list.data.map((s) => (
            <li key={s.id} className="overflow-hidden rounded-xl border border-line">
              <SnapshotImage path={`/organizations/${orgId}/snapshots/${s.id}/image`} alt={`${s.event_type} at ${s.captured_at}`} />
              <div className="flex items-center justify-between px-2 py-1.5 text-[11px] text-fg-subtle">
                {s.event_type} · {relativeTime(s.captured_at)}
                <button aria-label="Delete snapshot" onClick={() => remove.mutate(s.id)} className="hover:text-critical"><Trash2 className="size-3.5" /></button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function SnapshotImage({ path, alt }: { path: string; alt: string }) {
  const [src, setSrc] = useState<string | null>(null)
  useEffect(() => {
    let url: string | null = null
    let alive = true
    fetchObjectUrl(path).then((u) => { url = u; if (alive) setSrc(u) }).catch(() => {})
    return () => { alive = false; if (url) URL.revokeObjectURL(url) }
  }, [path])
  return src ? <img src={src} alt={alt} className="aspect-video w-full object-cover" /> : <div className="aspect-video bg-ink-850" />
}

function CameraGuide({ onClose }: { onClose: () => void }) {
  return (
    <Dialog open onClose={onClose} size="lg" title="Connect a camera" description="The camera agent runs on a Windows, macOS or Linux computer that can see the camera.">
      <ol className="space-y-3 text-sm">
        {[
          ['Enroll the computer', 'Devices → install the SENTINEL X agent and enroll it (one token, shown once).'],
          ['Install the vision extra', 'pip install "sentinel-x-agent[vision]"'],
          ['Start watching', 'Set SENTINEL_CAMERA_SOURCE to the camera index (0) or its RTSP URL, then run: sentinel-agent camera --key front-door --name "Front door"'],
          ['Turn detection on here', 'The camera appears with detection off. Turn it on, draw zones, and choose your privacy settings.'],
        ].map(([title, text], i) => (
          <li key={title} className="flex gap-3">
            <span className="brand-gradient grid size-7 shrink-0 place-items-center rounded-full text-xs font-semibold text-white">{i + 1}</span>
            <div><p className="font-medium text-fg">{title}</p><p className="break-words font-mono text-xs text-fg-muted">{text}</p></div>
          </li>
        ))}
      </ol>
    </Dialog>
  )
}
