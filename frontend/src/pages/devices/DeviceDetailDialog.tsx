import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldOff } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Input } from '@/components/ui/Field'
import { DeviceStatusBadge, Meter, SeverityBadge } from '@/components/ui/StatusBadges'
import { api, ApiError } from '@/lib/api'
import { dateTime, relativeTime, titleCase } from '@/lib/format'
import type { AgentConfig, DeviceDetail, Page, SecurityEvent } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

function uptime(seconds?: number): string {
  if (seconds === undefined) return '—'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`
}

export function DeviceDetailDialog({ deviceId, onClose }: { deviceId: string; onClose: () => void }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const manage = can('devices:manage')
  const device = useQuery({
    queryKey: qk.device(orgId, deviceId),
    queryFn: () => api<DeviceDetail>(`/organizations/${orgId}/devices/${deviceId}`),
  })
  const events = useQuery({
    queryKey: qk.events(orgId, { device_id: deviceId, limit: 8 }),
    queryFn: () => api<Page<SecurityEvent>>(`/organizations/${orgId}/events`, { query: { device_id: deviceId, limit: 8 } }),
    enabled: can('events:read'),
  })
  const revoke = useMutation({
    mutationFn: () => api<DeviceDetail>(`/organizations/${orgId}/devices/${deviceId}/revoke`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.devices(orgId) }),
  })
  const d = device.data
  const t = d?.telemetry ?? {}

  return (
    <Dialog open onClose={onClose} size="xl" title={d?.name ?? 'Device'} description={d ? `${d.hostname ?? ''} · ${titleCase(d.device_type)} · enrolled ${relativeTime(d.enrolled_at)}` : undefined}>
      {device.isError ? <ErrorNotice error={device.error} /> : !d ? <Skeleton className="h-64" /> : (
        <div className="grid gap-5 lg:grid-cols-[1fr_300px]">
          <div className="space-y-5">
            <section className="grid gap-4 rounded-xl border border-line bg-ink-900/60 p-4 sm:grid-cols-3">
              <Meter label="CPU" value={t.cpu_percent} warnAt={d.config.thresholds.cpu_percent - 10} critAt={d.config.thresholds.cpu_percent} />
              <Meter label="Memory" value={t.memory_percent} warnAt={d.config.thresholds.memory_percent - 10} critAt={d.config.thresholds.memory_percent} />
              <Meter label="System disk" value={t.disk_percent} warnAt={d.config.thresholds.disk_percent - 10} critAt={d.config.thresholds.disk_percent} />
            </section>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
              {[
                ['Status', <DeviceStatusBadge key="s" status={d.status} />],
                ['Health score', d.health_score ?? '—'],
                ['Uptime', uptime(t.uptime_seconds)],
                ['Processes', t.process_count ?? '—'],
                ['Operating system', d.os ?? '—'],
                ['IP address', <span key="ip" className="font-mono text-xs">{d.ip_address ?? '—'}</span>],
                ['Agent version', <span key="v" className="font-mono text-xs">{d.agent_version ?? '—'}</span>],
                ['Last heartbeat', d.last_seen_at ? <span key="l" title={dateTime(d.last_seen_at)}>{relativeTime(d.last_seen_at)}</span> : '—'],
                ['Credential rotated', relativeTime(d.credential_rotated_at)],
              ].map(([k, v]) => (
                <div key={String(k)}>
                  <dt className="text-xs text-fg-subtle">{k}</dt>
                  <dd className="mt-0.5 text-fg">{v}</dd>
                </div>
              ))}
            </dl>
            <div>
              <h3 className="mb-2 text-xs font-medium text-fg-muted">Listening TCP ports ({t.listening_ports?.length ?? 0})</h3>
              {t.listening_ports?.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {t.listening_ports.map((p) => <span key={p} className="rounded-md border border-line-strong bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-fg-muted">{p}</span>)}
                </div>
              ) : <p className="text-xs text-fg-subtle">Not reported (collector disabled or no permission on this OS).</p>}
            </div>
            {events.data && (
              <div>
                <h3 className="mb-2 text-xs font-medium text-fg-muted">Recent events</h3>
                {events.data.items.length === 0 ? <p className="text-xs text-fg-subtle">No events from this device.</p> : (
                  <ul className="divide-y divide-line rounded-lg border border-line">
                    {events.data.items.map((e) => (
                      <li key={e.id} className="flex items-center gap-3 px-3 py-2 text-sm">
                        <SeverityBadge severity={e.severity} />
                        <span className="min-w-0 flex-1 truncate text-fg">{e.title}</span>
                        {e.occurrence_count > 1 && <span className="tabular text-xs text-fg-subtle">×{e.occurrence_count}</span>}
                        <span className="whitespace-nowrap text-xs text-fg-subtle">{relativeTime(e.occurred_at)}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>

          <aside className="space-y-4">
            {manage && d.enrollment_status === 'enrolled' && <ConfigForm key={d.config_version} deviceId={d.id} config={d.config} version={d.config_version} />}
            {manage && d.enrollment_status === 'enrolled' && (
              <div className="rounded-xl border border-critical/25 bg-critical/[0.04] p-4">
                <h3 className="text-sm font-medium text-fg">Revoke device</h3>
                <p className="mt-1 text-xs text-fg-muted">The credential stops working immediately and the agent shuts down on its next contact. This cannot be undone; re-enroll with a new token.</p>
                {revoke.error && <div className="mt-2"><ErrorNotice error={revoke.error} /></div>}
                <Button
                  className="mt-3"
                  size="sm"
                  variant="danger"
                  icon={<ShieldOff className="size-3.5" />}
                  loading={revoke.isPending}
                  onClick={() => window.confirm(`Revoke ${d.name}? Its agent will be disconnected.`) && revoke.mutate()}
                >
                  Revoke device
                </Button>
              </div>
            )}
            {d.enrollment_status === 'revoked' && (
              <p className="rounded-lg border border-line bg-ink-900/60 p-3 text-xs text-fg-muted">This device was revoked and no longer reports. It is kept for the audit trail.</p>
            )}
          </aside>
        </div>
      )}
    </Dialog>
  )
}

function ConfigForm({ deviceId, config, version }: { deviceId: string; config: AgentConfig; version: number }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [form, setForm] = useState<AgentConfig>(config)
  const save = useMutation({
    mutationFn: () => api<DeviceDetail>(`/organizations/${orgId}/devices/${deviceId}`, { method: 'PATCH', body: { config: form } }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.device(orgId, deviceId) }),
  })
  const err = save.error instanceof ApiError ? save.error : null
  const toggle = (c: AgentConfig['collectors'][number]) =>
    setForm((f) => ({ ...f, collectors: f.collectors.includes(c) ? f.collectors.filter((x) => x !== c) : [...f.collectors, c] }))
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate()
  }
  return (
    <form onSubmit={submit} className="space-y-3 rounded-xl border border-line bg-ink-900/60 p-4">
      <div className="flex items-baseline justify-between">
        <h3 className="text-sm font-medium text-fg">Agent configuration</h3>
        <span className="font-mono text-[11px] text-fg-subtle">v{version}</span>
      </div>
      <p className="text-xs text-fg-subtle">Delivered on the next heartbeat. Only these allow-listed settings exist.</p>
      {save.error && <ErrorNotice error={save.error} />}
      <label className="block text-xs text-fg-muted">
        Heartbeat interval (seconds)
        <Input type="number" min={15} max={3600} className="mt-1 h-8 text-xs" value={form.heartbeat_interval_seconds} onChange={(e) => setForm((f) => ({ ...f, heartbeat_interval_seconds: Number(e.target.value) }))} />
      </label>
      <fieldset className="text-xs text-fg-muted">
        <legend className="mb-1">Collectors</legend>
        <div className="flex flex-wrap gap-3">
          {(['system', 'network', 'ports'] as const).map((c) => (
            <label key={c} className="flex items-center gap-1.5">
              <input type="checkbox" checked={form.collectors.includes(c)} onChange={() => toggle(c)} className="accent-[var(--color-accent)]" /> {c}
            </label>
          ))}
        </div>
      </fieldset>
      <p className="text-xs text-fg-muted">Alert thresholds</p>
      <div className="grid grid-cols-3 gap-2">
        {(['cpu_percent', 'memory_percent', 'disk_percent'] as const).map((k) => (
          <label key={k} className="block text-[11px] text-fg-muted">
            {{ cpu_percent: 'CPU %', memory_percent: 'Memory %', disk_percent: 'Disk %' }[k]}
            <Input type="number" min={50} max={100} className="mt-1 h-8 text-xs" value={form.thresholds[k]} onChange={(e) => setForm((f) => ({ ...f, thresholds: { ...f.thresholds, [k]: Number(e.target.value) } }))} />
          </label>
        ))}
      </div>
      {err?.details && <p className="text-xs text-critical">{err.details.map((d) => `${d.field}: ${d.message}`).join(' · ')}</p>}
      <Button type="submit" size="sm" loading={save.isPending} disabled={JSON.stringify(form) === JSON.stringify(config)}>Push configuration</Button>
    </form>
  )
}
