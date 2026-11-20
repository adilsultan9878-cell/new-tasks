import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, KeyRound, MonitorSmartphone, Plus, Search, Terminal } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Input, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { DeviceStatusBadge } from '@/components/ui/StatusBadges'
import { absoluteApiBase, api, ApiError } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime, titleCase } from '@/lib/format'
import type { Device, EnrollmentToken, EnrollmentTokenCreated } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { DeviceDetailDialog } from './DeviceDetailDialog'

const DEVICE_TYPES = ['workstation', 'server', 'mobile', 'iot', 'camera', 'sensor_hub', 'network', 'other']

export function DevicesPage() {
  const { orgId, can } = useOrg()
  const manage = can('devices:manage')
  const [query, setQuery] = useState('')
  const [showRevoked, setShowRevoked] = useState(false)
  const [enrolling, setEnrolling] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)

  const devices = useQuery({
    queryKey: [...qk.devices(orgId), { showRevoked }],
    queryFn: () => api<Device[]>(`/organizations/${orgId}/devices`, { query: { include_decommissioned: showRevoked } }),
    refetchInterval: 60_000,
  })
  const q = query.trim().toLowerCase()
  const rows = (devices.data ?? []).filter(
    (d) => !q || d.name.toLowerCase().includes(q) || (d.hostname ?? '').toLowerCase().includes(q) || (d.ip_address ?? '').includes(q),
  )
  const counts = (devices.data ?? []).reduce<Record<string, number>>((acc, d) => ({ ...acc, [d.status]: (acc[d.status] ?? 0) + 1 }), {})

  return (
    <div>
      <PageHeader
        eyebrow="AEGIS ONE · Device Management"
        title="Devices"
        description="Authorized devices running the SENTINEL X agent. Each one authenticates with its own credential; revoking a device cuts it off immediately."
        actions={manage && <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEnrolling(true)}>Enroll device</Button>}
      />

      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(['online', 'degraded', 'offline'] as const).map((s) => (
          <div key={s} className="panel flex items-center justify-between px-4 py-3">
            <DeviceStatusBadge status={s} />
            <span className="tabular text-xl font-semibold">{counts[s] ?? 0}</span>
          </div>
        ))}
        <div className="panel flex items-center justify-between px-4 py-3">
          <span className="text-xs font-medium text-fg-muted">Total</span>
          <span className="tabular text-xl font-semibold">{(devices.data ?? []).filter((d) => d.status !== 'decommissioned').length}</span>
        </div>
      </div>

      <Panel
        title="Enrolled devices"
        flush
        actions={
          <div className="flex items-center gap-2">
            <label className="hidden items-center gap-1.5 text-xs text-fg-muted sm:flex">
              <input type="checkbox" checked={showRevoked} onChange={(e) => setShowRevoked(e.target.checked)} className="accent-[var(--color-accent)]" />
              Show revoked
            </label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-subtle" aria-hidden />
              <Input aria-label="Filter devices" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter…" className="h-8 w-40 pl-8 text-xs sm:w-52" />
            </div>
          </div>
        }
      >
        {devices.isPending ? (
          <div className="space-y-3 p-5">{Array.from({ length: 3 }, (_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : devices.isError ? (
          <div className="p-5"><ErrorNotice error={devices.error} /></div>
        ) : rows.length === 0 ? (
          <EmptyState
            icon={MonitorSmartphone}
            title={devices.data.length ? 'No devices match the filter' : 'No devices enrolled yet'}
            action={manage && !devices.data.length ? <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEnrolling(true)}>Enroll your first device</Button> : undefined}
          >
            {!devices.data.length && 'Create an enrollment token, install the local agent on an authorized machine, and it appears here within seconds.'}
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-fg-subtle">
                  <th className="px-5 py-2.5 font-medium">Device</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Health</th>
                  <th className="px-3 py-2.5 font-medium">OS</th>
                  <th className="px-3 py-2.5 font-medium">IP address</th>
                  <th className="px-3 py-2.5 font-medium">Agent</th>
                  <th className="px-5 py-2.5 font-medium">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map((d) => (
                  <tr
                    key={d.id}
                    onClick={() => setSelected(d.id)}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setSelected(d.id)}
                    tabIndex={0}
                    className={cn('cursor-pointer hover:bg-ink-850/60 focus-visible:bg-ink-850', d.status === 'decommissioned' && 'opacity-55')}
                    aria-label={`Open ${d.name}`}
                  >
                    <td className="px-5 py-3">
                      <p className="font-medium text-fg">{d.name}</p>
                      <p className="text-xs text-fg-subtle">{d.hostname ?? '—'} · {titleCase(d.device_type)}</p>
                    </td>
                    <td className="px-3 py-3"><DeviceStatusBadge status={d.status} /></td>
                    <td className="px-3 py-3">
                      {d.health_score === null ? <span className="text-fg-subtle">—</span> : (
                        <span className={cn('tabular font-medium', d.health_score >= 80 ? 'text-ok' : d.health_score >= 60 ? 'text-medium' : 'text-critical')}>{d.health_score}</span>
                      )}
                    </td>
                    <td className="px-3 py-3 text-fg-muted">{d.os ?? '—'}</td>
                    <td className="px-3 py-3 font-mono text-xs text-fg-muted">{d.ip_address ?? '—'}</td>
                    <td className="px-3 py-3 font-mono text-xs text-fg-muted">{d.agent_version ?? '—'}</td>
                    <td className="px-5 py-3 text-fg-muted">{relativeTime(d.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {manage && <EnrollmentTokens />}
      {manage && <EnrollDialog open={enrolling} onClose={() => setEnrolling(false)} />}
      {selected && <DeviceDetailDialog deviceId={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function EnrollmentTokens() {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const tokens = useQuery({ queryKey: qk.tokens(orgId), queryFn: () => api<EnrollmentToken[]>(`/organizations/${orgId}/enrollment-tokens`) })
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/organizations/${orgId}/enrollment-tokens/${id}/revoke`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.tokens(orgId) }),
  })
  if (!tokens.data?.length) return null
  const tone = { active: 'ok', expired: 'neutral', exhausted: 'neutral', revoked: 'critical' } as const
  return (
    <Panel className="mt-5" title="Enrollment tokens" description="Secrets are shown only once at creation; only a hash is stored" flush>
      <ul className="divide-y divide-line">
        {tokens.data.map((t) => (
          <li key={t.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
            <KeyRound className="size-4 text-fg-subtle" aria-hidden />
            <span className="min-w-0 flex-1">
              <span className="block truncate font-medium text-fg">{t.label}</span>
              <span className="text-xs text-fg-subtle">
                {titleCase(t.device_type)} · used {t.use_count}/{t.max_uses} · {t.state === 'active' ? `expires ${relativeTime(t.expires_at)}` : `created ${relativeTime(t.created_at)}`}
              </span>
            </span>
            <Badge tone={tone[t.state]}>{t.state}</Badge>
            {t.state === 'active' && (
              <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables === t.id} onClick={() => revoke.mutate(t.id)}>Revoke</Button>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  )
}

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked: the text remains selectable */
    }
  }
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-medium text-fg-muted">{label}</span>
        <button type="button" onClick={() => void copy()} className="flex items-center gap-1 text-xs text-accent hover:underline">
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-[12px] leading-relaxed text-fg">{text}</pre>
    </div>
  )
}

function EnrollDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ label: '', device_type: 'workstation', max_uses: 1, expires_in_hours: 24 })
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null)
  const create = useMutation({
    mutationFn: () => api<EnrollmentTokenCreated>(`/organizations/${orgId}/enrollment-tokens`, { method: 'POST', body: { ...form, label: form.label.trim() } }),
    onSuccess: (t) => {
      setCreated(t)
      void queryClient.invalidateQueries({ queryKey: qk.tokens(orgId) })
    },
  })
  const err = create.error instanceof ApiError ? create.error : null
  const close = () => {
    setCreated(null)
    create.reset()
    setForm((f) => ({ ...f, label: '' }))
    onClose()
  }
  const server = absoluteApiBase().replace(/\/api\/v1$/, '')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    create.mutate()
  }

  return (
    <Dialog open={open} onClose={close} size="lg" title={created ? 'Install the agent' : 'Enroll a device'} description={created ? 'Copy the token now — it will not be shown again.' : 'Creates a short-lived enrollment token for authorized devices you control.'}>
      {created ? (
        <div className="space-y-4">
          <CopyBlock label="Enrollment token" text={created.token} />
          <div className="rounded-lg border border-line bg-ink-900/60 p-3 text-xs text-fg-muted">
            <p className="mb-2 flex items-center gap-1.5 font-medium text-fg"><Terminal className="size-3.5" /> On the device (Windows PowerShell, macOS or Linux), from the SENTINEL X repository folder:</p>
            <ol className="list-decimal space-y-1 pl-4">
              <li>Install Python 3.10+ if needed.</li>
              <li>Run the commands below. The agent reads system health and listening ports only — it never runs remote commands.</li>
            </ol>
          </div>
          <CopyBlock label="1 · Install" text="pip install ./agent" />
          <CopyBlock label="2 · Enroll" text={`sentinel-agent enroll --server ${server} --token ${created.token}`} />
          <CopyBlock label="3 · Run" text="sentinel-agent run" />
          <p className="text-xs text-fg-subtle">
            Valid for {created.max_uses} enrollment{created.max_uses > 1 ? 's' : ''}, expires {relativeTime(created.expires_at)}. The device appears in the list as soon as it enrolls.
          </p>
          <div className="flex justify-end"><Button variant="primary" onClick={close}>Done</Button></div>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4" noValidate>
          {create.error && !err?.details && <ErrorNotice error={create.error} />}
          <Field label="Label" error={err?.fieldError('label')} hint="e.g. “Finance laptops” or “Lab server rack 2”">
            {({ id, describedBy, invalid }) => (
              <Input id={id} aria-describedby={describedBy} invalid={invalid} autoFocus required maxLength={120} value={form.label} onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))} />
            )}
          </Field>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Device type">
              {({ id }) => (
                <Select id={id} value={form.device_type} onChange={(e) => setForm((f) => ({ ...f, device_type: e.target.value }))}>
                  {DEVICE_TYPES.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}
                </Select>
              )}
            </Field>
            <Field label="Max devices">
              {({ id }) => <Input id={id} type="number" min={1} max={100} value={form.max_uses} onChange={(e) => setForm((f) => ({ ...f, max_uses: Number(e.target.value) }))} />}
            </Field>
            <Field label="Expires in">
              {({ id }) => (
                <Select id={id} value={form.expires_in_hours} onChange={(e) => setForm((f) => ({ ...f, expires_in_hours: Number(e.target.value) }))}>
                  <option value={1}>1 hour</option>
                  <option value={24}>24 hours</option>
                  <option value={72}>3 days</option>
                  <option value={168}>7 days</option>
                </Select>
              )}
            </Field>
          </div>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={close}>Cancel</Button>
            <Button type="submit" variant="primary" loading={create.isPending} disabled={!form.label.trim()}>Create token</Button>
          </div>
        </form>
      )}
    </Dialog>
  )
}
