import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, ChevronLeft, ChevronRight, Plus, ShieldAlert } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton, StatusDot } from '@/components/ui/Feedback'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/StatusBadges'
import { api, ApiError } from '@/lib/api'
import { cn } from '@/lib/cn'
import { dateTime, relativeTime, titleCase } from '@/lib/format'
import type { Alert, IngestResult, Page, SecurityEvent, SecurityEventDetail } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'
import { useRealtime } from '@/realtime/RealtimeProvider'
import { AnalyzeButton, PriorityBadge, RiskBadge } from '@/pages/brain/shared'

const PAGE = 50
const CATEGORIES = ['network', 'auth', 'malware', 'phishing', 'system', 'agent', 'policy', 'iot', 'vision', 'other']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

export function EventsPage() {
  const { orgId, can } = useOrg()
  const { status: live } = useRealtime()
  const [filters, setFilters] = useState({ severity: '', category: '', status: 'open', q: '' })
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const params = { ...filters, limit: PAGE, offset }

  const events = useQuery({
    queryKey: qk.events(orgId, params),
    queryFn: () => api<Page<SecurityEvent>>(`/organizations/${orgId}/events`, { query: params }),
    placeholderData: keepPreviousData,
    refetchInterval: live === 'live' ? false : 30_000,
  })
  const alerts = useQuery({
    queryKey: qk.alerts(orgId),
    queryFn: () => api<Alert[]>(`/organizations/${orgId}/alerts`, { query: { status: 'open', limit: 5 } }),
    enabled: can('alerts:read'),
  })
  const set = (k: keyof typeof filters) => (v: string) => {
    setFilters((f) => ({ ...f, [k]: v }))
    setOffset(0)
  }
  const total = events.data?.total ?? 0

  return (
    <div>
      <PageHeader
        eyebrow="SENTINEL X · Security operations"
        title="Security events"
        description="Everything your enrolled agents and analysts report, de-duplicated and checked against deterministic detection rules."
        actions={
          <>
            <span className="flex items-center gap-2 text-xs text-fg-subtle">
              <StatusDot tone={live === 'live' ? 'ok' : 'warn'} pulse={live === 'live'} />
              {live === 'live' ? 'Streaming live' : 'Polling every 30 s'}
            </span>
            {can('events:ingest') && <Button icon={<Plus className="size-4" />} onClick={() => setSubmitting(true)}>Report event</Button>}
          </>
        }
      />

      {!!alerts.data?.length && (
        <Panel className="mb-5" title={<span className="flex items-center gap-2"><ShieldAlert className="size-4 text-critical" /> Open alerts</span>} description="Raised by detection rules and triaged automatically by the Security Brain · full alert workflow arrives with the Incident Response Center (Phase 5)" flush>
          <ul className="divide-y divide-line">
            {alerts.data.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 px-5 py-2.5 text-sm">
                <SeverityBadge severity={a.severity} />
                <button className="min-w-0 flex-1 truncate text-left text-fg hover:underline" onClick={() => a.event_id && setSelected(a.event_id)}>{a.title}</button>
                <span className="font-mono text-[11px] text-fg-subtle">{a.detection_rule}</span>
                <TriageCell alert={a} />
                <span className="text-xs text-fg-subtle">{relativeTime(a.created_at)}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Panel
        title="Event stream"
        description={events.data ? `${total} event${total === 1 ? '' : 's'}` : undefined}
        flush
        actions={
          <div className="flex flex-wrap justify-end gap-2">
            <Input aria-label="Search titles" placeholder="Search…" value={filters.q} onChange={(e) => set('q')(e.target.value)} className="h-8 w-36 text-xs" />
            <Select aria-label="Severity" className="h-8 w-32 text-xs" value={filters.severity} onChange={(e) => set('severity')(e.target.value)}>
              <option value="">All severities</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
            </Select>
            <Select aria-label="Category" className="h-8 w-32 text-xs" value={filters.category} onChange={(e) => set('category')(e.target.value)}>
              <option value="">All categories</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{titleCase(c)}</option>)}
            </Select>
            <Select aria-label="Status" className="h-8 w-28 text-xs" value={filters.status} onChange={(e) => set('status')(e.target.value)}>
              <option value="open">Open</option>
              <option value="new">New</option>
              <option value="triaged">Triaged</option>
              <option value="closed">Closed</option>
              <option value="">All</option>
            </Select>
          </div>
        }
      >
        {events.isPending ? (
          <div className="space-y-3 p-5">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-9" />)}</div>
        ) : events.isError ? (
          <div className="p-5"><ErrorNotice error={events.error} /></div>
        ) : events.data.items.length === 0 ? (
          <EmptyState icon={Activity} title="No matching events">
            Events appear here in real time once an enrolled agent reports, or when an analyst files one.
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-fg-subtle">
                  <th className="px-5 py-2.5 font-medium">Time</th>
                  <th className="px-3 py-2.5 font-medium">Severity</th>
                  <th className="px-3 py-2.5 font-medium">Event</th>
                  <th className="px-3 py-2.5 font-medium">Device</th>
                  <th className="px-3 py-2.5 font-medium">Category</th>
                  <th className="px-5 py-2.5 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {events.data.items.map((e) => (
                  <tr key={e.id} tabIndex={0} onClick={() => setSelected(e.id)} onKeyDown={(k) => k.key === 'Enter' && setSelected(e.id)} className="cursor-pointer hover:bg-ink-850/60 focus-visible:bg-ink-850" aria-label={`Open event ${e.title}`}>
                    <td className="whitespace-nowrap px-5 py-2.5 text-fg-muted" title={dateTime(e.occurred_at)}>{relativeTime(e.occurred_at)}</td>
                    <td className="px-3 py-2.5"><SeverityBadge severity={e.severity} /></td>
                    <td className="px-3 py-2.5">
                      <span className="text-fg">{e.title}</span>
                      {e.occurrence_count > 1 && <span className="ml-2 rounded bg-ink-750 px-1.5 py-0.5 font-mono text-[10px] text-fg-muted" title="Folded duplicates">×{e.occurrence_count}</span>}
                      <span className="block font-mono text-[11px] text-fg-subtle">{e.event_type}</span>
                    </td>
                    <td className="px-3 py-2.5 text-fg-muted">{e.device_name ?? <span className="text-fg-subtle">{e.source}</span>}</td>
                    <td className="px-3 py-2.5 text-fg-muted">{titleCase(e.category)}</td>
                    <td className="px-5 py-2.5"><Badge tone={e.status === 'new' ? 'accent' : 'neutral'}>{e.status}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {total > PAGE && (
          <div className="flex items-center justify-between border-t border-line px-5 py-3 text-xs text-fg-subtle">
            <span>{offset + 1}–{Math.min(offset + PAGE, total)} of {total}</span>
            <div className="flex gap-2">
              <Button size="sm" icon={<ChevronLeft className="size-3.5" />} disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE))}>Previous</Button>
              <Button size="sm" disabled={offset + PAGE >= total} onClick={() => setOffset((o) => o + PAGE)}>Next <ChevronRight className="size-3.5" /></Button>
            </div>
          </div>
        )}
      </Panel>

      {selected && <EventDetailDialog eventId={selected} onClose={() => setSelected(null)} />}
      <ReportEventDialog open={submitting} onClose={() => setSubmitting(false)} />
    </div>
  )
}

function EventDetailDialog({ eventId, onClose }: { eventId: string; onClose: () => void }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const detail = useQuery({
    queryKey: qk.event(orgId, eventId),
    queryFn: () => api<SecurityEventDetail>(`/organizations/${orgId}/events/${eventId}`),
  })
  const setStatus = useMutation({
    mutationFn: (status: string) => api(`/organizations/${orgId}/events/${eventId}`, { method: 'PATCH', body: { status } }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['events', orgId] }),
  })
  const e = detail.data
  return (
    <Dialog open onClose={onClose} size="xl" title={e?.title ?? 'Event'} description={e ? `${e.event_type} · ${titleCase(e.source)}${e.device_name ? ` · ${e.device_name}` : ''}` : undefined}>
      {detail.isError ? <ErrorNotice error={detail.error} /> : !e ? <Skeleton className="h-64" /> : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <SeverityBadge severity={e.severity} />
            <Badge tone={e.status === 'new' ? 'accent' : 'neutral'}>{e.status}</Badge>
            <span className="text-fg-muted">First seen {dateTime(e.occurred_at)}</span>
            {e.occurrence_count > 1 && <span className="text-fg-muted">· seen {e.occurrence_count}× (last {relativeTime(e.last_occurred_at)})</span>}
            {can('alerts:manage') && (
              <div className="ml-auto flex gap-2">
                {e.status !== 'triaged' && e.status !== 'closed' && <Button size="sm" loading={setStatus.isPending} onClick={() => setStatus.mutate('triaged')}>Mark triaged</Button>}
                {e.status !== 'closed' ? <Button size="sm" variant="primary" loading={setStatus.isPending} onClick={() => setStatus.mutate('closed')}>Close</Button>
                  : <Button size="sm" loading={setStatus.isPending} onClick={() => setStatus.mutate('new')}>Reopen</Button>}
              </div>
            )}
          </div>
          {setStatus.error && <ErrorNotice error={setStatus.error} />}
          {e.description && <p className="text-sm text-fg-muted">{e.description}</p>}
          {e.alerts.length > 0 && (
            <div className="rounded-xl border border-critical/25 bg-critical/[0.04] p-3">
              <h3 className="mb-2 text-xs font-medium text-fg">Alerts raised by this event</h3>
              <ul className="space-y-1.5 text-sm">
                {e.alerts.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={a.severity} />
                    <span className="text-fg">{a.title}</span>
                    <span className="font-mono text-[11px] text-fg-subtle">rule: {a.detection_rule}</span>
                    <TriageCell alert={a} />
                    {a.description && <span className="w-full text-xs text-fg-muted">{a.description}</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="grid gap-4 lg:grid-cols-2">
            <JsonBlock title="Normalized" value={e.normalized} />
            <JsonBlock title="Raw payload (as reported)" value={e.raw} />
          </div>
        </div>
      )}
    </Dialog>
  )
}

function JsonBlock({ title, value }: { title: string; value: unknown }) {
  return (
    <div>
      <h3 className="mb-1.5 text-xs font-medium text-fg-muted">{title}</h3>
      <pre className="max-h-72 overflow-auto rounded-lg border border-line bg-canvas p-3 font-mono text-[11.5px] leading-relaxed text-fg-muted">{JSON.stringify(value, null, 2)}</pre>
    </div>
  )
}

function ReportEventDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const blank = { title: '', category: 'policy', severity: 'medium', event_type: 'analyst.report', description: '' }
  const [form, setForm] = useState(blank)
  const submit = useMutation({
    mutationFn: () => api<IngestResult>(`/organizations/${orgId}/events`, {
      method: 'POST',
      body: { ...form, title: form.title.trim(), description: form.description.trim() || null },
    }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['events', orgId] })
      setForm(blank)
      onClose()
    },
  })
  const err = submit.error instanceof ApiError ? submit.error : null
  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    submit.mutate()
  }
  return (
    <Dialog open={open} onClose={onClose} title="Report a security event" description="Recorded with your name as a manual event and evaluated by the same detection rules (high/critical events raise alerts).">
      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        {submit.error && !err?.details && <ErrorNotice error={submit.error} />}
        <Field label="Title" error={err?.fieldError('title')}>
          {({ id, describedBy, invalid }) => <Input id={id} aria-describedby={describedBy} invalid={invalid} autoFocus maxLength={255} value={form.title} onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))} placeholder="Unknown USB device found in server room" />}
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Category">
            {({ id }) => (
              <Select id={id} value={form.category} onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))}>
                {CATEGORIES.map((c) => <option key={c} value={c}>{titleCase(c)}</option>)}
              </Select>
            )}
          </Field>
          <Field label="Severity">
            {({ id }) => (
              <Select id={id} value={form.severity} onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value }))}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
              </Select>
            )}
          </Field>
        </div>
        <Field label="Details" hint="Optional">
          {({ id }) => <Textarea id={id} maxLength={4000} value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />}
        </Field>
        <div className={cn('flex justify-end gap-2')}>
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={submit.isPending} disabled={!form.title.trim()}>Submit event</Button>
        </div>
      </form>
    </Dialog>
  )
}

/** Latest Security Brain triage of an alert, or a button to run one. */
function TriageCell({ alert }: { alert: Alert }) {
  const { orgId, can } = useOrg()
  const t = alert.triage
  if (t && can('brain:read')) {
    return (
      <Link to={`/org/${orgId}/brain/runs/${t.run_id}`} className="inline-flex items-center gap-1.5 rounded-md hover:opacity-80" title="Open the Security Brain triage">
        <PriorityBadge priority={t.priority} />
        <RiskBadge level={t.risk_level} score={t.risk_score} />
      </Link>
    )
  }
  return <AnalyzeButton subjectType="alert" subjectId={alert.id} label="Triage" variant="ghost" />
}
