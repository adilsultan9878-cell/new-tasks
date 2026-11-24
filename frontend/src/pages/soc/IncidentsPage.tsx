import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronRight, Plus, ShieldCheck, Siren } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Input, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/StatusBadges'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime } from '@/lib/format'
import type { Alert, Incident, IncidentDetail, Page, ResponseAction, Severity } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { ActionRow, EmergencyStopBanner, EmergencyStopButton, IncidentStatusPill, ProposeActionDialog } from './shared'

const FILTERS = [
  { key: 'active', label: 'Active' },
  { key: 'closed', label: 'Closed' },
  { key: '', label: 'All' },
] as const

export function IncidentsPage() {
  const { orgId, can } = useOrg()
  const [filter, setFilter] = useState<string>('active')
  const [creating, setCreating] = useState(false)
  const [proposing, setProposing] = useState(false)
  const incidents = useQuery({
    queryKey: qk.incidents(orgId, { status: filter }),
    queryFn: () => api<Page<Incident>>(`/organizations/${orgId}/incidents`, { query: { status: filter, limit: 100 } }),
    placeholderData: keepPreviousData,
  })
  const pending = useQuery({
    queryKey: qk.actions(orgId, { status: 'pending_approval' }),
    queryFn: () => api<Page<ResponseAction>>(`/organizations/${orgId}/actions`, { query: { status: 'pending_approval', limit: 20 } }),
  })
  const recent = useQuery({
    queryKey: qk.actions(orgId, { limit: 8 }),
    queryFn: () => api<Page<ResponseAction>>(`/organizations/${orgId}/actions`, { query: { limit: 8 } }),
  })

  return (
    <div>
      <PageHeader
        eyebrow="SENTINEL X · Respond"
        title="Incident Response"
        description="Turn alerts into incidents, coordinate the response and keep every decision on record. Actions come from a fixed allow-list, wait for approval when they matter, and can be stopped at once."
        actions={<>
          <EmergencyStopButton />
          {can('responses:propose') && <Button size="md" icon={<ShieldCheck className="size-4" />} onClick={() => setProposing(true)}>Propose action</Button>}
          {can('incidents:manage') && <Button size="md" variant="primary" icon={<Plus className="size-4" />} onClick={() => setCreating(true)}>New incident</Button>}
        </>}
      />
      <EmergencyStopBanner />

      {!!pending.data?.items.length && (
        <Panel className="mb-5 border-medium/30" title={`Waiting for approval (${pending.data.total})`} description="Medium and high impact actions run only after an approver decides">
          <ul className="space-y-2.5">{pending.data.items.map((a) => <ActionRow key={a.id} action={a} showIncident />)}</ul>
        </Panel>
      )}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel
          title="Incidents"
          description={incidents.data ? `${incidents.data.total} ${filter === 'active' ? 'active' : filter || 'total'}` : undefined}
          flush
          actions={
            <div className="flex gap-1 rounded-lg border border-line bg-ink-900/60 p-0.5" role="tablist" aria-label="Incident filter">
              {FILTERS.map((f) => (
                <button key={f.label} role="tab" aria-selected={filter === f.key} onClick={() => setFilter(f.key)}
                  className={cn('rounded-md px-2.5 py-1 text-xs', filter === f.key ? 'bg-ink-750 text-fg' : 'text-fg-muted hover:text-fg')}>{f.label}</button>
              ))}
            </div>
          }
        >
          {incidents.isPending ? <div className="space-y-2 p-5"><Skeleton className="h-12" /><Skeleton className="h-12" /></div>
            : incidents.isError ? <div className="p-5"><ErrorNotice error={incidents.error} /></div>
            : incidents.data.items.length === 0 ? (
              <EmptyState icon={Siren} title={filter === 'active' ? 'No active incidents' : 'No incidents'}>
                Open an incident from one or more alerts to coordinate the response, collect evidence and write the report.
              </EmptyState>
            ) : (
              <ul className="divide-y divide-line">
                {incidents.data.items.map((i) => (
                  <li key={i.id}>
                    <Link to={`/org/${orgId}/incidents/${i.id}`} className="flex items-center gap-3 px-5 py-3 hover:bg-ink-850/60">
                      <SeverityBadge severity={i.severity} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm text-fg"><span className="mr-2 font-mono text-xs text-fg-subtle">{i.reference}</span>{i.title}</p>
                        <p className="mt-0.5 text-xs text-fg-subtle">
                          {i.alert_count} alert{i.alert_count === 1 ? '' : 's'} · {i.assignee_name ? `assigned to ${i.assignee_name}` : 'unassigned'} · opened {relativeTime(i.opened_at)}
                          {i.pending_actions > 0 && <span className="text-medium"> · {i.pending_actions} action{i.pending_actions === 1 ? '' : 's'} pending</span>}
                        </p>
                      </div>
                      <IncidentStatusPill status={i.status} />
                      <ChevronRight className="size-4 shrink-0 text-fg-subtle" aria-hidden />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
        </Panel>

        <Panel title="Recent actions" description="Every response action, newest first">
          {recent.isPending ? <Skeleton className="h-24" /> : !recent.data?.items.length
            ? <p className="text-sm text-fg-subtle">No response actions yet.</p>
            : <ul className="space-y-2.5">{recent.data.items.map((a) => <ActionRow key={a.id} action={a} showIncident />)}</ul>}
        </Panel>
      </div>

      {creating && <NewIncidentDialog onClose={() => setCreating(false)} />}
      {proposing && <ProposeActionDialog onClose={() => setProposing(false)} />}
    </div>
  )
}

export function NewIncidentDialog({ onClose, presetAlert }: { onClose: () => void; presetAlert?: Alert }) {
  const { orgId, can } = useOrg()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [title, setTitle] = useState(presetAlert?.title ?? '')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [summary, setSummary] = useState('')
  const [selected, setSelected] = useState<Set<string>>(new Set(presetAlert ? [presetAlert.id] : []))
  const alerts = useQuery({
    queryKey: [...qk.alerts(orgId), 'open-for-incident'],
    queryFn: () => api<Alert[]>(`/organizations/${orgId}/alerts`, { query: { status: 'open', limit: 50 } }),
    enabled: can('alerts:read'),
  })
  const create = useMutation({
    mutationFn: () => api<IncidentDetail>(`/organizations/${orgId}/incidents`, {
      method: 'POST', body: { title: title.trim(), severity: severity || undefined, summary: summary.trim() || undefined, alert_ids: [...selected] },
    }),
    onSuccess: (inc) => {
      void queryClient.invalidateQueries({ queryKey: ['incidents', orgId] })
      void queryClient.invalidateQueries({ queryKey: ['alerts', orgId] })
      navigate(`/org/${orgId}/incidents/${inc.id}`)
    },
  })
  const toggle = (id: string) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n })
  const options = [...(alerts.data ?? []), ...(presetAlert && !alerts.data?.some((a) => a.id === presetAlert.id) ? [presetAlert] : [])]

  return (
    <Dialog open onClose={onClose} size="lg" title="New incident" description="Linked alerts are acknowledged; the incident severity defaults to the highest of them.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }} className="space-y-4">
        <Field label="Title">{({ id }) => <Input id={id} required minLength={3} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ransomware on the finance file share" />}</Field>
        <div className="grid gap-3 sm:grid-cols-[180px_1fr]">
          <Field label="Severity">
            {({ id }) => (
              <Select id={id} value={severity} onChange={(e) => setSeverity(e.target.value as Severity | '')}>
                <option value="">From alerts</option>
                {(['critical', 'high', 'medium', 'low'] as const).map((s) => <option key={s} value={s}>{s}</option>)}
              </Select>
            )}
          </Field>
          <Field label="Summary (optional)">{({ id }) => <Input id={id} value={summary} onChange={(e) => setSummary(e.target.value)} />}</Field>
        </div>
        <fieldset>
          <legend className="mb-1.5 text-[13px] font-medium text-fg-muted">Open alerts to link</legend>
          <div className="max-h-56 space-y-1 overflow-y-auto rounded-lg border border-line p-1.5">
            {alerts.isPending ? <Skeleton className="h-8" /> : options.length === 0 ? <p className="px-2 py-1.5 text-xs text-fg-subtle">No open alerts.</p> : options.map((a) => (
              <label key={a.id} className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm hover:bg-ink-800">
                <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} className="accent-[var(--color-accent)]" />
                <SeverityBadge severity={a.severity} />
                <span className="min-w-0 flex-1 truncate text-fg">{a.title}</span>
              </label>
            ))}
          </div>
        </fieldset>
        {create.isError && <ErrorNotice error={create.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={create.isPending} disabled={title.trim().length < 3}>Open incident</Button>
        </div>
      </form>
    </Dialog>
  )
}

