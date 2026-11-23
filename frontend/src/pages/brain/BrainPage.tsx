import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { BrainCircuit, ChevronRight, Plus } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime } from '@/lib/format'
import type { Alert, BrainActivity, BrainRun, BrainStatus, BrainSubject, Device, Page } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { AGENT_TITLE, AnalyzeButton, PriorityBadge, RiskBadge, SUBJECT_LABEL, useAnalyze } from './shared'

export function useBrainStatus() {
  return useQuery({ queryKey: qk.brainStatus, queryFn: () => api<BrainStatus>('/brain/status'), staleTime: 300_000 })
}

export function BrainPage() {
  const { orgId, can } = useOrg()
  const [filters, setFilters] = useState({ subject_type: '', trigger: '' })
  const [creating, setCreating] = useState(false)
  const status = useBrainStatus()
  const activity = useQuery({ queryKey: qk.brainActivity(orgId), queryFn: () => api<BrainActivity>(`/organizations/${orgId}/brain/activity`) })
  const runs = useQuery({
    queryKey: qk.brainRuns(orgId, filters),
    queryFn: () => api<Page<BrainRun>>(`/organizations/${orgId}/brain/runs`, { query: { ...filters, limit: 50 } }),
    placeholderData: keepPreviousData,
  })

  return (
    <div>
      <PageHeader
        eyebrow="SENTINEL X · Security operations"
        title="Security Brain"
        description="An orchestrator runs specialised agents over an alert, a device or the whole organization. Agents read your data through read-only tools and produce a weighted risk score with evidence and recommendations. No AI model is configured — nothing here is AI-generated."
        actions={can('brain:run') ? <>
          <Button size="sm" icon={<Plus className="size-3.5" />} onClick={() => setCreating(true)}>Analyze device or alert</Button>
          <AnalyzeButton subjectType="organization" label="Analyze organization" variant="primary" />
        </> : undefined}
      />

      <div className="mb-5 grid gap-3 sm:grid-cols-3">
        <Stat label="Analyses" value={activity.data?.runs_total} hint="stored with full evidence" />
        <Stat label="Automatic alert triage" value={activity.data?.runs_by_trigger.alert ?? (activity.data ? 0 : undefined)} hint={status.data ? (status.data.auto_triage ? 'runs on every new alert' : 'disabled (BRAIN_AUTO_TRIAGE=false)') : ''} />
        <Stat label="Run by analysts" value={activity.data?.runs_by_trigger.manual ?? (activity.data ? 0 : undefined)} hint="manual analyses" />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <Panel
          title="Analyses"
          description={runs.data ? `${runs.data.total} total` : undefined}
          flush
          actions={
            <div className="flex flex-wrap gap-2">
              <Select aria-label="Subject type" value={filters.subject_type} onChange={(e) => setFilters((f) => ({ ...f, subject_type: e.target.value }))} className="h-8 w-36 text-xs">
                <option value="">All subjects</option><option value="alert">Alerts</option><option value="device">Devices</option><option value="organization">Organization</option>
              </Select>
              <Select aria-label="Trigger" value={filters.trigger} onChange={(e) => setFilters((f) => ({ ...f, trigger: e.target.value }))} className="h-8 w-32 text-xs">
                <option value="">Any trigger</option><option value="alert">Automatic</option><option value="manual">Manual</option>
              </Select>
            </div>
          }
        >
          {runs.isPending ? <div className="space-y-2 p-5"><Skeleton className="h-10" /><Skeleton className="h-10" /></div>
            : runs.isError ? <div className="p-5"><ErrorNotice error={runs.error} /></div>
            : runs.data.items.length === 0 ? (
              <EmptyState icon={BrainCircuit} title="No analyses yet">
                New high/critical alerts are triaged automatically. You can also analyse the organization, a device or an alert.
              </EmptyState>
            ) : (
              <ul className="divide-y divide-line">
                {runs.data.items.map((r) => (
                  <li key={r.id}>
                    <Link to={`/org/${orgId}/brain/runs/${r.id}`} className="flex items-center gap-3 px-5 py-3 hover:bg-ink-850/60">
                      <RiskBadge level={r.risk_level} score={r.risk_score} className="w-[86px] justify-between" />
                      <div className="min-w-0 flex-1">
                        <p className="flex items-center gap-2 truncate text-sm text-fg"><PriorityBadge priority={r.priority} /> <span className="truncate">{r.subject_label}</span></p>
                        <p className="mt-0.5 text-xs text-fg-subtle">
                          {SUBJECT_LABEL[r.subject_type]} · {r.finding_count} finding{r.finding_count === 1 ? '' : 's'} · {r.recommendation_count} recommendation{r.recommendation_count === 1 ? '' : 's'} · coverage {r.coverage}%
                        </p>
                      </div>
                      <div className="hidden shrink-0 text-right sm:block">
                        <Badge tone={r.trigger === 'alert' ? 'accent' : 'neutral'}>{r.trigger === 'alert' ? 'automatic' : 'manual'}</Badge>
                        <p className="mt-1 text-[11px] text-fg-subtle">{relativeTime(r.created_at)}</p>
                      </div>
                      <ChevronRight className="size-4 shrink-0 text-fg-subtle" aria-hidden />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
        </Panel>

        <div className="space-y-5">
          <Panel title="Engine">
            {status.isError ? <ErrorNotice error={status.error} /> : !status.data ? <Skeleton className="h-24" /> : (
              <div className="space-y-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="accent">deterministic</Badge>
                  <Badge>AI provider: {status.data.engine.provider}</Badge>
                  <span className="font-mono text-[11px] text-fg-subtle">{status.data.engine.engine_version}</span>
                </div>
                <p className="text-xs text-fg-muted">{status.data.engine.description}</p>
                <dl className="grid grid-cols-2 gap-2 text-xs">
                  <dt className="text-fg-subtle">Auto-triage</dt><dd className="text-fg">{status.data.auto_triage ? 'on — every new alert' : 'off'}</dd>
                  <dt className="text-fg-subtle">Look-back window</dt><dd className="text-fg">{status.data.lookback_days} days</dd>
                  <dt className="text-fg-subtle">Agents</dt><dd className="text-fg"><Link to={`/org/${orgId}/agents`} className="text-accent hover:underline">{status.data.agents.length} · Agent Center</Link></dd>
                </dl>
              </div>
            )}
          </Panel>
          {status.data && <ScoringModels status={status.data} />}
        </div>
      </div>

      {creating && <NewAnalysisDialog onClose={() => setCreating(false)} />}
    </div>
  )
}

function Stat({ label, value, hint }: { label: string; value: number | undefined; hint: string }) {
  return (
    <div className="rounded-xl border border-line bg-ink-900/60 px-4 py-3">
      <p className="text-xs text-fg-subtle">{label}</p>
      {value === undefined ? <Skeleton className="mt-1 h-7 w-12" /> : <p className="tabular mt-0.5 text-2xl font-semibold text-fg">{value}</p>}
      <p className="mt-0.5 truncate text-[11px] text-fg-subtle">{hint}</p>
    </div>
  )
}

function ScoringModels({ status }: { status: BrainStatus }) {
  const [subject, setSubject] = useState<BrainSubject>('alert')
  const model = status.models[subject] ?? []
  return (
    <Panel title="Scoring model" description="Published weights — every model totals 100 points">
      <div className="mb-3 flex gap-1 rounded-lg border border-line bg-ink-900/60 p-0.5" role="tablist" aria-label="Scoring model">
        {(['alert', 'device', 'organization'] as const).map((s) => (
          <button key={s} role="tab" aria-selected={subject === s} onClick={() => setSubject(s)}
            className={cn('flex-1 rounded-md px-2 py-1 text-xs capitalize', subject === s ? 'bg-ink-750 text-fg' : 'text-fg-muted hover:text-fg')}>
            {s}
          </button>
        ))}
      </div>
      <ul className="space-y-2.5">
        {model.map((f) => (
          <li key={f.key}>
            <div className="flex items-baseline justify-between gap-2 text-sm">
              <span className="text-fg">{f.label}</span>
              <span className="tabular text-xs text-fg-muted">{f.max_points} pts</span>
            </div>
            <p className="text-xs text-fg-subtle">{f.description} <span className="text-fg-muted">({AGENT_TITLE[f.agent] ?? f.agent})</span></p>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-[11px] text-fg-subtle">Levels: critical 75+, high 50+, medium 25+, low 10+. Alert priority: P1 critical … P4 low.</p>
    </Panel>
  )
}

function NewAnalysisDialog({ onClose }: { onClose: () => void }) {
  const { orgId, can } = useOrg()
  const [kind, setKind] = useState<'device' | 'alert'>(can('devices:read') ? 'device' : 'alert')
  const [subjectId, setSubjectId] = useState('')
  const analyze = useAnalyze()
  const devices = useQuery({ queryKey: qk.devices(orgId), queryFn: () => api<Device[]>(`/organizations/${orgId}/devices`), enabled: can('devices:read') })
  const alerts = useQuery({
    queryKey: [...qk.alerts(orgId), 'brain-picker'],
    queryFn: () => api<Alert[]>(`/organizations/${orgId}/alerts`, { query: { limit: 50 } }),
    enabled: can('alerts:read'),
  })
  const options = kind === 'device'
    ? (devices.data ?? []).filter((d) => d.enrollment_status !== 'pending').map((d) => ({ id: d.id, label: `${d.name}${d.ip_address ? ` · ${d.ip_address}` : ''}` }))
    : (alerts.data ?? []).map((a) => ({ id: a.id, label: `[${a.severity}] ${a.title}` }))
  const loading = kind === 'device' ? devices.isPending : alerts.isPending

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (subjectId) analyze.mutate({ subject_type: kind, subject_id: subjectId })
  }

  return (
    <Dialog open onClose={onClose} title="New analysis" description="The Brain runs its agents on the selected subject and stores the result with its evidence.">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Subject">
          {({ id }) => (
            <Select id={id} value={kind} onChange={(e) => { setKind(e.target.value as 'device' | 'alert'); setSubjectId('') }}>
              {can('devices:read') && <option value="device">Device — risk assessment</option>}
              {can('alerts:read') && <option value="alert">Alert — triage</option>}
            </Select>
          )}
        </Field>
        <Field label={kind === 'device' ? 'Device' : 'Alert'} hint={!loading && options.length === 0 ? `No ${kind}s yet.` : undefined}>
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy} value={subjectId} onChange={(e) => setSubjectId(e.target.value)} disabled={loading || options.length === 0}>
              <option value="">{loading ? 'Loading…' : `Select a ${kind}`}</option>
              {options.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
            </Select>
          )}
        </Field>
        {analyze.isError && <ErrorNotice error={analyze.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={analyze.isPending} disabled={!subjectId} icon={<BrainCircuit className="size-4" />}>Analyze</Button>
        </div>
      </form>
    </Dialog>
  )
}
