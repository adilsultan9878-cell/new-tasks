import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CircleCheck, Database, FlaskConical, Plus, ShieldCheck, Trash2, Upload, X } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Input, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime } from '@/lib/format'
import type { LabCondition, LabDataset, LabExperiment, LabField, LabOp, LabReproduction, LabRule } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

const FIELDS: { key: LabField; label: string }[] = [
  { key: 'event_type', label: 'Event type' },
  { key: 'category', label: 'Category' },
  { key: 'severity', label: 'Severity' },
  { key: 'title', label: 'Title' },
  { key: 'source', label: 'Source' },
  { key: 'device', label: 'Device' },
]
const OPS: Record<LabOp, string> = {
  eq: 'is', ne: 'is not', in: 'is one of', contains: 'contains', not_contains: 'does not contain', startswith: 'starts with',
  gte: 'is at least', lte: 'is at most',
}
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
const opsFor = (field: LabField): LabOp[] => (field === 'severity' ? ['gte', 'lte', 'eq', 'in'] : ['eq', 'ne', 'contains', 'not_contains', 'startswith', 'in'])
const pct = (v: number | null) => (v === null ? '—' : `${Math.round(v * 100)}%`)

export function LabPage() {
  const { orgId, can } = useOrg()
  const base = `/organizations/${orgId}/lab`
  const datasets = useQuery({ queryKey: qk.labDatasets(orgId), queryFn: () => api<LabDataset[]>(`${base}/datasets`) })
  const experiments = useQuery({ queryKey: qk.labExperiments(orgId), queryFn: () => api<LabExperiment[]>(`${base}/experiments`) })
  const [selected, setSelected] = useState<string | null>(null)
  const [creating, setCreating] = useState<'events' | 'upload' | null>(null)
  const [latest, setLatest] = useState<LabExperiment | null>(null)
  const dataset = datasets.data?.find((d) => d.id === selected) ?? datasets.data?.[0] ?? null
  const run = can('lab:run')

  return (
    <div>
      <PageHeader eyebrow="NEXUS ZERO · Investigate" title="Research Lab"
        description="Try a detection rule on past events before you trust it. The lab works on frozen copies, scores the rule against what your analysts decided, and never changes live alerts."
        actions={run && <>
          <Button variant="ghost" icon={<Upload className="size-4" />} onClick={() => setCreating('upload')}>Upload lab data</Button>
          <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setCreating('events')}>New dataset</Button>
        </>}
      />

      {datasets.isPending ? <Skeleton className="h-40" />
        : datasets.isError ? <ErrorNotice error={datasets.error} />
        : datasets.data.length === 0 ? (
          <Panel>
            <EmptyState icon={FlaskConical} title="Start with a dataset"
              action={run ? <div className="flex flex-wrap justify-center gap-2"><Button variant="primary" onClick={() => setCreating('events')}>Use my recent events</Button><Button variant="ghost" onClick={() => setCreating('upload')}>Upload lab data</Button></div> : undefined}>
              A dataset is a frozen copy of past events. Events your analysts confirmed are labelled “real”, alerts closed as false positives “benign” — that is how a rule gets a score.
            </EmptyState>
          </Panel>
        ) : (
          <div className="grid gap-5 xl:grid-cols-[22rem_1fr]">
            <Panel className="self-start" title="1. Dataset" description="Frozen copies — the SHA-256 pins every experiment to its data" flush>
              <ul className="divide-y divide-line" aria-label="Datasets">
                {datasets.data.map((d) => <DatasetRow key={d.id} dataset={d} active={d.id === dataset?.id} onSelect={() => { setSelected(d.id); setLatest(null) }} />)}
              </ul>
            </Panel>
            <div className="space-y-5">
              {dataset && run && <RuleBuilder dataset={dataset} onResult={setLatest} />}
              {latest && <ResultCard experiment={latest} />}
            </div>
          </div>
        )}

      <Panel className="mt-5" title="Experiments" description="Every backtest with the exact rule, data hash and engine version — re-check that it reproduces" flush>
        {experiments.isPending ? <div className="p-5"><Skeleton className="h-20" /></div>
          : experiments.isError ? <div className="p-5"><ErrorNotice error={experiments.error} /></div>
          : <ExperimentTable experiments={experiments.data} onOpen={setLatest} />}
      </Panel>

      {creating && <DatasetDialog kind={creating} onClose={() => setCreating(null)} onCreated={(d) => { setSelected(d.id); setLatest(null) }} />}
    </div>
  )
}

function LabelChips({ counts }: { counts: LabDataset['label_counts'] }) {
  return (
    <span className="flex flex-wrap gap-1.5">
      <Badge tone="critical">{counts.malicious} real</Badge>
      <Badge tone="ok">{counts.benign} benign</Badge>
      <Badge>{counts.unlabelled} unlabelled</Badge>
    </span>
  )
}

function DatasetRow({ dataset: d, active, onSelect }: { dataset: LabDataset; active: boolean; onSelect: () => void }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const remove = useMutation({
    mutationFn: () => api<void>(`/organizations/${orgId}/lab/datasets/${d.id}`, { method: 'DELETE' }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['lab', orgId] }),
  })
  return (
    <li className={cn('relative', active && 'bg-accent-soft/40')}>
      {active && <span className="absolute inset-y-0 left-0 w-0.5 bg-accent" aria-hidden />}
      <button type="button" onClick={onSelect} aria-pressed={active} className="block w-full px-4 py-3 text-left hover:bg-ink-800/40 sm:px-5">
        <span className="flex items-center gap-2">
          <Database className={cn('size-4 shrink-0', active ? 'text-accent' : 'text-fg-subtle')} aria-hidden />
          <span className="truncate font-medium text-fg">{d.name}</span>
          {d.includes_simulated && <Badge tone="warn">incl. simulated</Badge>}
        </span>
        <span className="mt-1 block text-xs text-fg-subtle">
          {d.row_count} events · {d.source === 'upload' ? 'uploaded' : `last ${String(d.params.days)} days`} · {relativeTime(d.created_at)}
        </span>
        <span className="mt-2 block"><LabelChips counts={d.label_counts} /></span>
        <span className="mt-2 block font-mono text-[11px] text-fg-subtle" title={d.sha256}>sha256 {d.sha256.slice(0, 16)}…</span>
      </button>
      {can('lab:run') && (
        <button type="button" aria-label={`Delete ${d.name}`} className="absolute right-3 top-3 rounded p-1 text-fg-subtle hover:bg-ink-750 hover:text-critical"
          onClick={() => { if (window.confirm(`Delete “${d.name}” and its ${d.experiments} experiment(s)?`)) remove.mutate() }}>
          <Trash2 className="size-3.5" />
        </button>
      )}
    </li>
  )
}

const BLANK: LabCondition = { field: 'event_type', op: 'eq', value: '' }

function RuleBuilder({ dataset, onResult }: { dataset: LabDataset; onResult: (e: LabExperiment) => void }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [mode, setMode] = useState<LabRule['mode']>('all')
  const [conditions, setConditions] = useState<LabCondition[]>([{ field: 'event_type', op: 'eq', value: 'auth.failed_login' }])
  const [useThreshold, setUseThreshold] = useState(true)
  const [count, setCount] = useState(5)
  const [minutes, setMinutes] = useState(10)
  const runIt = useMutation({
    mutationFn: () => api<LabExperiment>(`/organizations/${orgId}/lab/experiments`, {
      method: 'POST',
      body: {
        dataset_id: dataset.id,
        name: name.trim() || 'Untitled rule',
        rule: {
          mode,
          conditions: conditions.map((c) => ({ ...c, value: c.op === 'in' ? String(c.value).split(',').map((v) => v.trim()).filter(Boolean) : c.value })),
          threshold: useThreshold ? { count, within_minutes: minutes, per_device: true } : null,
        },
      },
    }),
    onSuccess: (e) => { void queryClient.invalidateQueries({ queryKey: ['lab', orgId] }); onResult(e) },
  })
  const set = (i: number, patch: Partial<LabCondition>) => setConditions((all) => all.map((c, j) => {
    if (j !== i) return c
    const next = { ...c, ...patch }
    if (patch.field === 'severity') {
      next.op = 'gte'
      next.value = 'high'
    } else if (patch.field) {
      if (!opsFor(patch.field).includes(next.op)) next.op = 'eq'
      if (c.field === 'severity') next.value = ''
    }
    return next
  }))
  const valid = conditions.every((c) => String(c.value).trim().length > 0)

  return (
    <Panel title="2. Rule" description={`Backtest on “${dataset.name}” (${dataset.row_count} events). Nothing is executed — a rule is just conditions.`}>
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); runIt.mutate() }} className="space-y-4">
        <div className="flex flex-wrap items-center gap-2 text-sm text-fg-muted">
          Alert on events that match
          <Select aria-label="Match mode" className="w-auto" value={mode} onChange={(e) => setMode(e.target.value as LabRule['mode'])}>
            <option value="all">all</option>
            <option value="any">any</option>
          </Select>
          of these conditions:
        </div>
        <ol className="space-y-2">
          {conditions.map((c, i) => (
            <li key={i} className="grid gap-2 rounded-xl border border-line bg-ink-900/50 p-2 sm:grid-cols-[9rem_9rem_1fr_auto]">
              <Select aria-label={`Field ${i + 1}`} value={c.field} onChange={(e) => set(i, { field: e.target.value as LabField })}>
                {FIELDS.map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}
              </Select>
              <Select aria-label={`Operator ${i + 1}`} value={c.op} onChange={(e) => set(i, { op: e.target.value as LabOp })}>
                {opsFor(c.field).map((op) => <option key={op} value={op}>{OPS[op]}</option>)}
              </Select>
              {c.field === 'severity' && c.op !== 'in' ? (
                <Select aria-label={`Value ${i + 1}`} value={String(c.value)} onChange={(e) => set(i, { value: e.target.value })}>
                  {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                </Select>
              ) : (
                <Input aria-label={`Value ${i + 1}`} value={String(c.value)} maxLength={200} placeholder={c.op === 'in' ? 'comma, separated, values' : 'value'}
                  onChange={(e) => set(i, { value: e.target.value })} />
              )}
              <button type="button" disabled={conditions.length === 1} aria-label={`Remove condition ${i + 1}`} onClick={() => setConditions((all) => all.filter((_, j) => j !== i))}
                className="grid size-10 place-items-center rounded-lg text-fg-subtle hover:bg-ink-750 hover:text-critical disabled:opacity-30">
                <X className="size-4" />
              </button>
            </li>
          ))}
        </ol>
        {conditions.length < 20 && <Button type="button" size="sm" variant="ghost" icon={<Plus className="size-3.5" />} onClick={() => setConditions((all) => [...all, { ...BLANK }])}>Add condition</Button>}

        <label className="flex flex-wrap items-center gap-2 rounded-xl border border-line p-3 text-sm text-fg-muted">
          <input type="checkbox" checked={useThreshold} onChange={(e) => setUseThreshold(e.target.checked)} className="accent-[var(--color-accent)]" />
          Only alert when it happens at least
          <Input aria-label="Count" type="number" min={2} max={1000} className="h-9 w-20" value={count} disabled={!useThreshold} onChange={(e) => setCount(Number(e.target.value))} />
          times within
          <Input aria-label="Minutes" type="number" min={1} max={1440} className="h-9 w-20" value={minutes} disabled={!useThreshold} onChange={(e) => setMinutes(Number(e.target.value))} />
          minutes on the same device
        </label>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1"><Field label="Experiment name">{({ id }) => <Input id={id} value={name} maxLength={120} placeholder="e.g. Brute force: 5 failures in 10 min" onChange={(e) => setName(e.target.value)} />}</Field></div>
          <Button type="submit" variant="primary" icon={<FlaskConical className="size-4" />} loading={runIt.isPending} disabled={!valid}>Run backtest</Button>
        </div>
        {runIt.isError && <ErrorNotice error={runIt.error} />}
      </form>
    </Panel>
  )
}

function Meter({ label, help, value, baseline }: { label: string; help: string; value: number | null; baseline: number | null }) {
  const better = value !== null && baseline !== null && value > baseline
  return (
    <div className="rounded-xl border border-line bg-ink-900/50 p-4">
      <p className="text-xs text-fg-subtle">{label}</p>
      <p className="tabular mt-1 text-3xl font-semibold tracking-tight text-fg">{pct(value)}</p>
      <div className="mt-3 space-y-1.5" aria-hidden>
        <div className="h-1.5 rounded-full bg-ink-700"><div className="brand-gradient h-1.5 rounded-full" style={{ width: `${(value ?? 0) * 100}%` }} /></div>
        <div className="h-1.5 rounded-full bg-ink-700"><div className="h-1.5 rounded-full bg-fg-subtle/60" style={{ width: `${(baseline ?? 0) * 100}%` }} /></div>
      </div>
      <p className="mt-2 text-xs text-fg-subtle">Built-in rules: {pct(baseline)} {better && <span className="text-ok">· better</span>}</p>
      <p className="mt-1 text-[11px] text-fg-subtle">{help}</p>
    </div>
  )
}

function ResultCard({ experiment: e }: { experiment: LabExperiment }) {
  const r = e.results
  const c = r.confusion
  const real = c.tp + c.fn
  return (
    <Panel title={`Result: ${e.name}`} description={`${r.rows} events, ${r.labelled} with an analyst verdict · engine ${e.engine_version}`}>
      <div className="grid gap-3 sm:grid-cols-3">
        <Meter label="Precision" help="Of the alerts it raises, how many were real" value={r.precision} baseline={r.baseline.precision} />
        <Meter label="Recall" help="Of the real attacks, how many it catches" value={r.recall} baseline={r.baseline.recall} />
        <Meter label="F1 score" help="Both together (higher is better)" value={r.f1} baseline={r.baseline.f1} />
      </div>
      <ul className="mt-4 grid gap-2 text-sm sm:grid-cols-2">
        <li className="rounded-lg border border-line px-3 py-2"><span className="text-fg">Caught {c.tp} of {real} real attacks</span></li>
        <li className="rounded-lg border border-line px-3 py-2"><span className="text-fg">{c.fp} false alarm{c.fp === 1 ? '' : 's'}</span> <span className="text-fg-subtle">· built-in: {r.baseline.confusion.fp}</span></li>
        <li className="rounded-lg border border-line px-3 py-2"><span className="text-fg">{r.alerts_per_day} alerts per day</span> <span className="text-fg-subtle">· built-in: {r.baseline.alerts_per_day}</span></li>
        <li className="rounded-lg border border-line px-3 py-2"><span className="text-fg">{r.fired_unlabelled} on events nobody judged yet</span></li>
      </ul>
      <div className="mt-4 grid gap-3 md:grid-cols-3">
        {([['tp', 'Caught', 'text-ok'], ['fn', 'Missed', 'text-critical'], ['fp', 'False alarms', 'text-medium']] as const).map(([k, label, tone]) => (
          <div key={k}>
            <p className={cn('mb-1 text-xs font-medium', tone)}>{label}</p>
            {r.samples[k].length ? (
              <ul className="space-y-1 text-xs text-fg-muted">{r.samples[k].map((s) => <li key={s.id} className="truncate" title={s.title}>{s.title}</li>)}</ul>
            ) : <p className="text-xs text-fg-subtle">None</p>}
          </div>
        ))}
      </div>
    </Panel>
  )
}

function ExperimentTable({ experiments, onOpen }: { experiments: LabExperiment[]; onOpen: (e: LabExperiment) => void }) {
  const { orgId } = useOrg()
  const [checks, setChecks] = useState<Record<string, LabReproduction>>({})
  const check = useMutation({
    mutationFn: (id: string) => api<LabReproduction>(`/organizations/${orgId}/lab/experiments/${id}/reproduce`, { method: 'POST' }),
    onSuccess: (res, id) => setChecks((all) => ({ ...all, [id]: res })),
  })
  if (experiments.length === 0) return <EmptyState icon={FlaskConical} title="No experiments yet">Run a backtest and it shows up here.</EmptyState>
  return (
    <div className="relative overflow-x-auto">
      <table className="w-full min-w-[44rem] text-sm">
        <thead className="text-left text-xs text-fg-subtle">
          <tr className="border-b border-line">
            <th className="px-4 py-2 font-medium sm:px-5">Experiment</th>
            <th className="px-2 py-2 font-medium">Dataset</th>
            <th className="px-2 py-2 text-right font-medium">Precision</th>
            <th className="px-2 py-2 text-right font-medium">Recall</th>
            <th className="px-2 py-2 text-right font-medium">F1</th>
            <th className="px-2 py-2 text-right font-medium">Alerts/day</th>
            <th className="px-4 py-2 sm:px-5"><span className="sr-only">Reproduce</span></th>
          </tr>
        </thead>
        <tbody>
          {experiments.map((e) => {
            const res = checks[e.id]
            return (
              <tr key={e.id} className="border-b border-line last:border-0">
                <td className="px-4 py-2.5 sm:px-5">
                  <button type="button" onClick={() => onOpen(e)} className="text-left font-medium text-fg hover:text-accent">{e.name}</button>
                  <span className="block text-xs text-fg-subtle">{relativeTime(e.created_at)}{e.created_by_name && ` · ${e.created_by_name}`}</span>
                </td>
                <td className="px-2 py-2.5 text-fg-muted">{e.dataset_name ?? '—'}</td>
                <td className="tabular px-2 py-2.5 text-right">{pct(e.results.precision)}</td>
                <td className="tabular px-2 py-2.5 text-right">{pct(e.results.recall)}</td>
                <td className="tabular px-2 py-2.5 text-right font-medium text-fg">{pct(e.results.f1)}</td>
                <td className="tabular px-2 py-2.5 text-right">{e.results.alerts_per_day}</td>
                <td className="px-4 py-2.5 text-right sm:px-5">
                  {res ? (
                    <span className={cn('inline-flex items-center gap-1 text-xs', res.reproduced ? 'text-ok' : 'text-critical')}>
                      {res.reproduced ? <CircleCheck className="size-3.5" aria-hidden /> : <X className="size-3.5" aria-hidden />}{res.reproduced ? 'Reproduced' : 'Differs'}
                    </span>
                  ) : (
                    <Button size="sm" variant="ghost" icon={<ShieldCheck className="size-3.5" />} loading={check.isPending && check.variables === e.id} onClick={() => check.mutate(e.id)}>Re-check</Button>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

const SAMPLE = JSON.stringify([
  { occurred_at: '2026-11-01T09:00:00Z', category: 'auth', event_type: 'auth.failed_login', severity: 'medium', title: 'Failed login for admin', device: 'ws-1', label: 'malicious' },
  { occurred_at: '2026-11-01T11:00:00Z', category: 'auth', event_type: 'auth.failed_login', severity: 'medium', title: 'Typo in password', device: 'ws-2', label: 'benign' },
], null, 2)

function DatasetDialog({ kind, onClose, onCreated }: { kind: 'events' | 'upload'; onClose: () => void; onCreated: (d: LabDataset) => void }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [name, setName] = useState(kind === 'events' ? 'Recent events' : 'Lab data')
  const [days, setDays] = useState(30)
  const [simulated, setSimulated] = useState(false)
  const [text, setText] = useState(SAMPLE)
  const [parseError, setParseError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => {
      if (kind === 'events') {
        return api<LabDataset>(`/organizations/${orgId}/lab/datasets`, { method: 'POST', body: { name: name.trim(), days, include_simulated: simulated } })
      }
      const rows: unknown = JSON.parse(text)
      return api<LabDataset>(`/organizations/${orgId}/lab/datasets/upload`, { method: 'POST', body: { name: name.trim(), rows } })
    },
    onSuccess: (d) => { void queryClient.invalidateQueries({ queryKey: ['lab', orgId] }); onCreated(d); onClose() },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (kind === 'upload') {
      try { JSON.parse(text); setParseError(null) } catch { setParseError('That is not valid JSON.'); return }
    }
    save.mutate()
  }
  return (
    <Dialog open onClose={onClose} size={kind === 'upload' ? 'lg' : 'md'} title={kind === 'events' ? 'New dataset from your events' : 'Upload lab data'}
      description={kind === 'events' ? 'A frozen copy: later events and label changes do not alter it.' : 'Up to 5,000 events as a JSON array. Labels are optional: "malicious" or "benign".'}>
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name">{({ id }) => <Input id={id} required minLength={2} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
        {kind === 'events' ? (
          <>
            <Field label="Events from the last">{({ id }) => (
              <Select id={id} value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {[7, 30, 90, 365].map((d) => <option key={d} value={d}>{d} days</option>)}
              </Select>
            )}</Field>
            <label className="flex items-center gap-2 text-sm text-fg-muted">
              <input type="checkbox" checked={simulated} onChange={(e) => setSimulated(e.target.checked)} className="accent-[var(--color-accent)]" />
              Include simulator data (the dataset is labelled “incl. simulated”)
            </label>
          </>
        ) : (
          <Field label="Events (JSON)" error={parseError ?? undefined}>
            {({ id, invalid }) => (
              <textarea id={id} aria-invalid={invalid || undefined} value={text} onChange={(e) => setText(e.target.value)} rows={12} spellCheck={false}
                className="w-full rounded-lg border border-line-strong bg-ink-850 p-3 font-mono text-xs text-fg focus:border-accent/60 focus:outline-none focus:ring-2 focus:ring-accent/20" />
            )}
          </Field>
        )}
        {save.isError && <ErrorNotice error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>{kind === 'events' ? 'Create dataset' : 'Upload'}</Button>
        </div>
      </form>
    </Dialog>
  )
}
