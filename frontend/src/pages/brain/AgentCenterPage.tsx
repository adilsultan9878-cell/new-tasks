import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Bot, ChevronLeft, ChevronRight, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/StatusBadges'
import { api } from '@/lib/api'
import { relativeTime } from '@/lib/format'
import type { BrainActivity, BrainDecisionWithRun, Page } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { useBrainStatus } from './BrainPage'
import { AGENT_TITLE } from './shared'

const PAGE = 25
const TYPE_LABEL: Record<string, string> = { finding: 'Finding', recommend: 'Recommendation', score: 'Score', classify: 'Priority' }

/** Guarantees enforced in code and covered by the backend test-suite (tests/test_brain.py). */
const GUARANTEES = [
  'Read-only tools: agents cannot insert, update or delete anything — a run that leaves pending writes is aborted.',
  'Tenant-scoped: every query filters on your organization, with PostgreSQL row-level security underneath.',
  'No shell, no network: agents cannot run commands or call external services.',
  'Every tool call is traced with its arguments, row count and duration.',
  'Recommendations are advice only; anything that would change a system is flagged for human approval.',
]

export function AgentCenterPage() {
  const { orgId } = useOrg()
  const status = useBrainStatus()
  const activity = useQuery({ queryKey: qk.brainActivity(orgId), queryFn: () => api<BrainActivity>(`/organizations/${orgId}/brain/activity`) })
  const stats = new Map((activity.data?.agents ?? []).map((a) => [a.agent, a]))

  return (
    <div>
      <PageHeader
        eyebrow="SENTINEL X · Security operations"
        title="Agent Center"
        description="The specialised agents behind the Security Brain, the bounded tools each one may use, and every decision they have recorded. All agents are deterministic in this release."
      />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="grid gap-4 md:grid-cols-2">
          {status.isError ? <ErrorNotice error={status.error} />
            : !status.data ? [0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-44" />)
            : status.data.agents.map((agent) => {
              const s = stats.get(agent.name)
              return (
                <article key={agent.name} className="flex flex-col rounded-xl border border-line bg-ink-900/60 p-4">
                  <div className="flex items-start gap-3">
                    <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-accent/25 bg-accent-soft text-accent"><Bot className="size-4" aria-hidden /></span>
                    <div className="min-w-0">
                      <h2 className="text-sm font-semibold text-fg">{agent.title}</h2>
                      <p className="mt-0.5 text-xs text-fg-muted">{agent.description}</p>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1">
                    {agent.subjects.map((sub) => <Badge key={sub} tone="info">{sub}</Badge>)}
                    <Badge tone="ok">deterministic</Badge>
                  </div>
                  <ul className="mt-3 flex flex-wrap gap-1">
                    {agent.tools.map((t) => (
                      <li key={t} className="rounded border border-line-strong bg-ink-800 px-1.5 py-px font-mono text-[10.5px] text-fg-muted"
                        title={status.data.tools.find((x) => x.name === t)?.description}>{t}</li>
                    ))}
                  </ul>
                  <p className="mt-auto pt-3 text-[11px] text-fg-subtle">
                    {s ? <>{s.findings} finding{s.findings === 1 ? '' : 's'} · {s.recommendations} recommendation{s.recommendations === 1 ? '' : 's'}{s.last_decision_at ? ` · last ${relativeTime(s.last_decision_at)}` : ''}</> : activity.isPending ? '…' : 'No activity yet'}
                  </p>
                </article>
              )
            })}
        </div>
        <Panel title={<span className="flex items-center gap-2"><ShieldCheck className="size-4 text-ok" /> Guardrails</span>} description="Enforced in code and by automated tests">
          <ul className="space-y-2.5 text-xs text-fg-muted">
            {GUARANTEES.map((g) => <li key={g} className="flex gap-2"><span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-ok" aria-hidden />{g}</li>)}
          </ul>
        </Panel>
      </div>

      <DecisionHistory />
    </div>
  )
}

function DecisionHistory() {
  const { orgId } = useOrg()
  const [filters, setFilters] = useState({ agent: '', decision_type: '' })
  const [offset, setOffset] = useState(0)
  const params = { ...filters, limit: PAGE, offset }
  const decisions = useQuery({
    queryKey: qk.brainDecisions(orgId, params),
    queryFn: () => api<Page<BrainDecisionWithRun>>(`/organizations/${orgId}/brain/decisions`, { query: params }),
    placeholderData: keepPreviousData,
  })
  const set = (k: keyof typeof filters) => (v: string) => { setFilters((f) => ({ ...f, [k]: v })); setOffset(0) }
  const total = decisions.data?.total ?? 0

  return (
    <Panel
      className="mt-5"
      title="Decision history"
      description={decisions.data ? `${total} decision${total === 1 ? '' : 's'}` : undefined}
      flush
      actions={
        <div className="flex flex-wrap gap-2">
          <Select aria-label="Agent" value={filters.agent} onChange={(e) => set('agent')(e.target.value)} className="h-8 w-44 text-xs">
            <option value="">All agents</option>
            {Object.entries(AGENT_TITLE).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </Select>
          <Select aria-label="Decision type" value={filters.decision_type} onChange={(e) => set('decision_type')(e.target.value)} className="h-8 w-40 text-xs">
            <option value="">All types</option>
            {Object.entries(TYPE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </Select>
        </div>
      }
    >
      {decisions.isPending ? <div className="space-y-2 p-5"><Skeleton className="h-9" /><Skeleton className="h-9" /></div>
        : decisions.isError ? <div className="p-5"><ErrorNotice error={decisions.error} /></div>
        : decisions.data.items.length === 0 ? <EmptyState icon={Bot} title="No decisions yet">Decisions appear here when the Security Brain analyses an alert, a device or the organization.</EmptyState>
        : (
          <>
            <ul className="divide-y divide-line">
              {decisions.data.items.map((d) => (
                <li key={d.id}>
                  <Link to={`/org/${orgId}/brain/runs/${d.agent_run_id}`} className="flex items-start gap-3 px-5 py-2.5 hover:bg-ink-850/60">
                    <span className="mt-0.5 w-28 shrink-0 text-[11px] text-fg-subtle">{TYPE_LABEL[d.decision_type] ?? d.decision_type}</span>
                    <div className="min-w-0 flex-1">
                      <p className="flex flex-wrap items-center gap-2 text-sm text-fg">
                        {d.decision_type === 'finding' && d.severity && <SeverityBadge severity={d.severity} />}
                        <span className="min-w-0">{d.summary}</span>
                      </p>
                      <p className="mt-0.5 truncate text-xs text-fg-subtle">{AGENT_TITLE[d.agent_name ?? ''] ?? d.agent_name} · {d.subject_label}</p>
                    </div>
                    <span className="shrink-0 text-[11px] text-fg-subtle">{relativeTime(d.created_at)}</span>
                  </Link>
                </li>
              ))}
            </ul>
            {total > PAGE && (
              <div className="flex items-center justify-end gap-2 border-t border-line px-5 py-2.5 text-xs text-fg-subtle">
                <span className="tabular">{offset + 1}–{Math.min(offset + PAGE, total)} of {total}</span>
                <Button size="sm" variant="ghost" aria-label="Previous page" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} icon={<ChevronLeft className="size-4" />} />
                <Button size="sm" variant="ghost" aria-label="Next page" disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)} icon={<ChevronRight className="size-4" />} />
              </div>
            )}
          </>
        )}
    </Panel>
  )
}
