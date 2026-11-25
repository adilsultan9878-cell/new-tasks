import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, Clock3, History, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { dateTime, relativeTime } from '@/lib/format'
import type { AutomationRun } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { SimulatedBadge } from '@/pages/aegis/shared'

import { RunBadge, StepStatusIcon } from './shared'

function ApprovalCard({ run }: { run: AutomationRun }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const decide = useMutation({
    mutationFn: (approve: boolean) => api<AutomationRun>(`/organizations/${orgId}/automation/runs/${run.id}/decision`, { method: 'POST', body: { approve } }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['automation', orgId] })
      void queryClient.invalidateQueries({ queryKey: ['incidents', orgId] })
    },
  })
  return (
    <li className="rounded-xl border border-accent/30 bg-accent-soft/40 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <ShieldCheck className="size-4 text-accent" aria-hidden />
        <span className="font-medium text-fg">{run.workflow_name}</span>
        {run.is_simulated && <SimulatedBadge />}
        <span className="ml-auto inline-flex items-center gap-1 text-xs text-fg-subtle"><Clock3 className="size-3" aria-hidden />expires {relativeTime(run.expires_at)}</span>
      </div>
      <p className="mt-1 text-sm text-fg-muted">{run.trigger_label}{run.requested_by_name && ` · started by ${run.requested_by_name}`}</p>
      <ul className="mt-2 space-y-1">
        {run.steps.map((s, i) => <li key={i} className="flex items-center gap-2 text-sm text-fg"><StepStatusIcon status="waiting" />{s.title}</li>)}
      </ul>
      {can('responses:approve') ? (
        <div className="mt-3 flex gap-2">
          <Button size="sm" variant="primary" loading={decide.isPending && decide.variables === true} onClick={() => decide.mutate(true)}>Approve and run</Button>
          <Button size="sm" variant="ghost" loading={decide.isPending && decide.variables === false} onClick={() => decide.mutate(false)}>Reject</Button>
        </div>
      ) : <p className="mt-3 text-xs text-fg-subtle">An owner or administrator decides.</p>}
      {decide.isError && <div className="mt-2"><ErrorNotice error={decide.error} /></div>}
    </li>
  )
}

function RunRow({ run }: { run: AutomationRun }) {
  const { orgId } = useOrg()
  const [open, setOpen] = useState(false)
  const done = run.steps.filter((s) => s.status === 'succeeded').length
  return (
    <li className="border-b border-line last:border-0">
      <button type="button" onClick={() => setOpen((v) => !v)} aria-expanded={open}
        className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 text-left hover:bg-ink-800/40 sm:px-5">
        <RunBadge status={run.status} />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-fg">{run.workflow_name}</span>
          <span className="block truncate text-xs text-fg-subtle">{run.trigger_label}</span>
        </span>
        {run.is_simulated && <SimulatedBadge />}
        <span className="text-xs text-fg-subtle tabular">{done}/{run.steps.length} steps</span>
        <span className="text-xs text-fg-subtle" title={dateTime(run.created_at)}>{relativeTime(run.created_at)}</span>
        <ChevronDown className={cn('size-4 text-fg-subtle transition-transform', open && 'rotate-180')} aria-hidden />
      </button>
      {open && (
        <div className="space-y-2 px-4 pb-4 sm:px-5">
          <ol className="space-y-1.5">
            {run.steps.map((s, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <StepStatusIcon status={s.status} />
                <span className="min-w-0">
                  <span className="text-fg">{s.title}</span>
                  {s.detail && <span className="block text-xs text-fg-subtle">{s.detail}</span>}
                  {s.link && <Link to={`/org/${orgId}${s.link}`} className="text-xs text-accent hover:underline">Open</Link>}
                </span>
              </li>
            ))}
          </ol>
          {run.error && <p className="text-xs text-critical">{run.error}</p>}
          {run.decided_by_name && (
            <p className="text-xs text-fg-subtle">
              {run.status === 'rejected' ? 'Rejected' : 'Approved'} by {run.decided_by_name} {relativeTime(run.decided_at)}
              {run.decision_comment && ` — ${run.decision_comment}`}
            </p>
          )}
        </div>
      )}
    </li>
  )
}

export function ActivityTab({ runs, total, onMore }: { runs: AutomationRun[]; total: number; onMore: () => void }) {
  const waiting = runs.filter((r) => r.status === 'awaiting_approval')
  const history = runs.filter((r) => r.status !== 'awaiting_approval')
  return (
    <div className="space-y-5">
      {waiting.length > 0 && (
        <Panel title={`Waiting for approval (${waiting.length})`} description="Nothing in these runs happens until someone approves. Unanswered requests expire.">
          <ul className="space-y-3">{waiting.map((r) => <ApprovalCard key={r.id} run={r} />)}</ul>
        </Panel>
      )}
      <Panel title="Run history" description="Every run with what each step did" flush>
        {history.length === 0
          ? <EmptyState icon={History} title="No runs yet">Runs appear here as soon as a workflow starts.</EmptyState>
          : <ul>{history.map((r) => <RunRow key={r.id} run={r} />)}</ul>}
        {runs.length < total && <div className="border-t border-line p-3 text-center"><Button size="sm" variant="ghost" onClick={onMore}>Show more</Button></div>}
      </Panel>
    </div>
  )
}
