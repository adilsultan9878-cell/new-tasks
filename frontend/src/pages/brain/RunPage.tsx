import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, CircleDashed, Download, Lock, ShieldCheck, Wrench } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/StatusBadges'
import { api, downloadFile } from '@/lib/api'
import { cn } from '@/lib/cn'
import { dateTime, relativeTime } from '@/lib/format'
import type { BrainDecision, BrainFactor, BrainRecommendation, BrainRunDetail, BrainTraceEntry } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'
import { ProposeActionDialog } from '@/pages/soc/shared'

import { AGENT_TITLE, AnalyzeButton, levelStyle, PriorityBadge, ScoreMeter, SUBJECT_LABEL } from './shared'

const URGENCY: Record<BrainRecommendation['urgency'], { label: string; cls: string }> = {
  now: { label: 'Now', cls: 'border-critical/40 bg-critical/10 text-[#ff8f93]' },
  soon: { label: 'Soon', cls: 'border-medium/30 bg-medium/10 text-medium' },
  later: { label: 'Later', cls: 'border-line-strong bg-ink-750 text-fg-muted' },
}

export function RunPage() {
  const { runId = '' } = useParams()
  const { orgId } = useOrg()
  const run = useQuery({
    queryKey: qk.brainRun(orgId, runId),
    queryFn: () => api<BrainRunDetail>(`/organizations/${orgId}/brain/runs/${runId}`),
  })
  const back = <Link to={`/org/${orgId}/brain`} className="inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg"><ArrowLeft className="size-3.5" /> Security Brain</Link>

  if (run.isError) return <div className="space-y-4">{back}<ErrorNotice error={run.error} /></div>
  if (!run.data) return <div className="space-y-4">{back}<Skeleton className="h-40" /><Skeleton className="h-64" /></div>
  return <RunView run={run.data} back={back} />
}

export function RunView({ run, back }: { run: BrainRunDetail; back?: ReactNode }) {
  const { orgId, can } = useOrg()
  const [proposal, setProposal] = useState<BrainRecommendation['proposal']>(null)
  const [downloading, setDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState<unknown>(null)
  const subjectLink = run.subject_type === 'alert' ? `/org/${orgId}/events` : run.subject_type === 'device' ? `/org/${orgId}/devices` : null
  const findings = run.decisions.filter((d) => d.decision_type === 'finding')
  const anyAi = run.decisions.some((d) => d.is_ai_generated)

  const download = async () => {
    setDownloading(true)
    setDownloadError(null)
    try {
      await downloadFile(`/organizations/${orgId}/brain/runs/${run.id}/report`, `sentinel-x-${run.subject_type}-report.md`)
    } catch (e) {
      setDownloadError(e)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div>
      {back && <div className="mb-3">{back}</div>}
      <PageHeader
        eyebrow={`Security Brain · ${SUBJECT_LABEL[run.subject_type] ?? run.subject_type}`}
        title={run.subject_label ?? 'Analysis'}
        description={<>
          {run.trigger === 'alert' ? 'Automatic triage when the alert was raised' : 'Run by an analyst'} · <span title={dateTime(run.created_at)}>{relativeTime(run.created_at)}</span>
          {subjectLink && <> · <Link to={subjectLink} className="text-accent hover:underline">open {run.subject_type}s</Link></>}
        </>}
        actions={<>
          <Button size="sm" icon={<Download className="size-3.5" />} loading={downloading} onClick={() => void download()}>Report (.md)</Button>
          <AnalyzeButton subjectType={run.subject_type} subjectId={run.subject_type === 'organization' ? undefined : run.subject_id ?? undefined} label="Run again" />
        </>}
      />
      {downloadError !== null && <div className="mb-4"><ErrorNotice error={downloadError} /></div>}

      <div className="mb-5 flex items-start gap-2.5 rounded-xl border border-line bg-ink-900/50 px-4 py-3 text-xs text-fg-muted">
        <Lock className="mt-0.5 size-3.5 shrink-0 text-accent" aria-hidden />
        <p>
          <span className="font-medium text-fg">Deterministic engine{run.engine_version ? ` (${run.engine_version})` : ''} — {anyAi ? 'includes AI-generated text' : 'no AI model'}.</span>{' '}
          Every point below comes from a published weight and your organization's own data; agents used read-only tools only. Recommendations are advice — nothing was executed.
        </p>
      </div>

      <section className="mb-5 grid gap-5 rounded-xl border border-line bg-ink-900/60 p-5 md:grid-cols-[260px_1fr]">
        <div>
          <div className="flex items-baseline gap-2">
            <span className="tabular text-4xl font-semibold text-fg">{run.risk_score ?? '—'}</span>
            <span className="text-sm text-fg-subtle">/100</span>
          </div>
          <div className="mt-2 flex items-center gap-2">
            <span className={cn('rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide', levelStyle(run.risk_level).cls)}>{levelStyle(run.risk_level).label}</span>
            <PriorityBadge priority={run.priority} />
          </div>
          <div className="mt-3"><ScoreMeter score={run.risk_score ?? 0} level={run.risk_level} /></div>
          <p className="mt-3 text-xs text-fg-muted" title="Share of the scoring model (in points) that had input data">
            Data coverage <span className="tabular font-medium text-fg">{run.coverage ?? 0}%</span>
            {(run.coverage ?? 0) < 100 && <span className="block text-fg-subtle">Factors without data score 0 — the risk is a lower bound.</span>}
          </p>
        </div>
        <div className="min-w-0">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-fg-muted">Summary</h2>
          <p className="mt-1.5 text-sm text-fg">{run.summary}</p>
          <div className="mt-4 flex flex-wrap gap-1.5">
            {run.agents.map((a) => <Badge key={a} tone="accent">{AGENT_TITLE[a] ?? a}</Badge>)}
            {run.lookback_days && <Badge>{run.lookback_days}-day look-back</Badge>}
          </div>
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel title="Risk factors" description="Weighted model — each factor can add up to its maximum points">
          <ul className="space-y-3">{run.factors.map((f) => <FactorRow key={f.key} factor={f} />)}</ul>
        </Panel>
        <Panel title="Recommendations" description={`${run.recommendations.length} from the playbook · advice only, nothing executed`}>
          {run.recommendations.length === 0 ? <p className="text-sm text-fg-subtle">No action recommended.</p> : (
            <ol className="space-y-2.5">
              {run.recommendations.map((r, i) => (
                <li key={`${r.code}-${i}`} className="rounded-lg border border-line bg-ink-900/50 px-3 py-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={cn('rounded border px-1.5 py-px text-[10.5px] font-semibold uppercase leading-none', URGENCY[r.urgency].cls)}>{URGENCY[r.urgency].label}</span>
                    {r.changes_system && <Badge tone="warn" className="gap-1"><Wrench className="size-3" aria-hidden /> changes a system · needs approval</Badge>}
                    <span className="ml-auto text-[11px] text-fg-subtle">{AGENT_TITLE[r.agent] ?? r.agent}</span>
                  </div>
                  <p className="mt-1.5 text-sm text-fg">{r.text}</p>
                  <p className="mt-1 text-xs text-fg-subtle">Because: {r.because}</p>
                  {r.proposal && can('responses:propose') && (
                    <Button size="sm" className="mt-2" icon={<ShieldCheck className="size-3.5" />} onClick={() => setProposal(r.proposal ?? null)}>Propose this action</Button>
                  )}
                </li>
              ))}
            </ol>
          )}
        </Panel>
      </div>

      <Panel className="mt-5" title="Findings by agent" description={`${findings.length} finding${findings.length === 1 ? '' : 's'}`}>
        <div className="grid gap-5 lg:grid-cols-2">
          {run.agents.map((agent) => <AgentFindings key={agent} agent={agent} findings={findings.filter((f) => f.agent_name === agent)} />)}
        </div>
      </Panel>

      <Panel className="mt-5" title="Tool calls" description="Every read-only tool call the agents made, in order" flush>
        <TraceTable trace={run.trace} />
      </Panel>
      {proposal && <ProposeActionDialog runId={run.id} preset={proposal} onClose={() => setProposal(null)} />}
    </div>
  )
}

function FactorRow({ factor: f }: { factor: BrainFactor }) {
  const pct = f.max_points ? (f.points / f.max_points) * 100 : 0
  return (
    <li>
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span className="text-fg">{f.label} <span className="text-[11px] text-fg-subtle">· {AGENT_TITLE[f.agent] ?? f.agent}</span></span>
        {f.has_data
          ? <span className="tabular shrink-0 text-xs text-fg-muted"><span className="font-semibold text-fg">{f.points}</span>/{f.max_points}</span>
          : <span className="inline-flex shrink-0 items-center gap-1 text-xs text-fg-subtle"><CircleDashed className="size-3" aria-hidden /> no data · /{f.max_points}</span>}
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-ink-750">
        <div className={cn('h-full rounded-full', f.has_data ? (pct >= 75 ? 'bg-critical' : pct >= 40 ? 'bg-medium' : 'bg-accent') : 'bg-transparent')} style={{ width: `${f.has_data ? Math.max(pct, f.points ? 3 : 0) : 0}%` }} />
      </div>
      <p className="mt-1 text-xs text-fg-subtle">{f.evidence}</p>
    </li>
  )
}

function AgentFindings({ agent, findings }: { agent: string; findings: BrainDecision[] }) {
  return (
    <section>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-fg-muted">{AGENT_TITLE[agent] ?? agent}</h3>
      {findings.length === 0 ? <p className="rounded-lg border border-dashed border-line px-3 py-2 text-xs text-fg-subtle">Nothing notable.</p> : (
        <ul className="space-y-2">
          {findings.map((f) => (
            <li key={f.id} className="rounded-lg border border-line bg-ink-900/50 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity ?? 'info'} />
                <span className="text-sm font-medium text-fg">{f.summary}</span>
              </div>
              {f.rationale && <p className="mt-1 text-xs text-fg-muted">{f.rationale}</p>}
              {f.evidence_refs.length > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {f.evidence_refs.map((e) => (
                    <span key={`${e.type}:${e.id}`} className="max-w-full truncate rounded border border-line-strong bg-ink-800 px-1.5 py-px font-mono text-[10.5px] text-fg-subtle" title={`${e.type} ${e.id}`}>
                      {e.type}: {e.label || e.id.slice(0, 8)}
                    </span>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function TraceTable({ trace }: { trace: BrainTraceEntry[] }) {
  return (
    <div className="relative overflow-x-auto">
      <table className="w-full min-w-[640px] text-xs">
        <thead><tr className="border-b border-line text-left text-fg-subtle">
          <th className="px-5 py-2 font-medium">#</th><th className="px-3 py-2 font-medium">Agent</th><th className="px-3 py-2 font-medium">Tool</th>
          <th className="px-3 py-2 font-medium">Arguments</th><th className="px-3 py-2 text-right font-medium">Rows</th><th className="px-5 py-2 text-right font-medium">ms</th>
        </tr></thead>
        <tbody className="divide-y divide-line">
          {trace.map((t) => (
            <tr key={t.seq}>
              <td className="tabular px-5 py-1.5 text-fg-subtle">{t.seq}</td>
              <td className="px-3 py-1.5 text-fg-muted">{AGENT_TITLE[t.agent] ?? t.agent}</td>
              <td className="px-3 py-1.5 font-mono text-fg">{t.tool}</td>
              <td className="max-w-[320px] truncate px-3 py-1.5 font-mono text-fg-subtle" title={JSON.stringify(t.args)}>{JSON.stringify(t.args)}</td>
              <td className="tabular px-3 py-1.5 text-right text-fg-muted">{t.rows}</td>
              <td className="tabular px-5 py-1.5 text-right text-fg-subtle">{t.duration_ms}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
