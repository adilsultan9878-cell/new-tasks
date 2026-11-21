import { CheckCircle2, CircleDashed, CircleSlash, ExternalLink, Info, ShieldAlert, TriangleAlert } from 'lucide-react'
import type { ReactNode } from 'react'

import { SeverityBadge } from '@/components/ui/StatusBadges'
import { cn } from '@/lib/cn'
import { dateTime } from '@/lib/format'
import type { IntelFinding, InvestigationDetail, SourceCheck, Verdict } from '@/lib/types'

const VERDICT: Record<Verdict, { label: string; cls: string; icon: typeof ShieldAlert }> = {
  malicious: { label: 'Malicious', cls: 'border-critical/40 bg-critical/10 text-[#ff8f93]', icon: ShieldAlert },
  suspicious: { label: 'Suspicious', cls: 'border-medium/40 bg-medium/10 text-medium', icon: TriangleAlert },
  unknown: { label: 'No known threat found', cls: 'border-line-strong bg-ink-800 text-fg-muted', icon: Info },
  benign: { label: 'Benign', cls: 'border-ok/30 bg-ok/10 text-ok', icon: CheckCircle2 },
}

/** Unknown/unexpected verdict strings from the API fall back to the neutral badge (never crash). */
export function verdictStyle(verdict: Verdict | string) {
  return VERDICT[verdict as Verdict] ?? VERDICT.unknown
}

export function VerdictBadge({ verdict, size = 'sm' }: { verdict: Verdict | string; size?: 'sm' | 'lg' }) {
  const v = verdictStyle(verdict)
  const Icon = v.icon
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-md border font-medium', v.cls, size === 'lg' ? 'px-2.5 py-1 text-sm' : 'px-1.5 py-0.5 text-[11px]')}>
      <Icon className={size === 'lg' ? 'size-4' : 'size-3'} aria-hidden /> {v.label}
    </span>
  )
}

function RiskMeter({ score }: { score: number }) {
  const color = score >= 70 ? 'bg-critical' : score >= 35 ? 'bg-medium' : 'bg-accent'
  return (
    <div className="w-full max-w-xs">
      <div className="mb-1 flex items-baseline justify-between text-xs">
        <span className="text-fg-muted">Risk score</span>
        <span className="tabular text-lg font-semibold text-fg">{score}<span className="text-xs text-fg-subtle">/100</span></span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-ink-750" role="meter" aria-label="Risk score" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100}>
        <div className={cn('h-full rounded-full transition-[width] duration-500', color)} style={{ width: `${score}%` }} />
      </div>
    </div>
  )
}

function FindingList({ title, description, findings, empty }: { title: string; description: string; findings: IntelFinding[]; empty: string }) {
  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wider text-fg-muted">{title}</h3>
      <p className="mb-2 text-xs text-fg-subtle">{description}</p>
      {findings.length === 0 ? <p className="rounded-lg border border-dashed border-line px-3 py-2.5 text-xs text-fg-subtle">{empty}</p> : (
        <ul className="space-y-2">
          {findings.map((f, i) => (
            <li key={`${f.code}-${i}`} className="rounded-lg border border-line bg-ink-900/60 px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <span className="text-sm font-medium text-fg">{f.title}</span>
                {f.score > 0 && <span className="ml-auto font-mono text-[11px] text-fg-subtle">+{f.score}</span>}
              </div>
              <p className="mt-1 text-xs text-fg-muted">{f.detail}</p>
              <p className="mt-1 font-mono text-[10.5px] text-fg-subtle">source: {f.source}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

const CHECK_ICON: Record<SourceCheck['status'], ReactNode> = {
  ok: <CheckCircle2 className="size-3.5 text-ok" aria-label="consulted" />,
  not_configured: <CircleDashed className="size-3.5 text-fg-subtle" aria-label="not configured" />,
  unavailable: <CircleSlash className="size-3.5 text-medium" aria-label="unavailable" />,
  skipped: <CircleDashed className="size-3.5 text-fg-subtle" aria-label="skipped" />,
}

export function InvestigationView({ inv }: { inv: InvestigationDetail }) {
  const findings = inv.verified_findings ?? []
  const intel = findings.filter((f) => f.kind === 'intel' && f.score > 0)
  const checks = findings.filter((f) => f.kind === 'heuristic' && f.score > 0)
  const context = findings.filter((f) => f.kind === 'context' || f.score === 0)
  const sources = inv.details.checks ?? []
  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-4 rounded-xl border border-line bg-ink-900/60 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0 space-y-2">
          <VerdictBadge verdict={inv.verdict} size="lg" />
          <p className="break-all font-mono text-xs text-fg-muted">{inv.subject}</p>
          {inv.summary && <p className="max-w-2xl text-sm text-fg-muted">{inv.summary}</p>}
        </div>
        <RiskMeter score={inv.risk_score ?? 0} />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <FindingList title="Verified intelligence" description="Facts reported by trusted external sources or your watchlist." findings={intel} empty="No intelligence source reported this subject." />
        <FindingList title="Deterministic checks" description="Local, explainable rules — no AI involved." findings={checks} empty="No structural red flags." />
      </div>

      {context.length > 0 && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-fg-muted">Context</h3>
          <ul className="space-y-1 text-sm text-fg-muted">
            {context.map((f, i) => <li key={`${f.code}-${i}`}><span className="text-fg">{f.title}</span> — {f.detail} <span className="font-mono text-[10.5px] text-fg-subtle">({f.source})</span></li>)}
          </ul>
        </section>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-fg-muted">Sources</h3>
          <ul className="divide-y divide-line rounded-lg border border-line">
            {sources.map((c, i) => (
              <li key={`${c.source}-${i}`} className="flex items-center gap-2.5 px-3 py-2 text-xs">
                {CHECK_ICON[c.status]}
                <span className="w-28 shrink-0 font-mono text-fg">{c.source}</span>
                <span className="min-w-0 flex-1 truncate text-fg-muted" title={c.detail}>{c.status === 'ok' ? c.detail : `${c.status.replace('_', ' ')} — ${c.detail}`}</span>
                {c.duration_ms > 0 && <span className="tabular text-fg-subtle">{c.duration_ms} ms</span>}
              </li>
            ))}
            {sources.length === 0 && <li className="px-3 py-2 text-xs text-fg-subtle">Deterministic checks only.</li>}
          </ul>
          <p className="mt-2 text-xs text-fg-subtle">AI assessment: {inv.ai_assessment ?? 'not used — the AI Security Brain arrives in Phase 4 and will be labelled separately.'}</p>
        </section>
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-fg-muted">Timeline</h3>
          <ol className="relative space-y-2 border-l border-line pl-4 text-xs">
            {inv.timeline.map((t, i) => (
              <li key={i} className="relative">
                <span className={cn('absolute -left-[19px] top-1 size-2 rounded-full', t.status === 'ok' ? 'bg-ok' : t.status === 'unavailable' ? 'bg-medium' : 'bg-ink-600')} aria-hidden />
                <span className="text-fg">{t.step}</span>
                {t.detail && <span className="text-fg-subtle"> · {t.detail}</span>}
              </li>
            ))}
          </ol>
          <p className="mt-2 text-[11px] text-fg-subtle">Completed {dateTime(inv.completed_at)}</p>
        </section>
      </div>

      {inv.details.indicators && inv.details.indicators.length > 0 && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-fg-muted">Indicators recorded</h3>
          <div className="flex flex-wrap gap-1.5">
            {inv.details.indicators.map((x) => (
              <span key={`${x.type}:${x.value}`} className="max-w-full truncate rounded-md border border-line-strong bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-fg-muted" title={x.value}>
                {x.type}: {x.value}
              </span>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}

export function SafeExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer nofollow" className="inline-flex items-center gap-1 text-accent hover:underline">
      {children} <ExternalLink className="size-3" aria-hidden />
    </a>
  )
}
