import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  ArrowRight,
  CircleCheck,
  CircleDashed,
  Database,
  MonitorSmartphone,
  Plus,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Siren,
  TriangleAlert,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

import { useCurrentUser } from '@/auth/AuthContext'
import { BorderBeam } from '@/components/magic/BorderBeam'
import { RiskGauge } from '@/components/magic/RiskGauge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton, StatusDot } from '@/components/ui/Feedback'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/StatusBadges'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime, titleCase } from '@/lib/format'
import type { Alert, BrainRun, DashboardSummary, Page, SystemHealth } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'
import { AnalyzeButton, levelStyle, PriorityBadge, RiskBadge } from '@/pages/brain/shared'
import { useRealtime } from '@/realtime/RealtimeProvider'

import { DeviceHealthBar, KpiTile, SeverityBars } from './widgets'

const NetworkActivityChart = lazy(() => import('./NetworkActivityChart'))

const LEVEL_COLOR: Record<string, string> = {
  critical: 'var(--color-critical)',
  high: 'var(--color-high)',
  medium: 'var(--color-medium)',
  low: 'var(--color-low)',
  info: 'var(--color-ok)',
}

function useNow(intervalMs = 15_000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return now
}

function greeting(hour: number): string {
  return hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening'
}

export function CommandCenterPage() {
  const { orgId, can } = useOrg()
  const now = useNow()
  const summary = useQuery({
    queryKey: qk.dashboard(orgId),
    queryFn: () => api<DashboardSummary>(`/organizations/${orgId}/dashboard/summary`),
    refetchInterval: 30_000,
  })
  const d = summary.data

  return (
    <div className="space-y-5">
      <Hero updatedAt={d ? summary.dataUpdatedAt : null} now={now} refreshing={summary.isFetching} onRefresh={() => void summary.refetch()} />

      {summary.isError && <ErrorNotice error={summary.error} />}

      {!d ? (
        <DashboardSkeleton />
      ) : (
        <>
          {d.simulated_records_excluded > 0 && (
            <div className="flex items-center gap-2 rounded-lg border border-medium/25 bg-medium/[0.06] px-3 py-2 text-xs text-medium">
              <TriangleAlert className="size-3.5" aria-hidden />
              {d.simulated_records_excluded} simulated records exist in this organization and are excluded from every metric below.
            </div>
          )}

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 lg:gap-4">
            <KpiTile label="Enrolled devices" value={d.devices_total} icon={MonitorSmartphone} sub={d.devices_total ? `${d.devices_by_status.find((s) => s.key === 'online')?.count ?? 0} online` : 'No devices enrolled yet'} />
            <KpiTile label="Active security events" value={d.active_events} icon={Activity} sub={`${d.events_last_24h} in the last 24 h`} />
            <KpiTile label="Open incidents" value={d.open_incidents} icon={Siren} sub={d.open_incidents ? 'Requires response' : 'No open incidents'} tone="critical" />
            <KpiTile label="Critical alerts" value={d.critical_alerts} icon={ShieldAlert} sub={d.critical_alerts ? 'Open or acknowledged' : 'None open'} tone="critical" />
          </div>

          <GettingStarted summary={d} />

          <div className="grid gap-4 lg:grid-cols-3 lg:gap-5">
            <NeedsAttention summary={d} className="lg:col-span-2" />
            <Panel title="Device health" description={d.device_health_avg !== null ? `Average health score ${d.device_health_avg}/100` : 'Status of enrolled devices'}>
              {d.devices_total === 0 ? (
                <EmptyState icon={MonitorSmartphone} title="No enrolled devices" action={<Link to={`/org/${orgId}/devices`} className="text-xs text-accent hover:underline">Enroll a device →</Link>}>
                  Install the local security agent on an authorized machine.
                </EmptyState>
              ) : (
                <DeviceHealthBar data={d.devices_by_status} total={d.devices_total} />
              )}
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-3 lg:gap-5">
            <Panel className="lg:col-span-2" title="Recent activity" description="Latest security events from agents and analysts" actions={can('events:read') ? <Link to={`/org/${orgId}/events`} className="text-xs text-accent hover:underline">View all</Link> : undefined}>
              {d.recent_events.length === 0 ? (
                <EmptyState icon={Activity} title="No events yet">Events stream in live from enrolled agents.</EmptyState>
              ) : (
                <ul className="-my-1 divide-y divide-line">
                  {d.recent_events.map((e) => (
                    <li key={e.id} className="flex items-center gap-2.5 py-2 text-sm">
                      <SeverityBadge severity={e.severity} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-fg">{e.title}</span>
                        <span className="text-xs text-fg-subtle">{e.device_name ?? titleCase(e.category)} · {relativeTime(e.occurred_at, now)}{e.occurrence_count > 1 ? ` · ×${e.occurrence_count}` : ''}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <SystemHealthPanel system={d.system} />
          </div>

          {d.network_activity_24h.some((b) => b.count > 0) && (
            <Panel title="Network activity" description="Network-category events per hour · last 24 hours">
              <Suspense fallback={<Skeleton className="h-52" />}>
                <NetworkActivityChart data={d.network_activity_24h} />
              </Suspense>
            </Panel>
          )}
        </>
      )}
    </div>
  )
}

/** Greeting, the organization's latest Security Brain posture and the three most useful actions. */
function Hero({ updatedAt, now, refreshing, onRefresh }: { updatedAt: number | null; now: number; refreshing: boolean; onRefresh: () => void }) {
  const { orgId, membership, can } = useOrg()
  const user = useCurrentUser()
  const posture = useQuery({
    queryKey: qk.brainRuns(orgId, { subject_type: 'organization', limit: 1 }),
    queryFn: () => api<Page<BrainRun>>(`/organizations/${orgId}/brain/runs`, { query: { subject_type: 'organization', limit: 1 } }),
    enabled: can('brain:read'),
  })
  const run = posture.data?.items[0]
  const firstName = user?.full_name?.split(' ')[0]
  return (
    <section className="panel relative overflow-hidden p-5 sm:p-7">
      <div className="dot-pattern pointer-events-none absolute inset-0" aria-hidden />
      <div className="pointer-events-none absolute -right-24 -top-24 size-72 rounded-full bg-violet/15 blur-3xl" aria-hidden />
      <BorderBeam />
      <div className="relative flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
        <div className="min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-[0.16em] text-accent/90">Command Center · {membership.organization.name}</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-fg sm:text-3xl">
            {greeting(new Date(now).getHours())}{firstName ? <>, <span className="brand-text">{firstName}</span></> : null}
          </h1>
          <p className="mt-2 max-w-xl text-sm text-fg-muted">Your live security posture. Every number is computed from this organization's own records — nothing is estimated or simulated.</p>
          <div className="mt-5 flex flex-wrap items-center gap-2">
            {can('brain:run') && <AnalyzeButton subjectType="organization" label="Analyze my security" variant="primary" size="md" />}
            {can('events:ingest') && <Link to={`/org/${orgId}/events`}><Button size="md" icon={<Plus className="size-4" />}>Report event</Button></Link>}
            {can('devices:manage') && <Link to={`/org/${orgId}/devices`}><Button size="md" variant="ghost" icon={<MonitorSmartphone className="size-4" />}>Add device</Button></Link>}
          </div>
          {updatedAt !== null && (
            <p className="mt-4 flex items-center gap-2 text-xs text-fg-subtle" aria-live="polite">
              <StatusDot tone="ok" pulse /> Updated {relativeTime(new Date(updatedAt).toISOString(), now)}
              <button onClick={onRefresh} disabled={refreshing} className="inline-flex items-center gap-1 rounded px-1 text-fg-muted hover:text-fg disabled:opacity-50" aria-label="Refresh">
                <RefreshCw className={cn('size-3', refreshing && 'animate-spin')} aria-hidden /> Refresh
              </button>
            </p>
          )}
        </div>
        {can('brain:read') && (
          <div className="flex shrink-0 items-center gap-4">
            <RiskGauge value={run?.risk_score ?? 0} color={run ? LEVEL_COLOR[run.risk_level ?? 'info'] ?? LEVEL_COLOR.info! : 'var(--color-ink-600)'} label="Organization risk score">
              <div>
                <p className="tabular text-3xl font-semibold text-fg">{run?.risk_score ?? '—'}</p>
                <p className="text-[11px] uppercase tracking-wider text-fg-subtle">risk</p>
              </div>
            </RiskGauge>
            <div className="max-w-[11rem] text-sm">
              {run ? (
                <>
                  <span className={cn('rounded-md border px-2 py-0.5 text-xs font-semibold uppercase', levelStyle(run.risk_level).cls)}>{levelStyle(run.risk_level).label}</span>
                  <p className="mt-2 text-xs text-fg-muted">Analysed {relativeTime(run.created_at, now)} · {run.coverage}% data coverage</p>
                  <Link to={`/org/${orgId}/brain/runs/${run.id}`} className="mt-2 inline-flex items-center gap-1 text-xs text-accent hover:underline">See why <ArrowRight className="size-3" aria-hidden /></Link>
                </>
              ) : (
                <p className="text-xs text-fg-muted">{posture.isPending ? 'Loading…' : 'Not analysed yet. Run the Security Brain to score your organization.'}</p>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  )
}

function NeedsAttention({ summary, className }: { summary: DashboardSummary; className?: string }) {
  const { orgId, can } = useOrg()
  const alerts = useQuery({
    queryKey: [...qk.alerts(orgId), 'dashboard'],
    queryFn: () => api<Alert[]>(`/organizations/${orgId}/alerts`, { query: { status: 'open', limit: 5 } }),
    enabled: can('alerts:read'),
  })
  const quiet = summary.open_alerts_by_severity.every((s) => s.count === 0)
  return (
    <Panel className={className} title="Needs attention" description="Open alerts, triaged automatically by the Security Brain"
      actions={can('events:read') ? <Link to={`/org/${orgId}/events`} className="text-xs text-accent hover:underline">Open events</Link> : undefined}>
      {quiet ? (
        <EmptyState icon={ShieldCheck} title="No open alerts">All clear. Detection rules raise alerts for high/critical events and brute-force patterns.</EmptyState>
      ) : (
        <div className="grid gap-5 md:grid-cols-[200px_1fr] [&>*]:min-w-0">
          <SeverityBars data={summary.open_alerts_by_severity} />
          <ul className="-my-1 divide-y divide-line">
            {(alerts.data ?? []).map((a) => (
              <li key={a.id} className="flex items-center gap-2.5 py-2 text-sm">
                <SeverityBadge severity={a.severity} />
                <span className="min-w-0 flex-1 truncate text-fg">{a.title}</span>
                {a.triage && (
                  <Link to={`/org/${orgId}/brain/runs/${a.triage.run_id}`} className="inline-flex shrink-0 items-center gap-1.5 hover:opacity-80" title="Open the Security Brain triage">
                    <PriorityBadge priority={a.triage.priority} />
                    <RiskBadge level={a.triage.risk_level} score={a.triage.risk_score} />
                  </Link>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  )
}

function HealthRow({ icon: Icon, label, value, tone }: { icon: LucideIcon; label: string; value: ReactNode; tone: 'ok' | 'warn' | 'critical' | 'idle' }) {
  return (
    <li className="flex items-center justify-between gap-3 py-2 text-sm">
      <span className="flex items-center gap-2.5 text-fg-muted">
        <Icon className="size-4 text-fg-subtle" aria-hidden />
        {label}
      </span>
      <span className="flex items-center gap-2 text-right text-fg">
        {value}
        <StatusDot tone={tone} />
      </span>
    </li>
  )
}

const RLS_LABEL: Record<string, { text: string; tone: 'ok' | 'warn' | 'idle' }> = {
  enforced: { text: 'Enforced', tone: 'ok' },
  bypassed_by_role: { text: 'Bypassed by DB role', tone: 'warn' },
  not_supported: { text: 'N/A (SQLite dev)', tone: 'idle' },
  unknown: { text: 'Unknown', tone: 'warn' },
}

const LIVE_LABEL = {
  live: { text: 'Connected', tone: 'ok' },
  connecting: { text: 'Connecting', tone: 'warn' },
  reconnecting: { text: 'Reconnecting', tone: 'warn' },
  offline: { text: 'Not connected', tone: 'idle' },
} as const

export function SystemHealthPanel({ system }: { system: SystemHealth }) {
  const rls = RLS_LABEL[system.database.row_level_security] ?? RLS_LABEL.unknown!
  const live = LIVE_LABEL[useRealtime().status]
  return (
    <Panel title="System health" description={`API v${system.version} · ${system.environment}`}>
      <ul className="-my-2 divide-y divide-line">
        <HealthRow icon={Server} label="API" value="Operational" tone="ok" />
        <HealthRow
          icon={Database}
          label={`Database (${system.database.engine})`}
          value={system.database.status === 'ok' ? <span className="tabular">{system.database.latency_ms} ms</span> : 'Unavailable'}
          tone={system.database.status === 'ok' ? 'ok' : 'critical'}
        />
        <HealthRow icon={ShieldCheck} label="Row-Level Security" value={rls.text} tone={rls.tone} />
        <HealthRow icon={Zap} label="Realtime stream" value={live.text} tone={live.tone} />
      </ul>
    </Panel>
  )
}

function GettingStarted({ summary }: { summary: DashboardSummary }) {
  const { orgId, can } = useOrg()
  const steps = [
    { done: true, label: 'Create your organization', to: null as string | null },
    { done: summary.members > 1, label: 'Add your team', to: can('members:read') ? `/org/${orgId}/members` : null },
    { done: summary.devices_total > 0, label: 'Enroll a device', to: can('devices:read') ? `/org/${orgId}/devices` : null },
    { done: summary.recent_investigations.length > 0, label: 'Check a suspicious link', to: `/org/${orgId}/phishing` },
  ]
  const completed = steps.filter((s) => s.done).length
  if (completed === steps.length) return null
  return (
    <section className="panel flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:gap-5" aria-label="Getting started">
      <div className="shrink-0">
        <p className="text-sm font-medium text-fg">Getting started</p>
        <p className="text-xs text-fg-subtle">{completed} of {steps.length} complete</p>
      </div>
      <ol className="flex flex-1 flex-wrap gap-2">
        {steps.map((s) => {
          const body = (
            <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs', s.done ? 'border-ok/25 bg-ok/[0.06] text-ok' : 'border-line-strong text-fg-muted hover:border-accent/40 hover:text-fg')}>
              {s.done ? <CircleCheck className="size-3.5" aria-label="Done" /> : <CircleDashed className="size-3.5" aria-label="Not done" />}
              {s.label}
            </span>
          )
          return <li key={s.label}>{s.to && !s.done ? <Link to={s.to}>{body}</Link> : body}</li>
        })}
      </ol>
    </section>
  )
}

function DashboardSkeleton() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading dashboard">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 lg:gap-4">
        {Array.from({ length: 4 }, (_, i) => (
          <div key={i} className="panel space-y-3 p-5">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-8 w-14" />
            <Skeleton className="h-3 w-32" />
          </div>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        {Array.from({ length: 3 }, (_, i) => (
          <div key={i} className="panel h-56 p-5">
            <Skeleton className="h-3 w-40" />
          </div>
        ))}
      </div>
    </div>
  )
}
