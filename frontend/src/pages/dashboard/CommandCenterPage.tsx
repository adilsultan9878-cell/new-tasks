import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  Bot,
  CircleCheck,
  CircleDashed,
  Database,
  FileSearch,
  MonitorSmartphone,
  Network,
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

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton, StatusDot } from '@/components/ui/Feedback'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime, titleCase } from '@/lib/format'
import type { DashboardSummary, SystemHealth } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { DeviceHealthBar, KpiTile, SeverityBars } from './widgets'

const NetworkActivityChart = lazy(() => import('./NetworkActivityChart'))

function useNow(intervalMs = 15_000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(id)
  }, [intervalMs])
  return now
}

export function CommandCenterPage() {
  const { orgId, membership } = useOrg()
  const now = useNow()
  const summary = useQuery({
    queryKey: qk.dashboard(orgId),
    queryFn: () => api<DashboardSummary>(`/organizations/${orgId}/dashboard/summary`),
    refetchInterval: 30_000,
  })
  const d = summary.data

  return (
    <div>
      <PageHeader
        eyebrow="Command Center"
        title={membership.organization.name}
        description="Live security posture for this organization. Every figure is computed from this tenant's own records — nothing is estimated or simulated."
        actions={
          <>
            {d && (
              <span className="flex items-center gap-2 text-xs text-fg-subtle" aria-live="polite">
                <StatusDot tone="ok" pulse />
                Updated {relativeTime(new Date(summary.dataUpdatedAt).toISOString(), now)}
              </span>
            )}
            <Button size="sm" variant="secondary" icon={<RefreshCw className={cn('size-3.5', summary.isFetching && 'animate-spin')} />} onClick={() => void summary.refetch()} disabled={summary.isFetching}>
              Refresh
            </Button>
          </>
        }
      />

      {summary.isError && (
        <div className="mb-6">
          <ErrorNotice error={summary.error} />
        </div>
      )}

      {!d ? (
        <DashboardSkeleton />
      ) : (
        <div className="space-y-4 lg:space-y-5">
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

          <div className="grid gap-4 lg:grid-cols-3 lg:gap-5">
            <Panel title="Threat risk distribution" description="Open alerts by severity">
              {d.open_alerts_by_severity.every((s) => s.count === 0) ? (
                <EmptyState icon={ShieldCheck} title="No open alerts">
                  Alerts are raised by the detection engine once events flow in (Phase 2).
                </EmptyState>
              ) : (
                <SeverityBars data={d.open_alerts_by_severity} />
              )}
            </Panel>

            <Panel title="Device health" description={d.device_health_avg !== null ? `Average health score ${d.device_health_avg}/100` : 'Status of enrolled devices'}>
              {d.devices_total === 0 ? (
                <EmptyState icon={MonitorSmartphone} title="No enrolled devices">
                  Device enrollment and the local security agent arrive in Phase 2.
                </EmptyState>
              ) : (
                <DeviceHealthBar data={d.devices_by_status} total={d.devices_total} />
              )}
            </Panel>

            <SystemHealthPanel system={d.system} />
          </div>

          <div className="grid gap-4 lg:grid-cols-3 lg:gap-5">
            <Panel className="lg:col-span-2" title="Network activity" description="Network-category events per hour · last 24 hours">
              {d.network_activity_24h.every((b) => b.count === 0) ? (
                <EmptyState icon={Network} title="No network events in the last 24 hours">
                  The authorized-scope network monitor ships with NEXUS ZERO (Phase 3).
                </EmptyState>
              ) : (
                <Suspense fallback={<Skeleton className="h-52" />}>
                  <NetworkActivityChart data={d.network_activity_24h} />
                </Suspense>
              )}
            </Panel>
            <GettingStarted summary={d} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2 lg:gap-5">
            <Panel title="Recent investigations" description="Latest NEXUS ZERO investigations">
              {d.recent_investigations.length === 0 ? (
                <EmptyState icon={FileSearch} title="No investigations yet">
                  URL, phishing, hash and IP investigations are part of Phase 3.
                </EmptyState>
              ) : (
                <ul className="divide-y divide-line">
                  {d.recent_investigations.map((i) => (
                    <li key={i.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                      <span className="min-w-0">
                        <span className="block truncate text-fg">{i.title}</span>
                        <span className="text-xs text-fg-subtle">{titleCase(i.subject_type)} · {relativeTime(i.created_at, now)}</span>
                      </span>
                      <Badge tone={i.verdict === 'malicious' ? 'critical' : i.verdict === 'suspicious' ? 'warn' : 'neutral'}>{titleCase(i.verdict)}</Badge>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel title="AI agent activity" description="Specialised agents coordinated by the AI orchestrator">
              {d.recent_agent_runs.length === 0 ? (
                <EmptyState icon={Bot} title="No agent runs yet">
                  The AI orchestrator and specialised agents arrive in Phase 4. Every run will be logged here with its decisions.
                </EmptyState>
              ) : (
                <ul className="divide-y divide-line">
                  {d.recent_agent_runs.map((r) => (
                    <li key={r.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                      <span className="min-w-0">
                        <span className="block truncate text-fg">{titleCase(r.agent_name)}</span>
                        <span className="text-xs text-fg-subtle">{titleCase(r.trigger)} · {relativeTime(r.created_at, now)}</span>
                      </span>
                      <Badge tone={r.status === 'failed' ? 'critical' : r.status === 'succeeded' ? 'ok' : 'neutral'}>{titleCase(r.status)}</Badge>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>
        </div>
      )}
    </div>
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

export function SystemHealthPanel({ system }: { system: SystemHealth }) {
  const rls = RLS_LABEL[system.database.row_level_security] ?? RLS_LABEL.unknown!
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
        <HealthRow icon={Zap} label="Realtime stream" value={<span className="text-fg-subtle">Phase 2</span>} tone="idle" />
      </ul>
    </Panel>
  )
}

function GettingStarted({ summary }: { summary: DashboardSummary }) {
  const { orgId, can } = useOrg()
  const steps = [
    { done: true, label: 'Create your organization', detail: 'Isolated tenant ready', to: null as string | null },
    { done: summary.members > 1, label: 'Add your team', detail: summary.members > 1 ? `${summary.members} members` : 'Assign analyst & viewer roles', to: can('members:read') ? `/org/${orgId}/members` : null },
    { done: summary.devices_total > 0, label: 'Enroll your first device', detail: 'Local agent · Phase 2', to: `/org/${orgId}/m/devices` },
    { done: false, label: 'Run a threat investigation', detail: 'NEXUS ZERO · Phase 3', to: `/org/${orgId}/m/phishing` },
  ]
  const completed = steps.filter((s) => s.done).length
  return (
    <Panel title="Getting started" description={`${completed} of ${steps.length} complete`}>
      <div className="mb-4 h-1 overflow-hidden rounded-full bg-ink-750">
        <div className="h-full rounded-full bg-gradient-to-r from-accent to-electric transition-[width] duration-500" style={{ width: `${(completed / steps.length) * 100}%` }} />
      </div>
      <ol className="space-y-1">
        {steps.map((s) => {
          const body = (
            <span className="flex items-start gap-3 rounded-lg px-2 py-2">
              {s.done ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-ok" aria-label="Done" /> : <CircleDashed className="mt-0.5 size-4 shrink-0 text-fg-subtle" aria-label="Not done" />}
              <span>
                <span className={cn('block text-sm', s.done ? 'text-fg-muted line-through decoration-fg-subtle/50' : 'text-fg')}>{s.label}</span>
                <span className="block text-xs text-fg-subtle">{s.detail}</span>
              </span>
            </span>
          )
          return (
            <li key={s.label}>
              {s.to && !s.done ? (
                <Link to={s.to} className="block rounded-lg hover:bg-ink-800">
                  {body}
                </Link>
              ) : (
                body
              )}
            </li>
          )
        })}
      </ol>
    </Panel>
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
