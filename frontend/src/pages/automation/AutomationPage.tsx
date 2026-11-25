import { useQuery } from '@tanstack/react-query'
import { OctagonPause, Plus, TriangleAlert, Webhook as WebhookIcon } from 'lucide-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { ErrorNotice, Skeleton, StatusDot } from '@/components/ui/Feedback'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import type { AutomationCatalog, AutomationOverview, AutomationRun, Delivery, Recipe, Webhook, WebhookSecret, Workflow, WorkflowSecret } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { ActivityTab } from './ActivityTab'
import { SecretDialog, hookUrl } from './shared'
import { WebhookDialog, WebhooksTab } from './WebhooksTab'
import { WorkflowBuilder } from './WorkflowBuilder'
import { WorkflowsTab } from './WorkflowsTab'

type Tab = 'workflows' | 'activity' | 'webhooks'
type Page<T> = { items: T[]; total: number }

export function AutomationPage() {
  const { orgId, can } = useOrg()
  const [params, setParams] = useSearchParams()
  const tab = (['workflows', 'activity', 'webhooks'].includes(params.get('tab') ?? '') ? params.get('tab') : 'workflows') as Tab
  const setTab = (t: Tab) => setParams(t === 'workflows' ? {} : { tab: t }, { replace: true })
  const [limit, setLimit] = useState(25)
  const [builder, setBuilder] = useState<{ workflow?: Workflow; recipe?: Recipe } | null>(null)
  const [addingHook, setAddingHook] = useState(false)
  const [secret, setSecret] = useState<{ title: string; secret: string; url?: string } | null>(null)

  const base = `/organizations/${orgId}/automation`
  const overview = useQuery({ queryKey: qk.automationOverview(orgId), queryFn: () => api<AutomationOverview>(`${base}/overview`), refetchInterval: 30_000 })
  const catalog = useQuery({ queryKey: qk.automationCatalog(orgId), queryFn: () => api<AutomationCatalog>(`${base}/catalog`), staleTime: Infinity })
  const workflows = useQuery({ queryKey: qk.workflows(orgId), queryFn: () => api<Workflow[]>(`${base}/workflows`) })
  const runs = useQuery({ queryKey: qk.runs(orgId, limit), queryFn: () => api<Page<AutomationRun>>(`${base}/runs`, { query: { limit } }), refetchInterval: 30_000 })
  const hooks = useQuery({ queryKey: qk.webhooks(orgId), queryFn: () => api<Webhook[]>(`${base}/webhooks`) })
  const deliveries = useQuery({ queryKey: qk.deliveries(orgId), queryFn: () => api<Page<Delivery>>(`${base}/deliveries`, { query: { limit: 25 } }), refetchInterval: 30_000 })

  const manage = can('integrations:manage')
  const o = overview.data
  const waiting = o?.awaiting_approval ?? 0
  const loading = catalog.isPending || workflows.isPending || hooks.isPending
  const failed = catalog.error ?? workflows.error ?? hooks.error

  const onSaved = (result: Workflow | WorkflowSecret) => {
    setBuilder(null)
    if ('secret' in result) setSecret({ title: `“${result.workflow.name}” is ready`, secret: result.secret, url: hookUrl(result.hook_path) })
  }
  const onHookCreated = (s: WebhookSecret) => setSecret({ title: `Webhook “${s.webhook.name}” added`, secret: s.secret })

  return (
    <div>
      <PageHeader eyebrow="SENTINEL X · Respond" title="Automation"
        description="Let SENTINEL X do the routine work: tell the team, send alerts to n8n or chat, and prepare incidents and blocks. Anything that changes your defences waits for a person to approve it."
        actions={manage && <>
          <Button variant="ghost" icon={<WebhookIcon className="size-4" />} onClick={() => setAddingHook(true)}>Add webhook</Button>
          <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setBuilder({})} disabled={!catalog.data}>New workflow</Button>
        </>}
      />

      {o?.emergency_stop && (
        <div className="mb-4 flex items-center gap-3 rounded-xl border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-[#ff8f93]">
          <OctagonPause className="size-5 shrink-0" aria-hidden />
          Emergency stop is on: automation is paused — new runs are skipped and webhooks wait until it is released in Incident Response.
        </div>
      )}
      {o?.signing_key === 'ephemeral' && (
        <div className="mb-4 flex items-center gap-3 rounded-xl border border-medium/40 bg-medium/10 px-4 py-3 text-sm text-medium">
          <TriangleAlert className="size-5 shrink-0" aria-hidden />
          No AUTOMATION_SIGNING_KEY or JWT_SECRET is set, so webhook secrets change whenever the server restarts. Set one before connecting real tools.
        </div>
      )}

      {o && (
        <div className="mb-5 flex flex-wrap items-center gap-2 text-sm">
          <Chip tone={o.enabled ? 'ok' : 'idle'}>{o.enabled} of {o.workflows} workflow{o.workflows === 1 ? '' : 's'} on</Chip>
          {waiting > 0 && <Chip tone="warn" pulse onClick={() => setTab('activity')}>{waiting} waiting for approval</Chip>}
          <Chip tone={o.failed_today ? 'critical' : 'idle'}>{o.runs_today} run{o.runs_today === 1 ? '' : 's'} today{o.failed_today ? ` · ${o.failed_today} failed` : ''}</Chip>
          {o.deliveries_failed > 0 && <Chip tone="critical" onClick={() => setTab('webhooks')}>{o.deliveries_failed} webhook deliver{o.deliveries_failed === 1 ? 'y' : 'ies'} failed</Chip>}
          {!o.delivery_enabled && <Chip tone="warn">Deliveries switched off on this server</Chip>}
        </div>
      )}

      <div role="tablist" aria-label="Automation" className="mb-5 inline-flex max-w-full gap-1 overflow-x-auto rounded-lg border border-line bg-ink-900/60 p-0.5">
        {([['workflows', 'Workflows', workflows.data?.length], ['activity', 'Activity', waiting || undefined], ['webhooks', 'Webhooks', hooks.data?.length]] as const).map(([key, label, count]) => (
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
            className={cn('flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors', tab === key ? 'bg-ink-750 text-fg' : 'text-fg-muted hover:text-fg')}>
            {label}
            {!!count && <span className={cn('rounded-full px-1.5 text-[11px] tabular', key === 'activity' ? 'bg-accent text-white' : 'bg-ink-700 text-fg-muted')}>{count}</span>}
          </button>
        ))}
      </div>

      {failed ? <ErrorNotice error={failed} />
        : loading ? <div className="grid gap-4 lg:grid-cols-2">{[0, 1].map((i) => <Skeleton key={i} className="h-44" />)}</div>
        : tab === 'workflows' ? (
          <WorkflowsTab workflows={workflows.data ?? []} recipes={catalog.data?.recipes ?? []}
            onEdit={(w) => setBuilder({ workflow: w })} onUse={(r) => setBuilder({ recipe: r })} />
        ) : tab === 'activity' ? (
          runs.isError ? <ErrorNotice error={runs.error} />
            : <ActivityTab runs={runs.data?.items ?? []} total={runs.data?.total ?? 0} onMore={() => setLimit((l) => Math.min(l + 25, 100))} />
        ) : (
          <WebhooksTab hooks={hooks.data ?? []} deliveries={deliveries.data?.items ?? []} privateAllowed={!!o?.private_targets_allowed} onAdd={() => setAddingHook(true)} />
        )}

      {builder && catalog.data && (
        <WorkflowBuilder catalog={catalog.data} webhooks={hooks.data ?? []} initial={builder}
          onClose={() => setBuilder(null)} onSaved={onSaved} onAddWebhook={() => setAddingHook(true)} />
      )}
      {addingHook && <WebhookDialog privateAllowed={!!o?.private_targets_allowed} onClose={() => setAddingHook(false)} onCreated={onHookCreated} />}
      {secret && <SecretDialog title={secret.title} secret={secret.secret} url={secret.url} onClose={() => setSecret(null)} />}
    </div>
  )
}

function Chip({ tone, pulse, onClick, children }: { tone: 'ok' | 'warn' | 'critical' | 'idle'; pulse?: boolean; onClick?: () => void; children: React.ReactNode }) {
  const cls = cn('flex items-center gap-2 rounded-full border px-3 py-1 text-xs',
    tone === 'ok' ? 'border-ok/30 bg-ok/10 text-ok' : tone === 'warn' ? 'border-accent/40 bg-accent-soft text-fg' : tone === 'critical' ? 'border-critical/40 bg-critical/10 text-[#ff8f93]' : 'border-line text-fg-muted')
  const body = <><StatusDot tone={tone} pulse={pulse} />{children}</>
  return onClick ? <button type="button" onClick={onClick} className={cn(cls, 'hover:brightness-110')}>{body}</button> : <span className={cls}>{body}</span>
}
