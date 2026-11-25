import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Bell, CalendarClock, FilePlus2, Link2, Pencil, Play, Send, ShieldBan, Sparkles, Trash2, Webhook as WebhookIcon, Zap } from 'lucide-react'
import { useState } from 'react'

import { SpotlightCard } from '@/components/magic/SpotlightCard'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime } from '@/lib/format'
import type { AutomationRun, Recipe, Workflow, WorkflowSecret } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

import { ApprovalBadge, CopyField, RunBadge, SecretDialog, Switch, hookUrl } from './shared'

const STEP_ICON: Record<string, typeof Bell> = {
  notify: Bell,
  send_webhook: Send,
  create_incident: FilePlus2,
  propose_response: ShieldBan,
  create_event: Zap,
}
const TRIGGER_ICON = { event: Zap, schedule: CalendarClock, manual: Play, webhook: WebhookIcon }

export function RecipeGrid({ recipes, onUse, compact }: { recipes: Recipe[]; onUse: (r: Recipe) => void; compact?: boolean }) {
  const { can } = useOrg()
  return (
    <div className={cn('grid gap-3 sm:grid-cols-2', compact ? 'xl:grid-cols-4' : 'xl:grid-cols-3')}>
      {recipes.map((r) => {
        const Icon = STEP_ICON[r.steps[0]?.type ?? ''] ?? Sparkles
        return (
          <SpotlightCard key={r.key} role="group" aria-label={r.name} className="flex flex-col p-4">
            <span className="mb-3 grid size-9 place-items-center rounded-xl border border-line-strong bg-ink-850 text-accent"><Icon className="size-4" aria-hidden /></span>
            <p className="font-medium text-fg">{r.name}</p>
            <p className="mt-1 flex-1 text-xs text-fg-subtle">{r.description}</p>
            {can('integrations:manage') && (
              <Button size="sm" variant="ghost" className="mt-3 self-start" onClick={() => onUse(r)} icon={<ArrowRight className="size-3.5" />}>Use this</Button>
            )}
          </SpotlightCard>
        )
      })}
    </div>
  )
}

export function WorkflowCard({ workflow: wf, onEdit }: { workflow: Workflow; onEdit: () => void }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const [secret, setSecret] = useState<WorkflowSecret | null>(null)
  const [showHook, setShowHook] = useState(false)
  const refresh = () => void queryClient.invalidateQueries({ queryKey: ['automation', orgId] })
  const base = `/organizations/${orgId}/automation/workflows/${wf.id}`
  const toggle = useMutation({ mutationFn: (enabled: boolean) => api<Workflow>(base, { method: 'PATCH', body: { enabled } }), onSuccess: refresh })
  const run = useMutation({ mutationFn: () => api<AutomationRun>(`${base}/run`, { method: 'POST' }), onSuccess: refresh })
  const remove = useMutation({ mutationFn: () => api<void>(base, { method: 'DELETE' }), onSuccess: refresh })
  const rotate = useMutation({ mutationFn: () => api<WorkflowSecret>(`${base}/rotate-secret`, { method: 'POST' }), onSuccess: (s) => { setSecret(s); refresh() } })
  const manage = can('integrations:manage')
  const TriggerIcon = TRIGGER_ICON[wf.trigger_type]
  const error = toggle.error ?? run.error ?? remove.error ?? rotate.error

  return (
    <article className={cn('panel p-4 transition-opacity sm:p-5', !wf.enabled && 'opacity-75')} aria-label={wf.name}>
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="truncate font-medium text-fg">{wf.name}</h3>
          <p className="mt-0.5 text-xs text-fg-subtle">
            {wf.last_run_at ? `Last run ${relativeTime(wf.last_run_at)}` : 'Never run'}
            {wf.next_run_at && ` · next ${relativeTime(wf.next_run_at)}`}
            {wf.owner_name && ` · runs as ${wf.owner_name}`}
          </p>
        </div>
        {manage
          ? <Switch on={wf.enabled} onChange={(v) => toggle.mutate(v)} disabled={toggle.isPending} label={`${wf.enabled ? 'Turn off' : 'Turn on'} ${wf.name}`} />
          : <span className="text-xs text-fg-subtle">{wf.enabled ? 'On' : 'Off'}</span>}
      </div>

      {/* The workflow as a sentence: trigger → steps */}
      <div className="mt-4 flex flex-wrap items-center gap-1.5">
        <span className="inline-flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent-soft px-2.5 py-1 text-xs text-fg">
          <TriggerIcon className="size-3.5 text-accent" aria-hidden />{wf.trigger_label}
        </span>
        {wf.steps.map((s, i) => {
          const Icon = STEP_ICON[s.type] ?? Sparkles
          return (
            <span key={i} className="inline-flex items-center gap-1.5">
              <ArrowRight className="size-3.5 text-fg-subtle" aria-hidden />
              <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-ink-850 px-2.5 py-1 text-xs text-fg-muted">
                <Icon className="size-3.5" aria-hidden />{s.title}
              </span>
            </span>
          )
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <ApprovalBadge required={wf.requires_approval} />
        {wf.last_status && <RunBadge status={wf.last_status as AutomationRun['status']} />}
        {manage && (
          <span className="ml-auto flex flex-wrap gap-1">
            {(wf.trigger_type === 'manual' || wf.trigger_type === 'schedule') && (
              <Button size="sm" variant="ghost" icon={<Play className="size-3.5" />} loading={run.isPending} disabled={wf.trigger_type === 'manual' && !wf.enabled} onClick={() => run.mutate()}>Run now</Button>
            )}
            {wf.hook_path && <Button size="sm" variant="ghost" icon={<Link2 className="size-3.5" />} onClick={() => setShowHook((v) => !v)}>Connection</Button>}
            <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" />} onClick={onEdit}>Edit</Button>
            <Button size="sm" variant="ghost" icon={<Trash2 className="size-3.5" />} loading={remove.isPending}
              onClick={() => { if (window.confirm(`Delete “${wf.name}”? Its run history is deleted too.`)) remove.mutate() }}>Delete</Button>
          </span>
        )}
      </div>
      {run.data && <p className="mt-2 text-xs text-fg-muted">Started — {run.data.status === 'awaiting_approval' ? 'waiting for an approver (see Activity).' : `finished: ${run.data.status}.`}</p>}
      {showHook && wf.hook_path && (
        <div className="mt-3 space-y-2 rounded-xl border border-line bg-ink-900/50 p-3">
          <CopyField label="POST signed JSON to" value={hookUrl(wf.hook_path)} />
          <p className="text-xs text-fg-subtle">The secret was shown once when you created the workflow.
            <button type="button" className="ml-1 text-accent hover:underline" onClick={() => rotate.mutate()}>Make a new secret</button> (the old one stops working).</p>
        </div>
      )}
      {error && <div className="mt-2"><ErrorNotice error={error} /></div>}
      {secret && <SecretDialog title="New secret for this workflow" secret={secret.secret} url={hookUrl(secret.hook_path)} onClose={() => setSecret(null)} />}
    </article>
  )
}

export function WorkflowsTab({ workflows, recipes, onEdit, onUse }: {
  workflows: Workflow[]
  recipes: Recipe[]
  onEdit: (w: Workflow) => void
  onUse: (r: Recipe) => void
}) {
  if (workflows.length === 0) {
    return (
      <Panel title="Start from a recipe" description="Pick one, adjust it in the builder, done. Nothing runs until you save it.">
        <RecipeGrid recipes={recipes} onUse={onUse} />
      </Panel>
    )
  }
  return (
    <div className="space-y-5">
      <div className="grid gap-4 lg:grid-cols-2">
        {workflows.map((w) => <WorkflowCard key={w.id} workflow={w} onEdit={() => onEdit(w)} />)}
      </div>
      <details className="group">
        <summary className="cursor-pointer list-none text-sm text-fg-muted hover:text-fg">
          <Sparkles className="mr-1.5 inline size-4 text-accent" aria-hidden />More ideas <span className="text-fg-subtle group-open:hidden">· show recipes</span>
        </summary>
        <div className="mt-3"><RecipeGrid recipes={recipes} onUse={onUse} compact /></div>
      </details>
    </div>
  )
}
