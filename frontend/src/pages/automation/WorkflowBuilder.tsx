import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowDown, CalendarClock, Play, Plus, ShieldCheck, Trash2, Webhook as WebhookIcon, Zap } from 'lucide-react'
import { useMemo, useState, type FormEvent, type ReactNode } from 'react'

import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input, Select } from '@/components/ui/Field'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import type { AutomationCatalog, Recipe, TriggerType, Webhook, Workflow, WorkflowSecret, WorkflowStep } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

import { Switch } from './shared'

const TRIGGER_ICON: Record<TriggerType, typeof Zap> = { event: Zap, schedule: CalendarClock, manual: Play, webhook: WebhookIcon }
const TRIGGER_HINT: Record<TriggerType, string> = {
  event: 'An alert, incident, offline device or approval request',
  schedule: 'Every hour, day or week',
  manual: 'Only when someone presses Run',
  webhook: 'n8n or another tool calls a signed URL',
}
const SEVERITIES = ['low', 'medium', 'high', 'critical']

function defaultMessage(trigger: TriggerType, event: string): string {
  if (trigger === 'event') {
    return {
      'alert.created': '{{alert.severity}} alert: {{alert.title}}',
      'incident.created': 'Incident {{incident.reference}}: {{incident.title}}',
      'device.offline': '{{device.name}} stopped reporting',
      'action.pending_approval': 'Approval needed: {{action.title}}',
    }[event] ?? 'Something happened'
  }
  if (trigger === 'webhook') return 'Message from another tool: {{payload.title}}'
  return 'Open incidents: {{summary.open_incidents}}'
}

function newStep(type: string, trigger: TriggerType, event: string, webhooks: Webhook[]): WorkflowStep {
  switch (type) {
    case 'notify': return { type, audience: 'responders', message: defaultMessage(trigger, event) }
    case 'send_webhook': return { type, webhook_id: webhooks[0]?.id ?? '' }
    case 'create_incident': return { type, title: trigger === 'event' ? '{{alert.title}}' : '{{payload.title}}' }
    case 'propose_response':
      return trigger === 'event'
        ? { type, action_type: 'heighten_monitoring' }
        : { type, action_type: 'block_indicator', indicator_type: 'ipv4', value: trigger === 'webhook' ? '{{payload.value}}' : '' }
    default: return { type }
  }
}

type Initial = { workflow?: Workflow; recipe?: Recipe }

export function WorkflowBuilder({ catalog, webhooks, initial, onClose, onSaved, onAddWebhook }: {
  catalog: AutomationCatalog
  webhooks: Webhook[]
  initial: Initial
  onClose: () => void
  onSaved: (result: Workflow | WorkflowSecret) => void
  onAddWebhook: () => void
}) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const source = initial.workflow ?? initial.recipe
  const [name, setName] = useState(initial.workflow?.name ?? initial.recipe?.name ?? '')
  const [trigger, setTrigger] = useState<TriggerType>(source?.trigger_type ?? 'event')
  const [event, setEvent] = useState(source?.trigger_config.event ?? 'alert.created')
  const [minSeverity, setMinSeverity] = useState(source?.trigger_config.min_severity ?? 'high')
  const [includeSimulated, setIncludeSimulated] = useState(source?.trigger_config.include_simulated ?? false)
  const [every, setEvery] = useState(source?.trigger_config.every_minutes ?? 1440)
  const [steps, setSteps] = useState<WorkflowStep[]>(() => {
    if (initial.workflow) return initial.workflow.steps.map((s) => ({ type: s.type, ...s.params }))
    if (initial.recipe) return initial.recipe.steps.map((s) => (s.type === 'send_webhook' && !s.webhook_id ? { ...s, webhook_id: webhooks[0]?.id ?? '' } : { ...s }))
    return [newStep('notify', 'event', 'alert.created', webhooks)]
  })
  const [approval, setApproval] = useState(initial.workflow?.requires_approval ?? initial.recipe?.requires_approval ?? true)
  const [enabled, setEnabled] = useState(initial.workflow?.enabled ?? true)

  const eventSpec = catalog.events.find((e) => e.key === event)
  const stepSpecs = useMemo(() => Object.fromEntries(catalog.steps.map((s) => [s.key, s])), [catalog])
  const allowed = (type: string) => {
    const s = stepSpecs[type]
    if (!s) return false
    if (s.triggers.length && !s.triggers.includes(trigger)) return false
    if (trigger === 'event' && s.events.length && !s.events.includes(event)) return false
    return true
  }
  const forced = steps.some((s) => stepSpecs[s.type]?.risk !== 'low')
  const blocked = steps.some((s) => !allowed(s.type) || (s.type === 'send_webhook' && !s.webhook_id))
  const fields = trigger === 'event' ? eventSpec?.fields ?? [] : trigger === 'webhook' ? ['payload.title', 'payload.value'] : ['summary.open_incidents', 'summary.pending_approvals']

  const save = useMutation({
    mutationFn: () => {
      const trigger_config = trigger === 'event'
        ? { event, ...(eventSpec?.filters.includes('min_severity') ? { min_severity: minSeverity } : {}), ...(eventSpec?.filters.includes('include_simulated') ? { include_simulated: includeSimulated } : {}) }
        : trigger === 'schedule' ? { every_minutes: every } : {}
      const body = { name: name.trim(), trigger_type: trigger, trigger_config, steps, requires_approval: forced || approval, enabled }
      return initial.workflow
        ? api<Workflow>(`/organizations/${orgId}/automation/workflows/${initial.workflow.id}`, { method: 'PATCH', body })
        : api<Workflow | WorkflowSecret>(`/organizations/${orgId}/automation/workflows`, { method: 'POST', body })
    },
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: ['automation', orgId] })
      onSaved(result)
    },
  })

  const update = (i: number, patch: Record<string, unknown>) => setSteps((all) => all.map((s, j) => (j === i ? { ...s, ...patch } : s)))
  const changeTrigger = (t: TriggerType) => {
    setTrigger(t)
    if (steps.length === 0 || steps.every((s) => s.type === 'notify')) setSteps([newStep('notify', t, event, webhooks)])
  }

  return (
    <Dialog open onClose={onClose} size="lg" title={initial.workflow ? `Edit “${initial.workflow.name}”` : 'New workflow'}
      description="Three simple parts: when it starts, what it does, and whether a person approves it first.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); save.mutate() }} className="space-y-6">
        <Field label="Name">{({ id }) => <Input id={id} required minLength={3} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Tell the team about serious alerts" />}</Field>

        <Section n={1} title="When">
          <div className="grid gap-2 sm:grid-cols-2" role="radiogroup" aria-label="Trigger">
            {catalog.trigger_types.map((t) => {
              const Icon = TRIGGER_ICON[t.key]
              return (
                <button key={t.key} type="button" role="radio" aria-checked={trigger === t.key} onClick={() => changeTrigger(t.key)}
                  className={cn('flex items-start gap-3 rounded-xl border p-3 text-left transition-colors', trigger === t.key ? 'border-accent/60 bg-accent-soft' : 'border-line hover:border-line-strong')}>
                  <Icon className={cn('mt-0.5 size-4 shrink-0', trigger === t.key ? 'text-accent' : 'text-fg-subtle')} aria-hidden />
                  <span><span className="block text-sm font-medium text-fg">{t.title}</span><span className="block text-xs text-fg-subtle">{TRIGGER_HINT[t.key]}</span></span>
                </button>
              )
            })}
          </div>
          {trigger === 'event' && (
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <Field label="What happens">{({ id }) => (
                <Select id={id} value={event} onChange={(e) => setEvent(e.target.value)}>
                  {catalog.events.map((ev) => <option key={ev.key} value={ev.key}>{ev.title}</option>)}
                </Select>
              )}</Field>
              {eventSpec?.filters.includes('min_severity') && (
                <Field label="Only if severity is at least">{({ id }) => (
                  <Select id={id} value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
                    {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                  </Select>
                )}</Field>
              )}
              {eventSpec?.filters.includes('include_simulated') && (
                <label className="flex items-center gap-2 text-sm text-fg-muted sm:col-span-2">
                  <input type="checkbox" checked={includeSimulated} onChange={(e) => setIncludeSimulated(e.target.checked)} className="accent-[var(--color-accent)]" />
                  Also run for simulator data (runs are labelled “simulated”)
                </label>
              )}
            </div>
          )}
          {trigger === 'schedule' && (
            <div className="mt-3 max-w-xs">
              <Field label="How often">{({ id }) => (
                <Select id={id} value={every} onChange={(e) => setEvery(Number(e.target.value))}>
                  {catalog.schedules.map((s) => <option key={s.every_minutes} value={s.every_minutes}>{s.title}</option>)}
                </Select>
              )}</Field>
            </div>
          )}
          {trigger === 'webhook' && <p className="mt-3 text-xs text-fg-subtle">After saving you get a URL and a signing secret for n8n or any tool that can send an HTTP request.</p>}
        </Section>

        <Section n={2} title="Then">
          <ol className="space-y-2">
            {steps.map((step, i) => (
              <li key={i}>
                {i > 0 && <ArrowDown className="mx-auto mb-2 size-4 text-fg-subtle" aria-hidden />}
                <StepEditor step={step} index={i} catalog={catalog} webhooks={webhooks} trigger={trigger} allowed={allowed(step.type)}
                  onChange={(patch) => update(i, patch)} onRemove={steps.length > 1 ? () => setSteps((all) => all.filter((_, j) => j !== i)) : undefined}
                  onAddWebhook={onAddWebhook} />
              </li>
            ))}
          </ol>
          {steps.length < 10 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {catalog.steps.filter((s) => allowed(s.key)).map((s) => (
                <Button key={s.key} type="button" size="sm" variant="ghost" icon={<Plus className="size-3.5" />}
                  onClick={() => setSteps((all) => [...all, newStep(s.key, trigger, event, webhooks)])}>
                  {s.title}
                </Button>
              ))}
            </div>
          )}
          {fields.length > 0 && (
            <p className="mt-3 text-xs text-fg-subtle">
              Messages can use: {fields.map((f) => <code key={f} className="mr-1 rounded bg-ink-800 px-1 font-mono text-[11px] text-fg-muted">{`{{${f}}}`}</code>)}
            </p>
          )}
        </Section>

        <Section n={3} title="Safety">
          <div className="space-y-2">
            <label className="flex items-start gap-3 rounded-xl border border-line p-3">
              <Switch on={forced || approval} onChange={setApproval} disabled={forced} label="Ask an approver before each run" />
              <span>
                <span className="block text-sm text-fg">Ask an approver before each run</span>
                <span className="block text-xs text-fg-subtle">
                  {forced ? 'Required: this workflow opens incidents.' : steps.some((s) => s.type === 'propose_response') ? 'Proposed blocks always wait for approval in Incident Response anyway.' : 'When off, the steps run as soon as the workflow starts.'}
                </span>
              </span>
            </label>
            <label className="flex items-start gap-3 rounded-xl border border-line p-3">
              <Switch on={enabled} onChange={setEnabled} label="Turn on now" />
              <span><span className="block text-sm text-fg">Turn on now</span><span className="block text-xs text-fg-subtle">You can switch it off any time. The emergency stop pauses all automation.</span></span>
            </label>
          </div>
        </Section>

        {save.isError && <ErrorNotice error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending} disabled={blocked || !name.trim()}>{initial.workflow ? 'Save' : 'Create workflow'}</Button>
        </div>
      </form>
    </Dialog>
  )
}

function Section({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-fg">
        <span className="brand-gradient grid size-6 place-items-center rounded-full text-[11px] text-white">{n}</span>{title}
      </h3>
      {children}
    </section>
  )
}

function StepEditor({ step, index, catalog, webhooks, trigger, allowed, onChange, onRemove, onAddWebhook }: {
  step: WorkflowStep
  index: number
  catalog: AutomationCatalog
  webhooks: Webhook[]
  trigger: TriggerType
  allowed: boolean
  onChange: (patch: Record<string, unknown>) => void
  onRemove?: () => void
  onAddWebhook: () => void
}) {
  const spec = catalog.steps.find((s) => s.key === step.type)
  const str = (k: string) => String(step[k] ?? '')
  return (
    <div className={cn('rounded-xl border bg-ink-900/50 p-3', allowed ? 'border-line' : 'border-critical/40')}>
      <div className="mb-2 flex items-center gap-2">
        <span className="text-xs font-medium text-fg-subtle">Step {index + 1}</span>
        <span className="text-sm font-medium text-fg">{spec?.title ?? step.type}</span>
        {spec?.risk === 'medium' && <span className="inline-flex items-center gap-1 text-[11px] text-accent"><ShieldCheck className="size-3" aria-hidden />approval</span>}
        {onRemove && <button type="button" onClick={onRemove} className="ml-auto rounded p-1 text-fg-subtle hover:bg-ink-750 hover:text-critical" aria-label={`Remove step ${index + 1}`}><Trash2 className="size-3.5" /></button>}
      </div>
      {!allowed && <p className="mb-2 text-xs text-critical">Not available with this trigger — remove it.</p>}
      {step.type === 'notify' && (
        <div className="grid gap-2 sm:grid-cols-[10rem_1fr]">
          <Select aria-label="Who" value={str('audience')} onChange={(e) => onChange({ audience: e.target.value })}>
            <option value="responders">Responders</option>
            <option value="approvers">Approvers</option>
          </Select>
          <Input aria-label="Message" value={str('message')} maxLength={300} onChange={(e) => onChange({ message: e.target.value })} />
        </div>
      )}
      {step.type === 'send_webhook' && (webhooks.length ? (
        <Select aria-label="Webhook" value={str('webhook_id')} onChange={(e) => onChange({ webhook_id: e.target.value })}>
          {!step.webhook_id && <option value="">Choose a webhook</option>}
          {webhooks.map((w) => <option key={w.id} value={w.id}>{w.name} · {w.host}</option>)}
        </Select>
      ) : (
        <p className="text-sm text-fg-muted">No webhook yet. <button type="button" onClick={onAddWebhook} className="text-accent hover:underline">Add one</button> (for example your n8n Webhook URL).</p>
      ))}
      {step.type === 'create_incident' && <Input aria-label="Incident title" value={str('title')} maxLength={200} onChange={(e) => onChange({ title: e.target.value })} />}
      {step.type === 'propose_response' && (trigger === 'event' ? (
        <p className="text-sm text-fg-muted">Proposes 15-second reporting with all collectors on the alert's device. Runs only after an approver agrees in Incident Response.</p>
      ) : (
        <div className="grid gap-2 sm:grid-cols-[9rem_1fr]">
          <Select aria-label="Indicator type" value={str('indicator_type')} onChange={(e) => onChange({ indicator_type: e.target.value })}>
            {catalog.indicator_types.map((t) => <option key={t} value={t}>{t}</option>)}
          </Select>
          <Input aria-label="Value to block" value={str('value')} maxLength={300} placeholder={trigger === 'webhook' ? '{{payload.value}}' : '203.0.113.7'} onChange={(e) => onChange({ value: e.target.value })} />
        </div>
      ))}
      {step.type === 'create_event' && <p className="text-sm text-fg-muted">The request body becomes an event: <code className="font-mono text-xs">{'{"title", "severity", "category", "description"}'}</code>. High and critical raise alerts.</p>}
    </div>
  )
}
