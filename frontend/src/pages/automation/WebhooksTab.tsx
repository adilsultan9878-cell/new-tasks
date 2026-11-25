import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CircleAlert, CircleCheck, Clock3, KeyRound, Pencil, RotateCcw, Send, Trash2, Webhook as WebhookIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { dateTime, relativeTime } from '@/lib/format'
import type { Delivery, Webhook, WebhookSecret } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { SimulatedBadge } from '@/pages/aegis/shared'

import { CopyField, SecretDialog, Switch, VERIFY_SNIPPET } from './shared'

export function WebhookDialog({ webhook, privateAllowed, onClose, onCreated }: {
  webhook?: Webhook
  privateAllowed: boolean
  onClose: () => void
  onCreated?: (s: WebhookSecret) => void
}) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [name, setName] = useState(webhook?.name ?? '')
  const [url, setUrl] = useState(webhook?.url ?? '')
  const [provider, setProvider] = useState<Webhook['provider']>(webhook?.provider ?? 'n8n')
  const save = useMutation({
    mutationFn: (): Promise<Webhook | WebhookSecret> => webhook
      ? api<Webhook>(`/organizations/${orgId}/automation/webhooks/${webhook.id}`, { method: 'PATCH', body: { name: name.trim(), url: url.trim() } })
      : api<WebhookSecret>(`/organizations/${orgId}/automation/webhooks`, { method: 'POST', body: { name: name.trim(), url: url.trim(), provider } }),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: ['automation', orgId] })
      if ('webhook' in result) onCreated?.(result)
      onClose()
    },
  })
  return (
    <Dialog open onClose={onClose} title={webhook ? `Edit ${webhook.name}` : 'Add a webhook'}
      description="Where SENTINEL X sends signed JSON: an n8n Webhook node, a Slack or Teams workflow, or your own endpoint.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); save.mutate() }} className="space-y-4">
        <Field label="Name">{({ id }) => <Input id={id} required minLength={2} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} placeholder="n8n alerts" />}</Field>
        {!webhook && (
          <Field label="Kind">{({ id }) => (
            <Select id={id} value={provider} onChange={(e) => setProvider(e.target.value as Webhook['provider'])}>
              <option value="n8n">n8n</option>
              <option value="webhook">Other (any HTTPS endpoint)</option>
            </Select>
          )}</Field>
        )}
        <Field label="URL" hint={privateAllowed ? 'https:// for internet targets; http:// is allowed for your private network (local n8n).' : 'Public https:// addresses only. Internal and cloud-metadata addresses are refused.'}>
          {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} required type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://n8n.example.com/webhook/sentinel" />}
        </Field>
        {save.isError && <ErrorNotice error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={save.isPending}>{webhook ? 'Save' : 'Add webhook'}</Button>
        </div>
      </form>
    </Dialog>
  )
}

function Health({ hook }: { hook: Webhook }) {
  if (!hook.enabled) return <Badge>Off</Badge>
  if (hook.failure_count > 0) return <Badge tone="critical"><CircleAlert className="size-3" aria-hidden />{hook.failure_count} failed in a row</Badge>
  if (hook.last_success_at) return <Badge tone="ok"><CircleCheck className="size-3" aria-hidden />Healthy</Badge>
  return <Badge tone="neutral"><Clock3 className="size-3" aria-hidden />Not used yet</Badge>
}

function WebhookCard({ hook, onEdit }: { hook: Webhook; onEdit: () => void }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const [secret, setSecret] = useState<string | null>(null)
  const base = `/organizations/${orgId}/automation/webhooks/${hook.id}`
  const refresh = () => void queryClient.invalidateQueries({ queryKey: ['automation', orgId] })
  const test = useMutation({ mutationFn: () => api<Delivery>(`${base}/test`, { method: 'POST' }), onSuccess: refresh })
  const toggle = useMutation({ mutationFn: (enabled: boolean) => api<Webhook>(base, { method: 'PATCH', body: { enabled } }), onSuccess: refresh })
  const rotate = useMutation({ mutationFn: () => api<WebhookSecret>(`${base}/rotate-secret`, { method: 'POST' }), onSuccess: (s) => { setSecret(s.secret); refresh() } })
  const remove = useMutation({ mutationFn: () => api<void>(base, { method: 'DELETE' }), onSuccess: refresh })
  const manage = can('integrations:manage')
  const error = test.error ?? toggle.error ?? rotate.error ?? remove.error
  return (
    <article className="panel p-4 sm:p-5" aria-label={hook.name}>
      <div className="flex items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-line-strong bg-ink-850 text-accent"><WebhookIcon className="size-5" aria-hidden /></span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="truncate font-medium text-fg">{hook.name}</h3>
            <Badge tone="info">{hook.provider === 'n8n' ? 'n8n' : 'Webhook'}</Badge>
          </div>
          <p className="truncate font-mono text-xs text-fg-subtle">{hook.url}</p>
        </div>
        {manage && <Switch on={hook.enabled} onChange={(v) => toggle.mutate(v)} disabled={toggle.isPending} label={`${hook.enabled ? 'Turn off' : 'Turn on'} ${hook.name}`} />}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-fg-subtle">
        <Health hook={hook} />
        <span>{hook.last_success_at ? `last delivered ${relativeTime(hook.last_success_at)}` : 'no delivery yet'}</span>
        <span>· used by {hook.used_by} workflow{hook.used_by === 1 ? '' : 's'}</span>
      </div>
      {hook.last_error && hook.failure_count > 0 && <p className="mt-2 text-xs text-critical">{hook.last_error}</p>}
      {test.data && (
        <p className={cn('mt-2 text-xs', test.data.status === 'delivered' ? 'text-ok' : 'text-critical')}>
          Test {test.data.status === 'delivered' ? `delivered (HTTP ${test.data.last_status_code}, ${test.data.response_ms} ms)` : `not delivered: ${test.data.last_error}`}
        </p>
      )}
      {manage && (
        <div className="mt-3 flex flex-wrap gap-1">
          <Button size="sm" variant="ghost" icon={<Send className="size-3.5" />} loading={test.isPending} disabled={!hook.enabled} onClick={() => test.mutate()}>Send test</Button>
          <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" />} loading={rotate.isPending}
            onClick={() => { if (window.confirm('Make a new signing secret? The receiver must be updated; the old secret stops working.')) rotate.mutate() }}>New secret</Button>
          <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" />} onClick={onEdit}>Edit</Button>
          <Button size="sm" variant="ghost" icon={<Trash2 className="size-3.5" />} loading={remove.isPending}
            onClick={() => { if (window.confirm(`Delete “${hook.name}”?`)) remove.mutate() }}>Delete</Button>
        </div>
      )}
      {error && <div className="mt-2"><ErrorNotice error={error} /></div>}
      {secret && <SecretDialog title={`New secret for ${hook.name}`} secret={secret} onClose={() => setSecret(null)} />}
    </article>
  )
}

const DELIVERY_TONE = { delivered: 'ok', pending: 'accent', failed: 'critical' } as const

function Deliveries({ deliveries, hooks }: { deliveries: Delivery[]; hooks: Webhook[] }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const retry = useMutation({
    mutationFn: (id: string) => api<Delivery>(`/organizations/${orgId}/automation/deliveries/${id}/retry`, { method: 'POST' }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['automation', orgId] }),
  })
  const names = Object.fromEntries(hooks.map((h) => [h.id, h.name]))
  if (deliveries.length === 0) return <EmptyState icon={Send} title="No deliveries yet">Send a test, or let a workflow send something.</EmptyState>
  return (
    <div className="relative overflow-x-auto">
      <table className="w-full min-w-[40rem] text-sm">
        <thead className="text-left text-xs text-fg-subtle">
          <tr className="border-b border-line">
            <th className="px-4 py-2 font-medium sm:px-5">When</th>
            <th className="px-2 py-2 font-medium">What</th>
            <th className="px-2 py-2 font-medium">Webhook</th>
            <th className="px-2 py-2 font-medium">Result</th>
            <th className="px-4 py-2 font-medium sm:px-5"><span className="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {deliveries.map((d) => (
            <tr key={d.id} className="border-b border-line last:border-0">
              <td className="px-4 py-2.5 text-fg-muted sm:px-5" title={dateTime(d.created_at)}>{relativeTime(d.created_at)}</td>
              <td className="px-2 py-2.5"><span className="font-mono text-xs text-fg">{d.event_type}</span> {d.is_simulated && <SimulatedBadge />}</td>
              <td className="px-2 py-2.5 text-fg-muted">{names[d.webhook_id] ?? '—'}</td>
              <td className="px-2 py-2.5">
                <Badge tone={DELIVERY_TONE[d.status]}>{d.status}{d.last_status_code ? ` · ${d.last_status_code}` : ''}</Badge>
                <span className="ml-2 text-xs text-fg-subtle">{d.attempts} attempt{d.attempts === 1 ? '' : 's'}{d.status === 'pending' && d.next_attempt_at ? ` · next ${relativeTime(d.next_attempt_at)}` : ''}</span>
                {d.last_error && d.status !== 'delivered' && <span className="block text-xs text-critical">{d.last_error}</span>}
              </td>
              <td className="px-4 py-2.5 text-right sm:px-5">
                {can('integrations:manage') && d.status !== 'delivered' && (
                  <Button size="sm" variant="ghost" icon={<RotateCcw className="size-3.5" />} loading={retry.isPending && retry.variables === d.id} onClick={() => retry.mutate(d.id)}>Retry</Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {retry.isError && <div className="p-3"><ErrorNotice error={retry.error} /></div>}
    </div>
  )
}

export function WebhooksTab({ hooks, deliveries, privateAllowed, onAdd }: { hooks: Webhook[]; deliveries: Delivery[]; privateAllowed: boolean; onAdd: () => void }) {
  const { can } = useOrg()
  const [editing, setEditing] = useState<Webhook | null>(null)
  return (
    <div className="space-y-5">
      {hooks.length === 0 ? (
        <Panel>
          <EmptyState icon={WebhookIcon} title="No webhooks yet"
            action={can('integrations:manage') ? <Button variant="primary" onClick={onAdd}>Add a webhook</Button> : undefined}>
            A webhook is an address that receives signed JSON from SENTINEL X — for example an n8n workflow that posts to Slack, Teams or email.
          </EmptyState>
        </Panel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">{hooks.map((h) => <WebhookCard key={h.id} hook={h} onEdit={() => setEditing(h)} />)}</div>
      )}
      <Panel title="Recent deliveries" description="Failed calls are retried with growing pauses; redirects are never followed" flush>
        <Deliveries deliveries={deliveries} hooks={hooks} />
      </Panel>
      <Panel title="Check that a request really came from us" description="Use this in n8n (Code node) or your own receiver. Reject anything that fails.">
        <CopyField label="JavaScript" value={VERIFY_SNIPPET} />
      </Panel>
      {editing && <WebhookDialog webhook={editing} privateAllowed={privateAllowed} onClose={() => setEditing(null)} />}
    </div>
  )
}
