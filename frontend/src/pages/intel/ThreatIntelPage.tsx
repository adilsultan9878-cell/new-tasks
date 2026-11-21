import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, CircleDashed, Plus, Trash2 } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Input, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api, ApiError } from '@/lib/api'
import { relativeTime } from '@/lib/format'
import type { Indicator, IntelProvider, InvestigationDetail, Page } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { InvestigationHistory, useRunInvestigation } from './Investigations'
import { InvestigationView, SafeExternalLink, VerdictBadge } from './InvestigationView'

function looksLikeIp(v: string) {
  return /^[\d.]+$/.test(v) || v.includes(':')
}

export function ThreatIntelPage() {
  const { can } = useOrg()
  const [subject, setSubject] = useState('')
  const [result, setResult] = useState<InvestigationDetail | null>(null)
  const run = useRunInvestigation(setResult)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const v = subject.trim()
    run.mutate({ subject_type: looksLikeIp(v) ? 'ip' : 'domain', subject: v })
  }
  return (
    <div>
      <PageHeader eyebrow="NEXUS ZERO · Threat hunting" title="Threat Intelligence"
        description="Investigate IP addresses and domains against registries and reputation services, and keep your organization's own indicator watchlist." />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-5">
          <Panel title="Investigate an IP address or domain">
            {!can('investigations:run') ? <p className="text-sm text-fg-muted">Your role can view results but cannot run investigations.</p> : (
              <form onSubmit={submit} className="flex flex-col gap-3 sm:flex-row sm:items-start" noValidate>
                <div className="flex-1">
                  <Input aria-label="IP address or domain" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="185.220.101.4 or example.com" className="font-mono text-xs" spellCheck={false} />
                  {run.error && <div className="mt-2"><ErrorNotice error={run.error} /></div>}
                </div>
                <Button type="submit" variant="primary" loading={run.isPending} disabled={!subject.trim()}>Investigate</Button>
              </form>
            )}
          </Panel>
          {result && <Panel title="Result" description={result.title}><InvestigationView inv={result} /></Panel>}
          <Watchlist />
        </div>
        <div className="space-y-5">
          <Providers />
          <InvestigationHistory types={['ip', 'domain']} />
        </div>
      </div>
    </div>
  )
}

function Providers() {
  const providers = useQuery({ queryKey: qk.providers, queryFn: () => api<IntelProvider[]>('/intel/providers'), staleTime: 60_000 })
  return (
    <Panel title="Intelligence sources" description="What investigations can consult right now" flush>
      {providers.isPending ? <div className="p-5"><Skeleton className="h-40" /></div> : providers.isError ? <div className="p-5"><ErrorNotice error={providers.error} /></div> : (
        <ul className="divide-y divide-line">
          {providers.data.map((p) => (
            <li key={p.key} className="flex items-start gap-2.5 px-5 py-2.5 text-sm">
              {p.configured ? <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" aria-label="configured" /> : <CircleDashed className="mt-0.5 size-4 shrink-0 text-fg-subtle" aria-label="not configured" />}
              <div className="min-w-0">
                <p className="text-fg">{p.name}</p>
                <p className="text-xs text-fg-subtle">
                  {p.covers.join(' · ')}
                  {!p.configured && p.requires_key && <> · needs <span className="font-mono">{p.requires_key}</span></>}
                </p>
                {!p.configured && p.url && <p className="mt-0.5 text-xs"><SafeExternalLink href={p.url}>Get a free key</SafeExternalLink></p>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

function Watchlist() {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ indicator_type: 'domain', value: '', verdict: 'malicious', note: '' })
  const params = { limit: 50 }
  const list = useQuery({ queryKey: qk.indicators(orgId, params), queryFn: () => api<Page<Indicator>>(`/organizations/${orgId}/indicators`, { query: params }) })
  const add = useMutation({
    mutationFn: () => api(`/organizations/${orgId}/indicators`, { method: 'POST', body: { ...form, value: form.value.trim(), note: form.note.trim() || null } }),
    onSuccess: () => {
      setForm((f) => ({ ...f, value: '', note: '' }))
      void queryClient.invalidateQueries({ queryKey: ['indicators', orgId] })
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api(`/organizations/${orgId}/indicators/${id}`, { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['indicators', orgId] }),
  })
  const err = add.error instanceof ApiError ? add.error : null
  return (
    <Panel title="Indicators" description="Your watchlist plus everything investigations have recorded" flush>
      {can('intel:manage') && (
        <form onSubmit={(e) => { e.preventDefault(); add.mutate() }} className="grid gap-2 border-b border-line p-4 sm:grid-cols-[120px_1fr_120px_auto] sm:items-end">
          <Field label="Type">{({ id }) => (
            <Select id={id} className="h-9 text-xs" value={form.indicator_type} onChange={(e) => setForm((f) => ({ ...f, indicator_type: e.target.value }))}>
              {['domain', 'url', 'ipv4', 'ipv6', 'email', 'sha256', 'sha1', 'md5'].map((t) => <option key={t}>{t}</option>)}
            </Select>)}</Field>
          <Field label="Value" error={err?.fieldError('value')}>{({ id }) => <Input id={id} className="h-9 font-mono text-xs" value={form.value} onChange={(e) => setForm((f) => ({ ...f, value: e.target.value }))} />}</Field>
          <Field label="Verdict">{({ id }) => (
            <Select id={id} className="h-9 text-xs" value={form.verdict} onChange={(e) => setForm((f) => ({ ...f, verdict: e.target.value }))}>
              <option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="benign">Benign</option>
            </Select>)}</Field>
          <Button type="submit" size="sm" className="h-9" icon={<Plus className="size-3.5" />} loading={add.isPending} disabled={!form.value.trim()}>Add</Button>
          {add.error && !err?.details && <div className="sm:col-span-4"><ErrorNotice error={add.error} /></div>}
        </form>
      )}
      {list.isPending ? <div className="p-5"><Skeleton className="h-24" /></div> : list.isError ? <div className="p-5"><ErrorNotice error={list.error} /></div>
        : list.data.items.length === 0 ? <EmptyState icon={Plus} title="No indicators yet">Add known-bad domains, IPs or hashes, or run investigations.</EmptyState> : (
          <ul className="divide-y divide-line">
            {list.data.items.map((i) => (
              <li key={i.id} className="flex flex-wrap items-center gap-3 px-5 py-2.5 text-sm">
                <VerdictBadge verdict={i.verdict} />
                <span className="w-14 font-mono text-[11px] text-fg-subtle">{i.indicator_type}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg" title={i.value}>{i.value}</span>
                <Badge tone={i.source === 'analyst' ? 'accent' : 'neutral'}>{i.source}</Badge>
                <span className="text-xs text-fg-subtle">{relativeTime(i.last_seen_at)}</span>
                {can('intel:manage') && <button onClick={() => remove.mutate(i.id)} className="rounded p-1 text-fg-subtle hover:bg-ink-750 hover:text-fg" aria-label={`Remove ${i.value}`}><Trash2 className="size-3.5" /></button>}
              </li>
            ))}
          </ul>
        )}
    </Panel>
  )
}
