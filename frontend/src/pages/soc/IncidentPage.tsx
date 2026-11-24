import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Check, Download, FileLock2, FilePlus2, FileText, Fingerprint, ShieldCheck } from 'lucide-react'
import { useState, type FormEvent, type ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { SeverityBadge } from '@/components/ui/StatusBadges'
import { api, downloadFile } from '@/lib/api'
import { cn } from '@/lib/cn'
import { dateTime, relativeTime } from '@/lib/format'
import type { EvidenceItem, IncidentDetail, IncidentStatus, Member, ReportDetail } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'
import { PriorityBadge, RiskBadge } from '@/pages/brain/shared'

import { ActionRow, EmergencyStopBanner, formatBytes, INCIDENT_STATUSES, IncidentStatusPill, ProposeActionDialog } from './shared'

export function IncidentPage() {
  const { incidentId = '' } = useParams()
  const { orgId } = useOrg()
  const incident = useQuery({
    queryKey: qk.incident(orgId, incidentId),
    queryFn: () => api<IncidentDetail>(`/organizations/${orgId}/incidents/${incidentId}`),
  })
  const back = <Link to={`/org/${orgId}/incidents`} className="inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg"><ArrowLeft className="size-3.5" /> Incident Response</Link>
  if (incident.isError) return <div className="space-y-4">{back}<ErrorNotice error={incident.error} /></div>
  if (!incident.data) return <div className="space-y-4">{back}<Skeleton className="h-40" /><Skeleton className="h-64" /></div>
  return <IncidentView incident={incident.data} back={back} />
}

function useIncidentMutation(incidentId: string) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ path = '', method = 'PATCH', body }: { path?: string; method?: 'PATCH' | 'POST'; body: unknown }) =>
      api<IncidentDetail>(`/organizations/${orgId}/incidents/${incidentId}${path}`, { method, body }),
    onSuccess: (data) => {
      queryClient.setQueryData(qk.incident(orgId, incidentId), data)
      void queryClient.invalidateQueries({ queryKey: ['incidents', orgId, 'list'] })
      void queryClient.invalidateQueries({ queryKey: ['alerts', orgId] })
    },
  })
}

export function IncidentView({ incident: inc, back }: { incident: IncidentDetail; back?: ReactNode }) {
  const { orgId, can } = useOrg()
  const manage = can('incidents:manage')
  const update = useIncidentMutation(inc.id)
  const [proposing, setProposing] = useState(false)
  const [addingEvidence, setAddingEvidence] = useState(false)
  const members = useQuery({ queryKey: qk.members(orgId), queryFn: () => api<Member[]>(`/organizations/${orgId}/members`), enabled: manage && can('members:read') })
  const current = INCIDENT_STATUSES.findIndex((s) => s.key === inc.status)

  return (
    <div>
      {back && <div className="mb-3">{back}</div>}
      <EmergencyStopBanner />
      <section className="panel mb-5 p-5">
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-0 flex-1">
            <p className="font-mono text-xs text-accent">{inc.reference}</p>
            <h1 className="mt-1 text-xl font-semibold tracking-tight text-fg sm:text-2xl">{inc.title}</h1>
            <p className="mt-1.5 flex flex-wrap items-center gap-2 text-sm text-fg-muted">
              <SeverityBadge severity={inc.severity} /> <IncidentStatusPill status={inc.status} />
              <span>opened <span title={dateTime(inc.opened_at)}>{relativeTime(inc.opened_at)}</span></span>
              {inc.closed_at && <span>· closed {relativeTime(inc.closed_at)}</span>}
            </p>
          </div>
          {manage && (
            <div className="flex flex-wrap items-center gap-2">
              <Select aria-label="Assignee" className="h-9 w-48 text-xs" value={inc.assigned_to ?? ''}
                onChange={(e) => update.mutate({ body: e.target.value ? { assigned_to: e.target.value } : { unassign: true } })}>
                <option value="">Unassigned</option>
                {(members.data ?? []).filter((m) => m.status === 'active').map((m) => <option key={m.user_id} value={m.user_id}>{m.full_name}</option>)}
              </Select>
              <Select aria-label="Severity" className="h-9 w-32 text-xs" value={inc.severity} onChange={(e) => update.mutate({ body: { severity: e.target.value } })}>
                {['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s} value={s}>{s}</option>)}
              </Select>
            </div>
          )}
        </div>
        {inc.summary && <p className="mt-3 max-w-3xl text-sm text-fg-muted">{inc.summary}</p>}

        <ol className="mt-5 grid grid-cols-3 gap-1.5 sm:grid-cols-6" aria-label="Incident status">
          {INCIDENT_STATUSES.map((s, i) => {
            const done = i <= current
            return (
              <li key={s.key}>
                <button disabled={!manage || s.key === inc.status || update.isPending} onClick={() => update.mutate({ body: { status: s.key as IncidentStatus } })}
                  aria-current={s.key === inc.status ? 'step' : undefined}
                  className={cn('flex w-full flex-col items-start rounded-lg border px-2.5 py-2 text-left text-xs transition-colors disabled:cursor-default',
                    s.key === inc.status ? 'border-accent/50 bg-accent-soft text-fg' : done ? 'border-line text-fg-muted' : 'border-line/60 text-fg-subtle',
                    manage && s.key !== inc.status && 'hover:border-line-strong hover:text-fg')}>
                  <span className={cn('mb-1 h-1 w-full rounded-full', done ? 'brand-gradient' : 'bg-ink-750')} aria-hidden />
                  {s.label}
                </button>
              </li>
            )
          })}
        </ol>
        {update.isError && <div className="mt-3"><ErrorNotice error={update.error} /></div>}
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="min-w-0 space-y-5">
          <Panel title={`Alerts (${inc.alerts.length})`} description="Linked alerts with their Security Brain triage">
            {inc.alerts.length === 0 ? <p className="text-sm text-fg-subtle">No alerts linked.</p> : (
              <ul className="-my-1 divide-y divide-line">
                {inc.alerts.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-2.5 py-2 text-sm">
                    <SeverityBadge severity={a.severity} />
                    <span className="min-w-0 flex-1 truncate text-fg">{a.title}</span>
                    <Badge>{a.status.replace('_', ' ')}</Badge>
                    {a.triage && (
                      <Link to={`/org/${orgId}/brain/runs/${a.triage.run_id}`} className="inline-flex items-center gap-1.5 hover:opacity-80">
                        <PriorityBadge priority={a.triage.priority} /><RiskBadge level={a.triage.risk_level} score={a.triage.risk_score} />
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title={`Response actions (${inc.actions.length})`} description="Allow-listed, approval-gated, recorded"
            actions={can('responses:propose') && inc.status !== 'closed' ? <Button size="sm" icon={<ShieldCheck className="size-3.5" />} onClick={() => setProposing(true)}>Propose action</Button> : undefined}>
            {inc.actions.length === 0 ? <p className="text-sm text-fg-subtle">No actions yet.</p>
              : <ul className="space-y-2.5">{inc.actions.map((a) => <ActionRow key={a.id} action={a} />)}</ul>}
          </Panel>

          <Panel title={`Evidence (${inc.evidence.length})`} description="SHA-256 on collection · every access is a custody entry"
            actions={can('evidence:manage') ? <Button size="sm" icon={<FilePlus2 className="size-3.5" />} onClick={() => setAddingEvidence(true)}>Add evidence</Button> : undefined}>
            {inc.evidence.length === 0 ? <p className="text-sm text-fg-subtle">No evidence collected.</p>
              : <ul className="space-y-2.5">{inc.evidence.map((e) => <EvidenceRow key={e.id} item={e} />)}</ul>}
          </Panel>
        </div>

        <div className="min-w-0 space-y-5">
          <ReportsPanel incident={inc} />
          <Panel title="Timeline" description="Append-only — newest first">
            {manage && <NoteForm incidentId={inc.id} />}
            <ol className="relative mt-4 space-y-3 border-l border-line pl-4">
              {inc.timeline.map((t, i) => (
                <li key={`${t.at}-${i}`} className="relative text-sm">
                  <span className={cn('absolute -left-[21px] top-1.5 size-2 rounded-full', t.kind === 'note' ? 'bg-violet' : t.kind === 'action' ? 'bg-medium' : t.kind === 'evidence' ? 'bg-ok' : 'bg-accent')} aria-hidden />
                  <p className="text-fg">{t.text}</p>
                  <p className="text-[11px] text-fg-subtle">{t.actor ?? 'system'} · <span title={dateTime(t.at)}>{relativeTime(t.at)}</span></p>
                </li>
              ))}
            </ol>
          </Panel>
        </div>
      </div>

      {proposing && <ProposeActionDialog incidentId={inc.id} onClose={() => setProposing(false)} />}
      {addingEvidence && <AddEvidenceDialog incidentId={inc.id} onClose={() => setAddingEvidence(false)} />}
    </div>
  )
}

function NoteForm({ incidentId }: { incidentId: string }) {
  const update = useIncidentMutation(incidentId)
  const [text, setText] = useState('')
  return (
    <form onSubmit={(e: FormEvent) => { e.preventDefault(); if (text.trim()) update.mutate({ path: '/notes', method: 'POST', body: { text: text.trim() } }, { onSuccess: () => setText('') }) }} className="space-y-2">
      <Textarea aria-label="Add a note" rows={2} value={text} onChange={(e) => setText(e.target.value)} placeholder="What did you find or do?" />
      <div className="flex justify-end"><Button type="submit" size="sm" loading={update.isPending} disabled={!text.trim()}>Add note</Button></div>
      {update.isError && <ErrorNotice error={update.error} />}
    </form>
  )
}

export function EvidenceRow({ item: e, showIncident = false }: { item: EvidenceItem; showIncident?: boolean }) {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [downloadError, setDownloadError] = useState<unknown>(null)
  const verify = useMutation({
    mutationFn: () => api<{ intact: boolean }>(`/organizations/${orgId}/evidence/${e.id}/verify`, { method: 'POST' }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['incidents', orgId] }); void queryClient.invalidateQueries({ queryKey: ['evidence', orgId] }) },
  })
  const download = async () => {
    setDownloadError(null)
    try {
      await downloadFile(`/organizations/${orgId}/evidence/${e.id}/download`, e.filename ?? 'evidence.bin')
      void queryClient.invalidateQueries({ queryKey: ['incidents', orgId] })
      void queryClient.invalidateQueries({ queryKey: ['evidence', orgId] })
    } catch (err) {
      setDownloadError(err)
    }
  }
  const manage = can('evidence:manage')
  return (
    <li className="rounded-xl border border-line bg-ink-900/50 p-3.5">
      <div className="flex flex-wrap items-center gap-2">
        <FileLock2 className="size-4 text-accent" aria-hidden />
        <span className="font-medium text-fg">{e.title}</span>
        <Badge>{e.evidence_type}</Badge>
        {showIncident && e.incident_reference && <Link to={`/org/${orgId}/incidents/${e.incident_id}`} className="font-mono text-[11px] text-accent hover:underline">{e.incident_reference}</Link>}
        <span className="ml-auto text-[11px] text-fg-subtle">{formatBytes(e.size_bytes)} · {relativeTime(e.collected_at)}</span>
      </div>
      <p className="mt-1.5 flex items-center gap-1.5 break-all font-mono text-[11px] text-fg-muted" title="SHA-256"><Fingerprint className="size-3.5 shrink-0 text-fg-subtle" aria-hidden />{e.sha256}</p>
      {e.description && <p className="mt-1 text-xs text-fg-muted">{e.description}</p>}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {manage && e.stored && <Button size="sm" icon={<Check className="size-3.5" />} loading={verify.isPending} onClick={() => verify.mutate()}>Verify hash</Button>}
        {manage && e.stored && <Button size="sm" variant="ghost" icon={<Download className="size-3.5" />} onClick={() => void download()}>Download</Button>}
        {verify.data && <Badge tone={verify.data.intact ? 'ok' : 'critical'}>{verify.data.intact ? 'Intact — hash matches' : 'MISMATCH'}</Badge>}
        <button className="ml-auto text-xs text-fg-subtle hover:text-fg" onClick={() => setOpen((o) => !o)} aria-expanded={open}>Chain of custody ({e.chain_of_custody.length})</button>
      </div>
      {open && (
        <ol className="mt-2 space-y-1 border-t border-line pt-2 text-xs">
          {e.chain_of_custody.map((c, i) => (
            <li key={i} className="flex flex-wrap gap-x-2 text-fg-muted">
              <span className="font-medium text-fg">{c.action}{c.result ? ` (${c.result})` : ''}</span>
              <span>{c.actor ?? 'system'}</span>
              <span className="text-fg-subtle">{dateTime(c.at)}</span>
            </li>
          ))}
        </ol>
      )}
      {(verify.isError || downloadError !== null) && <div className="mt-2"><ErrorNotice error={verify.error ?? downloadError} /></div>}
    </li>
  )
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function toBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(binary)
}

function AddEvidenceDialog({ incidentId, onClose }: { incidentId: string; onClose: () => void }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [kind, setKind] = useState<'file' | 'note' | 'external'>('file')
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [note, setNote] = useState('')
  const [hash, setHash] = useState('')
  const add = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { kind, title: title.trim(), description: description.trim() || undefined }
      if (kind === 'file' && file) {
        const buffer = await file.arrayBuffer()
        Object.assign(body, { filename: file.name, content_type: file.type || undefined, content_base64: toBase64(buffer), sha256: await sha256Hex(buffer) })
      } else if (kind === 'note') {
        body.note = note
      } else {
        body.sha256 = hash.trim().toLowerCase()
      }
      return api<EvidenceItem>(`/organizations/${orgId}/incidents/${incidentId}/evidence`, { method: 'POST', body })
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['incidents', orgId] })
      void queryClient.invalidateQueries({ queryKey: ['evidence', orgId] })
      onClose()
    },
  })
  const ready = title.trim().length >= 2 && (kind === 'file' ? !!file : kind === 'note' ? !!note.trim() : /^[0-9a-fA-F]{64}$/.test(hash.trim()))
  return (
    <Dialog open onClose={onClose} size="lg" title="Add evidence" description="Files are hashed in your browser and again on the server; the two must match. Stored evidence can never be changed.">
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); add.mutate() }} className="space-y-4">
        <div className="flex gap-1 rounded-lg border border-line bg-ink-900/60 p-0.5" role="tablist" aria-label="Evidence type">
          {([['file', 'File (≤ 5 MB)'], ['note', 'Note'], ['external', 'External (hash only)']] as const).map(([k, label]) => (
            <button key={k} type="button" role="tab" aria-selected={kind === k} onClick={() => setKind(k)}
              className={cn('flex-1 rounded-md px-2 py-1.5 text-xs', kind === k ? 'bg-ink-750 text-fg' : 'text-fg-muted hover:text-fg')}>{label}</button>
          ))}
        </div>
        <Field label="Title">{({ id }) => <Input id={id} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Phishing email (.eml)" />}</Field>
        {kind === 'file' && <Field label="File">{({ id }) => <Input id={id} type="file" className="h-auto py-2 text-xs" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />}</Field>}
        {kind === 'note' && <Field label="Note">{({ id }) => <Textarea id={id} rows={4} value={note} onChange={(e) => setNote(e.target.value)} />}</Field>}
        {kind === 'external' && <Field label="SHA-256" hint="For material kept elsewhere, e.g. a disk image on an evidence drive.">{({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} className="font-mono text-xs" value={hash} onChange={(e) => setHash(e.target.value)} />}</Field>}
        <Field label="Description (optional)">{({ id }) => <Input id={id} value={description} onChange={(e) => setDescription(e.target.value)} />}</Field>
        {add.isError && <ErrorNotice error={add.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={add.isPending} disabled={!ready}>Store evidence</Button>
        </div>
      </form>
    </Dialog>
  )
}

function ReportsPanel({ incident }: { incident: IncidentDetail }) {
  const { orgId, can } = useOrg()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const generate = useMutation({
    mutationFn: () => api<ReportDetail>(`/organizations/${orgId}/reports`, { method: 'POST', body: { report_type: 'incident', incident_id: incident.id } }),
    onSuccess: (r) => {
      void queryClient.invalidateQueries({ queryKey: ['reports', orgId] })
      void queryClient.invalidateQueries({ queryKey: ['incidents', orgId] })
      navigate(`/org/${orgId}/reports/${r.id}`)
    },
  })
  return (
    <Panel title="Reports" actions={can('reports:manage') ? <Button size="sm" variant="primary" icon={<FileText className="size-3.5" />} loading={generate.isPending} onClick={() => generate.mutate()}>Generate report</Button> : undefined}>
      {incident.reports.length === 0 ? <p className="text-sm text-fg-subtle">No report yet. Reports are built from the incident's own records — nothing is AI-written.</p> : (
        <ul className="-my-1 divide-y divide-line">
          {incident.reports.map((r) => (
            <li key={r.id}><Link to={`/org/${orgId}/reports/${r.id}`} className="flex items-center justify-between gap-2 py-2 text-sm text-fg hover:text-accent">{r.title}<span className="text-xs text-fg-subtle">{relativeTime(r.created_at)}</span></Link></li>
          ))}
        </ul>
      )}
      {generate.isError && <div className="mt-2"><ErrorNotice error={generate.error} /></div>}
    </Panel>
  )
}
