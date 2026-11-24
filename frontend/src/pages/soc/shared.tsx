import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Check, OctagonX, Play, Plus, RotateCcw, ShieldAlert, X } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import { useCurrentUser } from '@/auth/AuthContext'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime } from '@/lib/format'
import type { ActionStatus, ActionType, Device, Impact, IncidentStatus, Member, ResponseAction, ResponseStatus } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

export const INCIDENT_STATUSES: { key: IncidentStatus; label: string }[] = [
  { key: 'open', label: 'Open' },
  { key: 'investigating', label: 'Investigating' },
  { key: 'contained', label: 'Contained' },
  { key: 'eradicated', label: 'Eradicated' },
  { key: 'recovered', label: 'Recovered' },
  { key: 'closed', label: 'Closed' },
]

export function IncidentStatusPill({ status }: { status: IncidentStatus | string }) {
  const label = INCIDENT_STATUSES.find((s) => s.key === status)?.label ?? status
  const cls = status === 'closed' ? 'border-ok/30 bg-ok/10 text-ok'
    : status === 'open' ? 'border-critical/35 bg-critical/10 text-[#ff8f93]'
      : status === 'investigating' ? 'border-medium/30 bg-medium/10 text-medium'
        : 'border-accent/30 bg-accent-soft text-accent'
  return <span className={cn('rounded-full border px-2 py-0.5 text-[11px] font-medium', cls)}>{label}</span>
}

export function ImpactBadge({ impact }: { impact: Impact }) {
  return <Badge tone={impact === 'high' ? 'critical' : impact === 'medium' ? 'warn' : 'info'}>{impact} impact</Badge>
}

const ACTION_STATUS: Record<ActionStatus, { label: string; tone: 'neutral' | 'ok' | 'warn' | 'critical' | 'info' | 'accent' }> = {
  pending_approval: { label: 'Waiting for approval', tone: 'warn' },
  approved: { label: 'Approved · not run', tone: 'accent' },
  rejected: { label: 'Rejected', tone: 'neutral' },
  executing: { label: 'Running', tone: 'info' },
  succeeded: { label: 'Done', tone: 'ok' },
  failed: { label: 'Failed', tone: 'critical' },
  rolled_back: { label: 'Rolled back', tone: 'neutral' },
  cancelled: { label: 'Cancelled', tone: 'neutral' },
}

export function ActionStatusBadge({ status }: { status: ActionStatus }) {
  const s = ACTION_STATUS[status] ?? { label: status, tone: 'neutral' as const }
  return <Badge tone={s.tone}>{s.label}</Badge>
}

export function formatBytes(n: number | null): string {
  if (n === null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export function useResponseStatus() {
  const { orgId } = useOrg()
  return useQuery({ queryKey: qk.responseStatus(orgId), queryFn: () => api<ResponseStatus>(`/organizations/${orgId}/response/status`) })
}

function useInvalidateSoc() {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  return () => {
    for (const key of ['actions', 'incidents', 'response', 'devices', 'indicators', 'members', 'evidence', 'reports']) {
      void queryClient.invalidateQueries({ queryKey: [key, orgId] })
    }
  }
}

/** One response action with the buttons the current member may use. */
export function ActionRow({ action: a, showIncident = false }: { action: ResponseAction; showIncident?: boolean }) {
  const { orgId, can } = useOrg()
  const me = useCurrentUser()
  const invalidate = useInvalidateSoc()
  const [comment, setComment] = useState('')
  const mutate = useMutation({
    mutationFn: ({ path, body }: { path: string; body?: unknown }) =>
      api<ResponseAction>(`/organizations/${orgId}/actions/${a.id}/${path}`, { method: 'POST', body }),
    onSuccess: invalidate,
  })
  const approver = can('responses:approve')
  const mine = me?.id === a.requested_by
  const held = typeof a.result.held === 'string' ? a.result.held : null
  const failed = typeof a.result.error === 'string' ? a.result.error : null
  return (
    <li className="rounded-xl border border-line bg-ink-900/50 p-3.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium text-fg">{a.title ?? a.action_type}</span>
        <ImpactBadge impact={a.impact} />
        <ActionStatusBadge status={a.status} />
        {showIncident && a.incident_reference && (
          <Link to={`/org/${orgId}/incidents/${a.incident_id}`} className="font-mono text-[11px] text-accent hover:underline">{a.incident_reference}</Link>
        )}
        <span className="ml-auto text-[11px] text-fg-subtle">{a.requested_by_name ?? 'system'} · {relativeTime(a.created_at)}</span>
      </div>
      {a.reason && <p className="mt-1.5 text-sm text-fg-muted">{a.reason}</p>}
      {a.approval && a.approval.status !== 'pending' && (
        <p className="mt-1 text-xs text-fg-subtle">
          {a.approval.status === 'expired' ? 'Approval expired' : `${a.approval.status === 'approved' ? 'Approved' : 'Rejected'} by ${a.approval.decided_by_name ?? '—'}`}
          {a.approval.comment ? ` — ${a.approval.comment}` : ''}
        </p>
      )}
      {a.status === 'pending_approval' && a.approval?.expires_at && <p className="mt-1 text-xs text-fg-subtle">Approval expires {relativeTime(a.approval.expires_at)}</p>}
      {held && a.status === 'approved' && <p className="mt-1 text-xs text-medium">{held}</p>}
      {failed && <p className="mt-1 text-xs text-critical">{failed}</p>}
      {!a.reversible && a.status !== 'succeeded' && a.impact === 'high' && <p className="mt-1 text-xs text-fg-subtle">Not reversible once it runs.</p>}

      {(a.status === 'pending_approval' && approver) && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Input aria-label="Approval comment" placeholder="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} className="h-8 w-56 text-xs" />
          <Button size="sm" variant="primary" icon={<Check className="size-3.5" />} loading={mutate.isPending} onClick={() => mutate.mutate({ path: 'decision', body: { approve: true, comment: comment || undefined } })}>Approve</Button>
          <Button size="sm" variant="danger" icon={<X className="size-3.5" />} disabled={mutate.isPending} onClick={() => mutate.mutate({ path: 'decision', body: { approve: false, comment: comment || undefined } })}>Reject</Button>
        </div>
      )}
      <div className="mt-2 flex flex-wrap gap-2 empty:hidden">
        {a.status === 'approved' && approver && <Button size="sm" icon={<Play className="size-3.5" />} loading={mutate.isPending} onClick={() => mutate.mutate({ path: 'run' })}>Run now</Button>}
        {a.status === 'succeeded' && a.reversible && approver && <Button size="sm" icon={<RotateCcw className="size-3.5" />} loading={mutate.isPending} onClick={() => mutate.mutate({ path: 'rollback' })}>Roll back</Button>}
        {(a.status === 'pending_approval' || a.status === 'approved') && (mine || approver) && can('responses:propose') && (
          <Button size="sm" variant="ghost" icon={<Ban className="size-3.5" />} disabled={mutate.isPending} onClick={() => mutate.mutate({ path: 'cancel' })}>Cancel</Button>
        )}
      </div>
      {mutate.isError && <div className="mt-2"><ErrorNotice error={mutate.error} /></div>}
    </li>
  )
}

/** Propose an allow-listed action. Medium and high impact actions wait for approval. */
export function ProposeActionDialog({ onClose, incidentId, runId, preset }: {
  onClose: () => void
  incidentId?: string
  runId?: string
  preset?: { action_type: ActionType; target: Record<string, string> }
}) {
  const { orgId, can } = useOrg()
  const me = useCurrentUser()
  const invalidate = useInvalidateSoc()
  const status = useResponseStatus()
  const [type, setType] = useState<ActionType>(preset?.action_type ?? 'notify_team')
  const [target, setTarget] = useState<Record<string, string>>(preset?.target ?? {})
  const [reason, setReason] = useState('')
  const devices = useQuery({ queryKey: qk.devices(orgId), queryFn: () => api<Device[]>(`/organizations/${orgId}/devices`), enabled: can('devices:read') })
  const members = useQuery({ queryKey: qk.members(orgId), queryFn: () => api<Member[]>(`/organizations/${orgId}/members`), enabled: can('members:read') })
  const spec = status.data?.action_types.find((t) => t.key === type)
  const propose = useMutation({
    mutationFn: () => api<ResponseAction>(`/organizations/${orgId}/actions`, {
      method: 'POST', body: { action_type: type, target, reason: reason.trim() || undefined, incident_id: incidentId, agent_run_id: runId },
    }),
    onSuccess: () => { invalidate(); onClose() },
  })
  const set = (k: string) => (v: string) => setTarget((t) => ({ ...t, [k]: v }))
  const submit = (e: FormEvent) => { e.preventDefault(); propose.mutate() }

  return (
    <Dialog open onClose={onClose} size="lg" title="Propose a response action"
      description="Only allow-listed actions exist. Medium and high impact actions run after an approver says yes; high impact needs someone other than you.">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Action">
          {({ id }) => (
            <Select id={id} value={type} onChange={(e) => { setType(e.target.value as ActionType); setTarget({}) }} disabled={!!preset}>
              {(status.data?.action_types ?? []).map((t) => <option key={t.key} value={t.key}>{t.title} — {t.impact} impact</option>)}
            </Select>
          )}
        </Field>
        {spec && (
          <div className="flex items-start gap-2 rounded-lg border border-line bg-ink-900/50 px-3 py-2 text-xs text-fg-muted">
            <ShieldAlert className="mt-0.5 size-3.5 shrink-0 text-accent" aria-hidden />
            <span>{spec.description} {spec.impact === 'low' ? 'Runs immediately.' : 'Needs approval.'}</span>
          </div>
        )}
        {type === 'notify_team' && (
          <Field label="Message">{({ id }) => <Textarea id={id} rows={2} value={target.message ?? ''} onChange={(e) => set('message')(e.target.value)} placeholder="What should the responders do?" />}</Field>
        )}
        {(type === 'heighten_monitoring' || type === 'revoke_device') && (
          <Field label="Device">
            {({ id }) => (
              <Select id={id} value={target.device_id ?? ''} onChange={(e) => set('device_id')(e.target.value)}>
                <option value="">Select a device</option>
                {(devices.data ?? []).filter((d) => d.enrollment_status === 'enrolled').map((d) => <option key={d.id} value={d.id}>{d.name}{d.ip_address ? ` · ${d.ip_address}` : ''}</option>)}
              </Select>
            )}
          </Field>
        )}
        {type === 'block_indicator' && (
          <div className="grid gap-3 sm:grid-cols-[140px_1fr]">
            <Field label="Type">
              {({ id }) => (
                <Select id={id} value={target.indicator_type ?? 'ipv4'} onChange={(e) => set('indicator_type')(e.target.value)} disabled={!!preset}>
                  {['ipv4', 'ipv6', 'domain', 'url', 'email', 'sha256', 'sha1', 'md5'].map((t) => <option key={t} value={t}>{t}</option>)}
                </Select>
              )}
            </Field>
            <Field label="Value">{({ id }) => <Input id={id} className="font-mono text-xs" value={target.value ?? ''} onChange={(e) => setTarget((t) => ({ indicator_type: t.indicator_type ?? 'ipv4', ...t, value: e.target.value }))} disabled={!!preset} placeholder="203.0.113.66" />}</Field>
          </div>
        )}
        {type === 'suspend_member' && (
          <Field label="Member">
            {({ id }) => (
              <Select id={id} value={target.user_id ?? ''} onChange={(e) => set('user_id')(e.target.value)}>
                <option value="">Select a member</option>
                {(members.data ?? []).filter((m) => m.status === 'active' && m.user_id !== me?.id).map((m) => <option key={m.user_id} value={m.user_id}>{m.full_name} · {m.role.name}</option>)}
              </Select>
            )}
          </Field>
        )}
        <Field label="Reason" hint="Recorded in the audit log and the incident timeline.">
          {({ id, describedBy }) => <Textarea id={id} aria-describedby={describedBy} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />}
        </Field>
        {propose.isError && <ErrorNotice error={propose.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={propose.isPending} icon={<Plus className="size-4" />}>{spec?.impact === 'low' ? 'Run action' : 'Request approval'}</Button>
        </div>
      </form>
    </Dialog>
  )
}

export function EmergencyStopBanner() {
  const status = useResponseStatus()
  const stop = status.data?.emergency_stop
  if (!stop?.engaged) return null
  return (
    <div role="alert" className="mb-5 flex items-start gap-3 rounded-2xl border border-critical/40 bg-critical/[0.08] px-4 py-3 text-sm">
      <OctagonX className="mt-0.5 size-5 shrink-0 text-critical" aria-hidden />
      <div>
        <p className="font-semibold text-[#ff8f93]">Emergency stop engaged — no response action can run</p>
        <p className="text-xs text-fg-muted">{stop.actor ? `By ${stop.actor} ` : ''}{stop.at ? relativeTime(stop.at) : ''}{stop.reason ? ` · ${stop.reason}` : ''}</p>
      </div>
    </div>
  )
}

export function EmergencyStopButton() {
  const { orgId, can } = useOrg()
  const status = useResponseStatus()
  const invalidate = useInvalidateSoc()
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const engaged = status.data?.emergency_stop.engaged ?? false
  const toggle = useMutation({
    mutationFn: () => api(`/organizations/${orgId}/response/emergency-stop`, { method: 'POST', body: { engaged: !engaged, reason: reason.trim() || undefined } }),
    onSuccess: () => { invalidate(); setOpen(false); setReason('') },
  })
  if (!can('responses:approve') || !status.data) return null
  return (
    <>
      <Button size="md" variant={engaged ? 'secondary' : 'danger'} icon={<OctagonX className="size-4" />} onClick={() => setOpen(true)}>
        {engaged ? 'Release emergency stop' : 'Emergency stop'}
      </Button>
      {open && (
        <Dialog open onClose={() => setOpen(false)} title={engaged ? 'Release the emergency stop?' : 'Engage the emergency stop?'}
          description={engaged ? 'Approved actions stay on hold until someone runs them.' : 'Every response action in this organization is held until the stop is released. Everyone who can propose actions is notified.'}>
          <form onSubmit={(e) => { e.preventDefault(); toggle.mutate() }} className="space-y-4">
            <Field label="Reason">{({ id }) => <Input id={id} value={reason} onChange={(e) => setReason(e.target.value)} placeholder={engaged ? 'Incident contained' : 'Unexpected behaviour during response'} />}</Field>
            {toggle.isError && <ErrorNotice error={toggle.error} />}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
              <Button type="submit" variant={engaged ? 'primary' : 'danger'} loading={toggle.isPending}>{engaged ? 'Release' : 'Engage stop'}</Button>
            </div>
          </form>
        </Dialog>
      )}
    </>
  )
}
