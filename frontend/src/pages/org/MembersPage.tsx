import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Mail, Minus, Trash2, UserPlus, Users } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'

import { useAuth } from '@/auth/AuthContext'
import { PageHeader } from '@/components/layout/PageHeader'
import { Avatar } from '@/components/ui/Avatar'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Input, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api, ApiError } from '@/lib/api'
import { relativeTime } from '@/lib/format'
import type { Invitation, InvitationCreated, Member, RoleWithPermissions } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

export function MembersPage() {
  const { orgId, can, membership } = useOrg()
  const { user } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const manage = can('members:manage')
  const [adding, setAdding] = useState(false)
  const [inviting, setInviting] = useState(false)
  const [actionError, setActionError] = useState<unknown>(null)

  const members = useQuery({ queryKey: qk.members(orgId), queryFn: () => api<Member[]>(`/organizations/${orgId}/members`) })
  const roles = useQuery({ queryKey: qk.roles, queryFn: () => api<RoleWithPermissions[]>('/organizations/roles'), staleTime: Infinity })
  const myRank = membership.role.rank

  const refresh = () => Promise.all([queryClient.invalidateQueries({ queryKey: qk.members(orgId) }), queryClient.invalidateQueries({ queryKey: qk.memberships })])

  const changeRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) => api(`/organizations/${orgId}/members/${id}`, { method: 'PATCH', body: { role } }),
    onMutate: () => setActionError(null),
    onError: setActionError,
    onSuccess: refresh,
  })
  const remove = useMutation({
    mutationFn: (m: Member) => api(`/organizations/${orgId}/members/${m.id}`, { method: 'DELETE' }),
    onMutate: () => setActionError(null),
    onError: setActionError,
    onSuccess: async (_d, m) => {
      if (m.user_id === user?.id) {
        await queryClient.invalidateQueries({ queryKey: qk.memberships })
        navigate('/', { replace: true })
      } else await refresh()
    },
  })

  return (
    <div>
      <PageHeader
        eyebrow="Administration"
        title="Users & Roles"
        description="Members of this organization and what each role can do. Nobody can grant a role above their own, and the last owner cannot be removed."
        actions={manage && <>
          <Button variant="ghost" icon={<UserPlus className="size-4" />} onClick={() => setAdding(true)}>Add member</Button>
          <Button variant="primary" icon={<Mail className="size-4" />} onClick={() => setInviting(true)}>Invite by e-mail</Button>
        </>}
      />
      {actionError !== null && (
        <div className="mb-4">
          <ErrorNotice error={actionError} />
        </div>
      )}
      <Panel title="Members" description={members.data ? `${members.data.length} total` : undefined} flush>
        {members.isPending ? (
          <div className="space-y-3 p-5">{Array.from({ length: 3 }, (_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : members.isError ? (
          <div className="p-5"><ErrorNotice error={members.error} /></div>
        ) : members.data.length === 0 ? (
          <EmptyState icon={Users} title="No members" />
        ) : (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[560px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-fg-subtle">
                  <th className="px-5 py-2.5 font-medium">Member</th>
                  <th className="px-3 py-2.5 font-medium">Role</th>
                  <th className="px-3 py-2.5 font-medium">Joined</th>
                  <th className="px-5 py-2.5"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {members.data.map((m) => {
                  const isMe = m.user_id === user?.id
                  const owners = members.data.filter((x) => x.role.key === 'owner').length
                  const canLeave = isMe && !(m.role.key === 'owner' && owners <= 1)
                  const editable = manage && !isMe && m.role.rank <= myRank
                  return (
                    <tr key={m.id} className="hover:bg-ink-850/60">
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-3">
                          <Avatar name={m.full_name} />
                          <div className="min-w-0">
                            <p className="truncate font-medium text-fg">
                              {m.full_name} {isMe && <span className="text-xs font-normal text-fg-subtle">(you)</span>}
                            </p>
                            <p className="truncate text-xs text-fg-subtle">{m.email}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        {editable && roles.data ? (
                          <Select
                            aria-label={`Role for ${m.full_name}`}
                            className="h-8 w-40 text-xs"
                            value={m.role.key}
                            disabled={changeRole.isPending}
                            onChange={(e) => changeRole.mutate({ id: m.id, role: e.target.value })}
                          >
                            {roles.data.filter((r) => r.rank <= myRank).map((r) => (
                              <option key={r.key} value={r.key}>{r.name}</option>
                            ))}
                          </Select>
                        ) : (
                          <Badge tone={m.role.key === 'owner' ? 'accent' : 'neutral'}>{m.role.name}</Badge>
                        )}
                      </td>
                      <td className="px-3 py-3 text-fg-muted">{relativeTime(m.joined_at)}</td>
                      <td className="px-5 py-3 text-right">
                        {(editable || canLeave) && (
                          <Button
                            size="sm"
                            variant="ghost"
                            icon={<Trash2 className="size-3.5" />}
                            onClick={() => {
                              const msg = isMe ? `Leave ${membership.organization.name}? You will lose access immediately.` : `Remove ${m.full_name} from ${membership.organization.name}?`
                              if (window.confirm(msg)) remove.mutate(m)
                            }}
                          >
                            {isMe ? 'Leave' : 'Remove'}
                          </Button>
                        )}
                        {isMe && !canLeave && <span className="text-xs text-fg-subtle" title="Promote another member to owner before leaving">Sole owner</span>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <PendingInvitations />
      {roles.data && <PermissionMatrix roles={roles.data} />}
      <AddMemberDialog open={adding} onClose={() => setAdding(false)} roles={(roles.data ?? []).filter((r) => r.rank <= myRank)} onAdded={refresh} />
      {inviting && <InviteDialog onClose={() => setInviting(false)} roles={(roles.data ?? []).filter((r) => r.rank <= myRank)} />}
    </div>
  )
}

function PermissionMatrix({ roles }: { roles: RoleWithPermissions[] }) {
  const all = Array.from(new Set(roles.flatMap((r) => r.permissions))).sort()
  return (
    <Panel className="mt-5" title="Permission matrix" description="Enforced by the API on every request; roles and permissions are stored in the database" flush>
      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[560px] text-xs">
          <thead>
            <tr className="border-b border-line text-left text-fg-subtle">
              <th className="px-5 py-2.5 font-medium">Permission</th>
              {roles.map((r) => (
                <th key={r.key} className="px-3 py-2.5 text-center font-medium" title={r.description ?? undefined}>{r.name}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {all.map((p) => (
              <tr key={p}>
                <td className="px-5 py-2 font-mono text-[11px] text-fg-muted">{p}</td>
                {roles.map((r) => (
                  <td key={r.key} className="px-3 py-2 text-center">
                    {r.permissions.includes(p) ? <Check className="mx-auto size-3.5 text-accent" aria-label="Granted" /> : <Minus className="mx-auto size-3.5 text-ink-600" aria-label="Not granted" />}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

function AddMemberDialog({ open, onClose, roles, onAdded }: { open: boolean; onClose: () => void; roles: RoleWithPermissions[]; onAdded: () => Promise<unknown> }) {
  const { orgId } = useOrg()
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('viewer')
  const add = useMutation({
    mutationFn: () => api<Member>(`/organizations/${orgId}/members`, { method: 'POST', body: { email: email.trim(), role } }),
    onSuccess: async () => {
      await onAdded()
      setEmail('')
      onClose()
    },
  })
  const err = add.error instanceof ApiError ? add.error : null
  const submit = (e: FormEvent) => {
    e.preventDefault()
    add.mutate()
  }
  return (
    <Dialog open={open} onClose={() => { add.reset(); onClose() }} title="Add member" description="For people who already have a SENTINEL X account. Anyone else: use Invite by e-mail.">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {add.error && !err?.details && <ErrorNotice error={add.error} />}
        <Field label="Email" error={err?.fieldError('email')}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} invalid={invalid} type="email" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="analyst@company.com" />
          )}
        </Field>
        <Field label="Role" hint={roles.find((r) => r.key === role)?.description ?? undefined}>
          {({ id, describedBy }) => (
            <Select id={id} aria-describedby={describedBy} value={role} onChange={(e) => setRole(e.target.value)}>
              {roles.map((r) => (
                <option key={r.key} value={r.key}>{r.name}</option>
              ))}
            </Select>
          )}
        </Field>
        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={add.isPending} disabled={!email.includes('@')}>Add member</Button>
        </div>
      </form>
    </Dialog>
  )
}

function PendingInvitations() {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const list = useQuery({ queryKey: ['invitations', orgId], queryFn: () => api<Invitation[]>(`/organizations/${orgId}/invitations`) })
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/organizations/${orgId}/invitations/${id}`, { method: 'DELETE' }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['invitations', orgId] }),
  })
  if (!list.data?.length) return null
  return (
    <Panel className="mt-5" title={`Invitations (${list.data.length})`} description="Waiting to be accepted. Each link works once and only for its address." flush>
      <ul className="divide-y divide-line">
        {list.data.map((inv) => (
          <li key={inv.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
            <Mail className="size-4 text-fg-subtle" aria-hidden />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-fg">{inv.email}</span>
              <span className="block text-xs text-fg-subtle">
                {inv.role.name} · {inv.invited_by_name ? `by ${inv.invited_by_name} · ` : ''}{inv.status === 'expired' ? 'expired' : `expires ${relativeTime(inv.expires_at)}`}
                {!inv.emailed && ' · link shared by hand'}
              </span>
            </span>
            {inv.status === 'expired' && <Badge>expired</Badge>}
            {can('members:manage') && (
              <Button size="sm" variant="ghost" icon={<Trash2 className="size-3.5" />} loading={revoke.isPending && revoke.variables === inv.id}
                onClick={() => revoke.mutate(inv.id)} aria-label={`Revoke invitation for ${inv.email}`}>Revoke</Button>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  )
}

function InviteDialog({ onClose, roles }: { onClose: () => void; roles: RoleWithPermissions[] }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('viewer')
  const [copied, setCopied] = useState(false)
  const invite = useMutation({
    mutationFn: () => api<InvitationCreated>(`/organizations/${orgId}/invitations`, { method: 'POST', body: { email: email.trim(), role } }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['invitations', orgId] }),
  })
  const err = invite.error instanceof ApiError ? invite.error : null
  const done = invite.data
  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
    } catch {
      /* clipboard blocked: the link stays selectable */
    }
  }
  return (
    <Dialog open onClose={onClose} title="Invite by e-mail" description="They get a link to join this organization — with a new account or the one they have.">
      {done ? (
        <div className="space-y-4" role="status">
          {done.link ? (
            <>
              <p className="text-sm text-fg">E-mail is not set up on this server, so pass this link to <strong>{done.invitation.email}</strong> yourself. It is shown only now.</p>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-canvas px-3 py-2 font-mono text-[12px] text-fg">{done.link}</pre>
              <Button size="sm" variant="ghost" onClick={() => void copy(done.link!)}>{copied ? 'Copied' : 'Copy link'}</Button>
            </>
          ) : (
            <p className="text-sm text-fg">Invitation sent to <strong>{done.invitation.email}</strong>. It works for 7 days.</p>
          )}
          <div className="flex justify-end"><Button variant="primary" onClick={onClose}>Done</Button></div>
        </div>
      ) : (
        <form onSubmit={(e: FormEvent) => { e.preventDefault(); invite.mutate() }} className="space-y-4" noValidate>
          {invite.error && !err?.details && <ErrorNotice error={invite.error} />}
          <Field label="Email" error={err?.fieldError('email')}>
            {({ id, describedBy, invalid }) => (
              <Input id={id} aria-describedby={describedBy} invalid={invalid} type="email" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="colleague@company.com" />
            )}
          </Field>
          <Field label="Role" hint={roles.find((r) => r.key === role)?.description ?? undefined}>
            {({ id, describedBy }) => (
              <Select id={id} aria-describedby={describedBy} value={role} onChange={(e) => setRole(e.target.value)}>
                {roles.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}
              </Select>
            )}
          </Field>
          <div className="flex justify-end gap-2 pt-1">
            <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" loading={invite.isPending} disabled={!email.includes('@')}>Send invitation</Button>
          </div>
        </form>
      )}
    </Dialog>
  )
}
