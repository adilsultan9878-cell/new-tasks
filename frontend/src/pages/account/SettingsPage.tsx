import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { LogOut, Monitor } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { useAuth } from '@/auth/AuthContext'
import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Input, PasswordInput } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api, ApiError } from '@/lib/api'
import { dateTime, relativeTime } from '@/lib/format'
import type { DashboardSummary, SessionInfo, User } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'
import { SystemHealthPanel } from '@/pages/dashboard/CommandCenterPage'
import { passwordChecks } from '@/pages/auth/password'

function describeAgent(ua: string | null): string {
  if (!ua) return 'Unknown device'
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : ua.split(' ')[0]
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : ''
  return [browser, os].filter(Boolean).join(' on ')
}

export function SettingsPage() {
  const { orgId } = useOrg()
  const summary = useQuery({
    queryKey: qk.dashboard(orgId),
    queryFn: () => api<DashboardSummary>(`/organizations/${orgId}/dashboard/summary`),
  })
  return (
    <div>
      <PageHeader eyebrow="Administration" title="System settings" description="Platform status and your personal account security." />
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-5">
          {summary.data ? <SystemHealthPanel system={summary.data.system} /> : summary.isError ? <ErrorNotice error={summary.error} /> : <Skeleton className="h-56" />}
          <Panel title="Security posture" description="How this deployment protects tenant data">
            <ul className="space-y-2.5 text-sm text-fg-muted">
              {[
                'Argon2id password hashing, account lockout and per-IP + per-account rate limits',
                '15-minute access tokens held in memory; rotating HttpOnly refresh cookie with reuse detection',
                'Every organization route resolves through your membership; non-members receive 404',
                'PostgreSQL Row-Level Security on every tenant table (when the API uses the least-privileged role)',
                'Append-only audit trail, including failed logins and permission denials',
              ].map((t) => (
                <li key={t} className="flex gap-2.5">
                  <span className="mt-2 size-1 shrink-0 rounded-full bg-accent" aria-hidden />
                  {t}
                </li>
              ))}
            </ul>
          </Panel>
        </div>
        <div className="space-y-5">
          <ProfilePanel />
          <PasswordPanel />
          <SessionsPanel />
        </div>
      </div>
    </div>
  )
}

function ProfilePanel() {
  const { user, setUser } = useAuth()
  const [name, setName] = useState(user?.full_name ?? '')
  const save = useMutation({
    mutationFn: () => api<User>('/auth/me', { method: 'PATCH', body: { full_name: name.trim() } }),
    onSuccess: setUser,
  })
  if (!user) return null
  return (
    <Panel title="Profile" description={`Member since ${dateTime(user.created_at)}`}>
      <form onSubmit={(e) => { e.preventDefault(); save.mutate() }} className="space-y-4" noValidate>
        {save.error && <ErrorNotice error={save.error} />}
        <Field label="Email">{({ id }) => <Input id={id} value={user.email} disabled />}</Field>
        <Field label="Full name">
          {({ id }) => <Input id={id} value={name} maxLength={120} onChange={(e) => setName(e.target.value)} />}
        </Field>
        <Button type="submit" loading={save.isPending} disabled={!name.trim() || name.trim() === user.full_name}>Save profile</Button>
      </form>
    </Panel>
  )
}

function PasswordPanel() {
  const { user } = useAuth()
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ current_password: '', new_password: '' })
  const [done, setDone] = useState(false)
  const checks = passwordChecks(form.new_password, user?.email ?? '')
  const change = useMutation({
    mutationFn: () => api('/auth/change-password', { method: 'POST', body: form }),
    onSuccess: () => {
      setDone(true)
      setForm({ current_password: '', new_password: '' })
      void queryClient.invalidateQueries({ queryKey: qk.sessions })
    },
  })
  const err = change.error instanceof ApiError ? change.error : null
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setDone(false)
    change.mutate()
  }
  return (
    <Panel title="Password" description="Changing it signs out every other session">
      <form onSubmit={submit} className="space-y-4" noValidate>
        {change.error && !err?.details && <ErrorNotice error={change.error} />}
        {done && <p className="rounded-lg border border-ok/25 bg-ok/[0.07] px-3 py-2 text-sm text-ok" role="status">Password updated. Other sessions were signed out.</p>}
        <Field label="Current password">
          {({ id }) => <PasswordInput id={id} autoComplete="current-password" value={form.current_password} onChange={(e) => setForm((f) => ({ ...f, current_password: e.target.value }))} />}
        </Field>
        <Field label="New password" error={err?.fieldError('new_password')} hint={form.new_password ? checks.filter((c) => !c.ok).map((c) => c.label).join(' · ') || 'Looks good' : undefined}>
          {({ id, describedBy, invalid }) => <PasswordInput id={id} aria-describedby={describedBy} invalid={invalid} autoComplete="new-password" value={form.new_password} onChange={(e) => setForm((f) => ({ ...f, new_password: e.target.value }))} />}
        </Field>
        <Button type="submit" loading={change.isPending} disabled={!form.current_password || !checks.every((c) => c.ok)}>Change password</Button>
      </form>
    </Panel>
  )
}

function SessionsPanel() {
  const queryClient = useQueryClient()
  const sessions = useQuery({ queryKey: qk.sessions, queryFn: () => api<SessionInfo[]>('/auth/sessions') })
  const { logout } = useAuth()
  const signOutAll = useMutation({
    mutationFn: () => api('/auth/logout-all', { method: 'POST' }),
    onSuccess: async () => {
      queryClient.clear()
      await logout()
    },
  })
  return (
    <Panel
      title="Active sessions"
      description="Devices currently signed in to your account"
      actions={<Button size="sm" variant="danger" icon={<LogOut className="size-3.5" />} loading={signOutAll.isPending} onClick={() => window.confirm('Sign out of every session, including this one?') && signOutAll.mutate()}>Sign out everywhere</Button>}
    >
      {sessions.isPending ? (
        <Skeleton className="h-16" />
      ) : sessions.isError ? (
        <ErrorNotice error={sessions.error} />
      ) : (
        <ul className="divide-y divide-line">
          {sessions.data.map((s) => (
            <li key={s.id} className="flex items-center gap-3 py-2.5 text-sm">
              <Monitor className="size-4 shrink-0 text-fg-subtle" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="truncate text-fg">{describeAgent(s.user_agent)}</p>
                <p className="text-xs text-fg-subtle">
                  {s.ip_address ?? 'unknown IP'} · signed in {relativeTime(s.created_at)}
                </p>
              </div>
              {s.current && <Badge tone="accent">This device</Badge>}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
