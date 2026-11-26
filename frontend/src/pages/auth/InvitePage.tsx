import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2, Check, Circle } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'

import { useAuth } from '@/auth/AuthContext'
import { tokenFromHash } from '@/auth/policy'
import { Button } from '@/components/ui/Button'
import { ErrorNotice, Spinner } from '@/components/ui/Feedback'
import { Field, Input, PasswordInput } from '@/components/ui/Field'
import { api, ApiError } from '@/lib/api'
import { cn } from '@/lib/cn'
import type { InvitationInfo, Membership } from '@/lib/types'
import { qk } from '@/org/queries'

import { AuthLayout } from './AuthLayout'
import { passwordChecks } from './password'

export function InvitePage() {
  const location = useLocation()
  const token = tokenFromHash(location.hash)
  const info = useQuery({
    queryKey: ['invitation', token],
    queryFn: () => api<InvitationInfo>('/invitations/lookup', { method: 'POST', body: { token }, auth: false }),
    enabled: !!token,
    retry: false,
  })

  return (
    <AuthLayout title="You are invited" subtitle="Join your team on SENTINEL X."
      footer={<Link to="/" className="font-medium text-accent hover:underline">Go to SENTINEL X</Link>}>
      {!token ? (
        <p className="rounded-xl border border-line p-4 text-sm text-fg-muted">Open the invitation link you received to continue.</p>
      ) : info.isPending ? (
        <Spinner label="Checking the invitation" />
      ) : info.isError ? (
        <p className="rounded-xl border border-critical/30 bg-critical/10 p-4 text-sm text-fg" role="alert">
          {info.error instanceof ApiError && info.error.status === 404
            ? 'This invitation is no longer valid — it was used, replaced, revoked or has expired. Ask for a new one.'
            : 'The invitation could not be checked. Try again in a moment.'}
        </p>
      ) : (
        <InviteBody info={info.data} token={token} />
      )}
    </AuthLayout>
  )
}

function InviteBody({ info, token }: { info: InvitationInfo; token: string }) {
  const { status, user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const accept = useMutation({
    mutationFn: () => api<Membership>('/invitations/accept', { method: 'POST', body: { token } }),
    onSuccess: async (m) => {
      await queryClient.invalidateQueries({ queryKey: qk.memberships })
      navigate(`/org/${m.organization.id}`, { replace: true })
    },
  })
  const card = (
    <div className="mb-5 flex items-center gap-3 rounded-xl border border-accent/30 bg-accent-soft/40 p-4">
      <Building2 className="size-6 shrink-0 text-accent" aria-hidden />
      <div>
        <p className="font-medium text-fg">{info.organization_name}</p>
        <p className="text-xs text-fg-muted">as {info.role} · for {info.email}</p>
      </div>
    </div>
  )

  if (status === 'authenticated' && user) {
    if (user.email.toLowerCase() !== info.email) {
      return (
        <div>
          {card}
          <p className="mb-4 text-sm text-fg-muted">You are signed in as <strong>{user.email}</strong>, but this invitation is for <strong>{info.email}</strong>.</p>
          <Button variant="ghost" onClick={() => void logout()}>Sign out and switch account</Button>
        </div>
      )
    }
    return (
      <div className="space-y-4">
        {card}
        {accept.isError && <ErrorNotice error={accept.error} />}
        <Button variant="primary" size="lg" className="w-full" loading={accept.isPending} onClick={() => accept.mutate()}>Accept invitation</Button>
      </div>
    )
  }
  if (info.account_exists) {
    return (
      <div>
        {card}
        <p className="mb-4 text-sm text-fg-muted">There is already an account for {info.email_hint}. Sign in with it to accept.</p>
        <Button variant="primary" size="lg" className="w-full" onClick={() => navigate('/login', { state: { from: `/invite${location.hash}` } })}>Sign in to accept</Button>
      </div>
    )
  }
  return (
    <div>
      {card}
      <SignUpForm email={info.email} token={token} />
    </div>
  )
}

function SignUpForm({ email, token }: { email: string; token: string }) {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [fullName, setFullName] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [submitting, setSubmitting] = useState(false)
  const checks = passwordChecks(password, email)
  const ok = checks.every((c) => c.ok) && fullName.trim().length > 0
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await register({ email, password, full_name: fullName.trim(), invitation_token: token })
      navigate('/', { replace: true })
    } catch (err) {
      setError(err)
    } finally {
      setSubmitting(false)
    }
  }
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <p className="text-sm text-fg-muted">Create your account to join.</p>
      {error !== null && <ErrorNotice error={error} />}
      <Field label="Work email">{({ id }) => <Input id={id} value={email} readOnly disabled />}</Field>
      <Field label="Full name">{({ id }) => <Input id={id} autoComplete="name" required autoFocus maxLength={120} value={fullName} onChange={(e) => setFullName(e.target.value)} />}</Field>
      <Field label="Password">{({ id }) => <PasswordInput id={id} autoComplete="new-password" required maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} />}</Field>
      <ul className="space-y-1" aria-label="Password requirements">
        {checks.map((c) => (
          <li key={c.label} className={cn('flex items-center gap-2 text-xs', c.ok ? 'text-ok' : 'text-fg-subtle')}>
            {c.ok ? <Check className="size-3.5" aria-hidden /> : <Circle className="size-3" aria-hidden />}{c.label}
          </li>
        ))}
      </ul>
      <Button type="submit" variant="primary" size="lg" className="w-full" loading={submitting} disabled={!ok}>Create account and join</Button>
    </form>
  )
}
