import { Check, Circle, CircleCheck } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useLocation } from 'react-router-dom'

import { tokenFromHash } from '@/auth/policy'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, PasswordInput } from '@/components/ui/Field'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'

import { AuthLayout } from './AuthLayout'
import { passwordChecks } from './password'

export function ResetPasswordPage() {
  const location = useLocation()
  const token = tokenFromHash(location.hash)
  const [password, setPassword] = useState('')
  const [done, setDone] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [submitting, setSubmitting] = useState(false)
  const checks = passwordChecks(password, '')
  const ok = checks.every((c) => c.ok)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await api('/auth/password-reset/confirm', { method: 'POST', body: { token, password }, auth: false })
      setDone(true)
      window.history.replaceState(null, '', location.pathname) // drop the used token from the address bar
    } catch (err) {
      setError(err)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <AuthLayout title="Choose a new password" subtitle="Every device that was signed in will be signed out."
      footer={<Link to="/login" className="font-medium text-accent hover:underline">Back to sign in</Link>}>
      {done ? (
        <div className="space-y-4" role="status">
          <p className="flex items-center gap-2 text-sm text-fg"><CircleCheck className="size-5 text-ok" aria-hidden /> Password changed.</p>
          <Link to="/login" className="inline-flex"><Button variant="primary">Sign in</Button></Link>
        </div>
      ) : !token ? (
        <p className="rounded-xl border border-line p-4 text-sm text-fg-muted">This page needs the link from the e-mail. <Link to="/forgot-password" className="text-accent hover:underline">Request a new one</Link>.</p>
      ) : (
        <form onSubmit={submit} className="space-y-4" noValidate>
          {error !== null && <ErrorNotice error={error} />}
          <Field label="New password">
            {({ id }) => <PasswordInput id={id} autoComplete="new-password" required autoFocus maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} />}
          </Field>
          <ul className="space-y-1" aria-label="Password requirements">
            {checks.map((c) => (
              <li key={c.label} className={cn('flex items-center gap-2 text-xs', c.ok ? 'text-ok' : 'text-fg-subtle')}>
                {c.ok ? <Check className="size-3.5" aria-hidden /> : <Circle className="size-3" aria-hidden />}{c.label}
              </li>
            ))}
          </ul>
          <Button type="submit" variant="primary" size="lg" className="w-full" loading={submitting} disabled={!ok}>Save new password</Button>
        </form>
      )}
    </AuthLayout>
  )
}
