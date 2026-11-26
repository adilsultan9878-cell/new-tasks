import { MailCheck } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import { useAuthPolicy } from '@/auth/policy'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input } from '@/components/ui/Field'
import { api } from '@/lib/api'

import { AuthLayout } from './AuthLayout'

export function ForgotPasswordPage() {
  const policy = useAuthPolicy()
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [submitting, setSubmitting] = useState(false)
  const off = policy.data && !policy.data.password_reset

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await api('/auth/password-reset/request', { method: 'POST', body: { email: email.trim() }, auth: false })
      setSent(true)
    } catch (err) {
      setError(err)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <AuthLayout title="Forgot your password?" subtitle="We e-mail you a link to choose a new one."
      footer={<Link to="/login" className="font-medium text-accent hover:underline">Back to sign in</Link>}>
      {sent ? (
        <div className="rounded-xl border border-ok/30 bg-ok/10 p-4 text-sm text-fg" role="status">
          <MailCheck className="mb-2 size-5 text-ok" aria-hidden />
          If an account exists for <strong>{email}</strong>, a reset link is on its way. It works for 30 minutes and only once.
        </div>
      ) : off ? (
        <p className="rounded-xl border border-line p-4 text-sm text-fg-muted">
          E-mail is not set up on this server, so passwords cannot be reset by e-mail. Ask an administrator of your organization for help.
        </p>
      ) : (
        <form onSubmit={submit} className="space-y-4" noValidate>
          {error !== null && <ErrorNotice error={error} />}
          <Field label="Work email">
            {({ id }) => <Input id={id} type="email" autoComplete="email" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />}
          </Field>
          <Button type="submit" variant="primary" size="lg" className="w-full" loading={submitting} disabled={!email.includes('@')}>Send reset link</Button>
        </form>
      )}
    </AuthLayout>
  )
}
