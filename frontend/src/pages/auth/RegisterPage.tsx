import { Check, Circle } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { useAuth } from '@/auth/AuthContext'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input, PasswordInput } from '@/components/ui/Field'
import { ApiError } from '@/lib/api'
import { cn } from '@/lib/cn'

import { AuthLayout } from './AuthLayout'
import { passwordChecks } from './password'

export function RegisterPage() {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ full_name: '', email: '', password: '' })
  const [error, setError] = useState<unknown>(null)
  const [submitting, setSubmitting] = useState(false)
  const checks = passwordChecks(form.password, form.email)
  const passwordOk = checks.every((c) => c.ok)

  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [key]: e.target.value }))

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!passwordOk) {
      setError(new ApiError(422, 'weak_password', 'Choose a stronger password.', [{ field: 'password', message: checks.find((c) => !c.ok)!.label }]))
      return
    }
    setSubmitting(true)
    try {
      await register(form)
      navigate('/onboarding', { replace: true })
    } catch (err) {
      setError(err)
    } finally {
      setSubmitting(false)
    }
  }

  const apiErr = error instanceof ApiError ? error : null
  return (
    <AuthLayout
      title="Create your account"
      subtitle="Then create or join an organization — each one is an isolated tenant."
      footer={
        <>
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-accent hover:underline">
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        {error !== null && !apiErr?.details && <ErrorNotice error={error} />}
        <Field label="Full name" error={apiErr?.fieldError('full_name')}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} invalid={invalid} autoComplete="name" required autoFocus maxLength={120} value={form.full_name} onChange={set('full_name')} placeholder="Ayesha Khan" />
          )}
        </Field>
        <Field label="Work email" error={apiErr?.fieldError('email')}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} invalid={invalid} type="email" autoComplete="email" required value={form.email} onChange={set('email')} placeholder="you@company.com" />
          )}
        </Field>
        <Field label="Password" error={apiErr?.fieldError('password')}>
          {({ id, describedBy, invalid }) => (
            <PasswordInput id={id} aria-describedby={describedBy} invalid={invalid} autoComplete="new-password" required maxLength={128} value={form.password} onChange={set('password')} />
          )}
        </Field>
        <ul className="space-y-1" aria-label="Password requirements">
          {checks.map((c) => (
            <li key={c.label} className={cn('flex items-center gap-2 text-xs', c.ok ? 'text-ok' : 'text-fg-subtle')}>
              {c.ok ? <Check className="size-3.5" aria-hidden /> : <Circle className="size-3" aria-hidden />}
              {c.label}
              <span className="sr-only">{c.ok ? '(met)' : '(not met)'}</span>
            </li>
          ))}
        </ul>
        <Button type="submit" variant="primary" size="lg" className="w-full" loading={submitting}>
          Create account
        </Button>
        <p className="text-xs leading-relaxed text-fg-subtle">
          Passwords are hashed with Argon2id. Sessions use a short-lived token in memory and a rotating, HttpOnly refresh cookie.
        </p>
      </form>
    </AuthLayout>
  )
}
