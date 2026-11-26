import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'

import { useAuth } from '@/auth/AuthContext'
import { useAuthPolicy } from '@/auth/policy'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input, PasswordInput } from '@/components/ui/Field'
import { ApiError } from '@/lib/api'

import { AuthLayout } from './AuthLayout'

export function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<unknown>(null)
  const [submitting, setSubmitting] = useState(false)
  const policy = useAuthPolicy()

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(email, password)
      const from = (location.state as { from?: string } | null)?.from
      navigate(from && from !== '/login' ? from : '/', { replace: true })
    } catch (err) {
      setError(err)
    } finally {
      setSubmitting(false)
    }
  }

  const fieldErr = error instanceof ApiError ? error : null
  return (
    <AuthLayout
      title="Sign in"
      subtitle="Access your organization's security operations."
      footer={
        <>
          New to SENTINEL X?{' '}
          <Link to="/register" className="font-medium text-accent hover:underline">
            Create an account
          </Link>
        </>
      }
    >
      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        {error !== null && !fieldErr?.details && <ErrorNotice error={error} />}
        <Field label="Work email" error={fieldErr?.fieldError('email')}>
          {({ id, describedBy, invalid }) => (
            <Input id={id} aria-describedby={describedBy} invalid={invalid} type="email" autoComplete="email" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
          )}
        </Field>
        <Field label="Password" error={fieldErr?.fieldError('password')}
          labelAside={policy.data?.password_reset ? <Link to="/forgot-password" className="text-xs text-accent hover:underline">Forgot password?</Link> : undefined}>
          {({ id, describedBy, invalid }) => (
            <PasswordInput id={id} aria-describedby={describedBy} invalid={invalid} autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          )}
        </Field>
        <Button type="submit" variant="primary" size="lg" className="w-full" loading={submitting}>
          Sign in
        </Button>
      </form>
    </AuthLayout>
  )
}
