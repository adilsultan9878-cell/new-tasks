import { useMutation } from '@tanstack/react-query'
import { CircleCheck } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { Link, useLocation } from 'react-router-dom'

import { useAuth } from '@/auth/AuthContext'
import { tokenFromHash } from '@/auth/policy'
import { Button } from '@/components/ui/Button'
import { ErrorNotice, Spinner } from '@/components/ui/Feedback'
import { api } from '@/lib/api'
import type { User } from '@/lib/types'

import { AuthLayout } from './AuthLayout'

export function VerifyEmailPage() {
  const location = useLocation()
  const { status, user, setUser } = useAuth()
  const token = tokenFromHash(location.hash)
  const confirm = useMutation({
    mutationFn: () => api<User>('/auth/verify-email/confirm', { method: 'POST', body: { token }, auth: false }),
    onSuccess: (confirmed) => {
      if (user && user.id === confirmed.id) setUser({ ...user, email_verified: true })
      window.history.replaceState(null, '', location.pathname)
    },
  })
  const started = useRef(false)
  useEffect(() => {
    if (token && !started.current) {
      started.current = true
      confirm.mutate()
    }
  }, [token, confirm])

  return (
    <AuthLayout title="Confirm your e-mail" subtitle="So that password resets and invitations reach you."
      footer={<Link to={status === 'authenticated' ? '/' : '/login'} className="font-medium text-accent hover:underline">{status === 'authenticated' ? 'Go to the console' : 'Sign in'}</Link>}>
      {!token ? (
        <p className="rounded-xl border border-line p-4 text-sm text-fg-muted">Open the link from the e-mail to confirm your address.</p>
      ) : confirm.isPending || confirm.isIdle ? (
        <Spinner label="Confirming" />
      ) : confirm.isError ? (
        <ErrorNotice error={confirm.error} />
      ) : (
        <div className="space-y-4" role="status">
          <p className="flex items-center gap-2 text-sm text-fg"><CircleCheck className="size-5 text-ok" aria-hidden /> {confirm.data.email} is confirmed.</p>
          <Link to={status === 'authenticated' ? '/' : '/login'} className="inline-flex"><Button variant="primary">Continue</Button></Link>
        </div>
      )}
    </AuthLayout>
  )
}
