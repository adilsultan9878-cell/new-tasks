import { useMutation } from '@tanstack/react-query'
import { MailWarning } from 'lucide-react'

import { useAuth } from '@/auth/AuthContext'
import { useAuthPolicy } from '@/auth/policy'
import { Button } from '@/components/ui/Button'
import { api } from '@/lib/api'

/** Shown only when this server sends e-mail and the address is not confirmed yet. */
export function VerifyEmailBanner() {
  const { user } = useAuth()
  const policy = useAuthPolicy()
  const resend = useMutation({ mutationFn: () => api<{ message: string }>('/auth/verify-email/request', { method: 'POST' }) })
  if (!user || user.email_verified || !policy.data?.email_verification) return null
  return (
    <div className="mb-5 flex flex-wrap items-center gap-3 rounded-xl border border-medium/30 bg-medium/10 px-4 py-3 text-sm" role="status">
      <MailWarning className="size-5 shrink-0 text-medium" aria-hidden />
      <span className="min-w-0 flex-1 text-fg">
        Please confirm <strong>{user.email}</strong> — we sent you a link.
        {policy.data.email_verification_required && ' Some actions wait until you do.'}
      </span>
      {resend.isSuccess ? (
        <span className="text-xs text-fg-muted">{resend.data.message}</span>
      ) : (
        <Button size="sm" variant="ghost" loading={resend.isPending} onClick={() => resend.mutate()}>Send the link again</Button>
      )}
    </div>
  )
}
