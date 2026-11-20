import { CircleAlert, LoaderCircle } from 'lucide-react'
import type { ReactNode } from 'react'

import { ApiError } from '@/lib/api'
import { cn } from '@/lib/cn'

export function Spinner({ className, label = 'Loading' }: { className?: string; label?: string }) {
  return (
    <span role="status" className={cn('inline-flex items-center gap-2 text-sm text-fg-subtle', className)}>
      <LoaderCircle className="size-4 animate-spin" aria-hidden />
      <span>{label}…</span>
    </span>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-md bg-ink-750', className)} aria-hidden />
}

export function ErrorNotice({ error, children }: { error: unknown; children?: ReactNode }) {
  const message = error instanceof ApiError ? error.message : 'Something went wrong.'
  const requestId = error instanceof ApiError ? error.requestId : undefined
  return (
    <div role="alert" className="flex items-start gap-2.5 rounded-lg border border-critical/30 bg-critical/[0.07] px-3 py-2.5 text-sm text-[#ff9ea1]">
      <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0">
        <p>{message}</p>
        {requestId && <p className="mt-0.5 font-mono text-[11px] text-fg-subtle">ref {requestId}</p>}
        {children}
      </div>
    </div>
  )
}

export function StatusDot({ tone, pulse }: { tone: 'ok' | 'warn' | 'critical' | 'idle'; pulse?: boolean }) {
  const color = { ok: 'bg-ok', warn: 'bg-medium', critical: 'bg-critical', idle: 'bg-fg-subtle' }[tone]
  return <span className={cn('inline-block size-2 rounded-full', color, pulse && 'animate-pulse-dot')} aria-hidden />
}
