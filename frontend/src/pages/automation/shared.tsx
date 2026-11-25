import { Check, CircleAlert, CircleCheck, CircleDashed, CircleSlash, Clock3, Copy, KeyRound, ShieldCheck } from 'lucide-react'
import { useState, type ReactNode } from 'react'

import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { absoluteApiBase } from '@/lib/api'
import { cn } from '@/lib/cn'
import type { RunStatus } from '@/lib/types'

export function hookUrl(path: string): string {
  return new URL(path, absoluteApiBase()).toString()
}

export function CopyField({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked: the text stays selectable */
    }
  }
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-medium text-fg-muted">{label}</span>
        <button type="button" onClick={() => void copy()} className="flex items-center gap-1 text-xs text-accent hover:underline">
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className={cn('overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-canvas px-3 py-2 text-[12px] leading-relaxed text-fg', mono && 'font-mono')}>{value}</pre>
    </div>
  )
}

/** Shown once after creating or rotating a secret. */
export function SecretDialog({ title, secret, url, onClose, children }: {
  title: string
  secret: string
  url?: string
  onClose: () => void
  children?: ReactNode
}) {
  return (
    <Dialog open onClose={onClose} size="lg" title={title} description="Copy the secret now — it is not stored and will not be shown again. You can always make a new one.">
      <div className="space-y-4">
        {url && <CopyField label="URL" value={url} />}
        <CopyField label="Signing secret" value={secret} />
        {children}
        <div className="flex items-center gap-2 rounded-lg border border-accent/25 bg-accent-soft px-3 py-2 text-xs text-fg-muted">
          <KeyRound className="size-4 shrink-0 text-accent" aria-hidden />
          Every request carries <code className="font-mono text-fg">X-Sentinel-Timestamp</code> and <code className="font-mono text-fg">X-Sentinel-Signature: v1=…</code> — an HMAC-SHA256 of
          “timestamp.body” with this secret.
        </div>
        <div className="flex justify-end"><Button variant="primary" onClick={onClose}>I saved it</Button></div>
      </div>
    </Dialog>
  )
}

const RUN: Record<RunStatus, { label: string; tone: 'ok' | 'critical' | 'warn' | 'neutral' | 'accent'; icon: typeof Check }> = {
  awaiting_approval: { label: 'Waiting for approval', tone: 'accent', icon: Clock3 },
  succeeded: { label: 'Done', tone: 'ok', icon: CircleCheck },
  failed: { label: 'Failed', tone: 'critical', icon: CircleAlert },
  rejected: { label: 'Rejected', tone: 'neutral', icon: CircleSlash },
  expired: { label: 'Expired', tone: 'neutral', icon: CircleDashed },
  skipped: { label: 'Paused', tone: 'warn', icon: CircleSlash },
}

export function RunBadge({ status }: { status: RunStatus }) {
  const s = RUN[status] ?? RUN.failed
  const Icon = s.icon
  return <Badge tone={s.tone}><Icon className="size-3" aria-hidden />{s.label}</Badge>
}

export function StepStatusIcon({ status }: { status: string }) {
  if (status === 'succeeded') return <CircleCheck className="size-4 shrink-0 text-ok" aria-label="done" />
  if (status === 'failed') return <CircleAlert className="size-4 shrink-0 text-critical" aria-label="failed" />
  if (status === 'waiting') return <Clock3 className="size-4 shrink-0 text-accent" aria-label="waiting" />
  return <CircleDashed className="size-4 shrink-0 text-fg-subtle" aria-label="skipped" />
}

export function ApprovalBadge({ required }: { required: boolean }) {
  return required
    ? <Badge tone="accent"><ShieldCheck className="size-3" aria-hidden />Needs approval</Badge>
    : <Badge tone="neutral">Runs automatically</Badge>
}

export function Switch({ on, onChange, label, disabled }: { on: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={cn('relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-50', on ? 'brand-gradient' : 'bg-ink-700')}
    >
      <span className={cn('absolute top-1 size-4 rounded-full bg-white shadow transition-all', on ? 'left-6' : 'left-1')} />
    </button>
  )
}

export const VERIFY_SNIPPET = `// Node.js / n8n Code node: verify a SENTINEL X webhook
const crypto = require('crypto')

function verify(rawBody, headers, secret) {
  const ts = headers['x-sentinel-timestamp']
  if (!ts || Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false
  const expected = 'v1=' + crypto.createHmac('sha256', secret)
    .update(ts + '.').update(rawBody).digest('hex')
  const given = String(headers['x-sentinel-signature'] || '')
  return given.split(/[ ,]+/).some((sig) =>
    sig.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)))
}`
