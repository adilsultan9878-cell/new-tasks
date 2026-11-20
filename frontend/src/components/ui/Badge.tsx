import type { ReactNode } from 'react'

import { cn } from '@/lib/cn'

type Tone = 'neutral' | 'accent' | 'ok' | 'warn' | 'critical' | 'info'

const tones: Record<Tone, string> = {
  neutral: 'bg-ink-750 text-fg-muted border-line-strong',
  accent: 'bg-accent-soft text-accent border-accent/25',
  ok: 'bg-ok/10 text-ok border-ok/25',
  warn: 'bg-medium/10 text-medium border-medium/25',
  critical: 'bg-critical/10 text-critical border-critical/30',
  info: 'bg-low/10 text-[#7fb0f0] border-low/25',
}

export function Badge({ tone = 'neutral', children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-none', tones[tone], className)}>
      {children}
    </span>
  )
}

export function PhaseBadge({ phase }: { phase: number }) {
  return (
    <span className="rounded border border-line-strong px-1 py-px font-mono text-[10px] leading-none text-fg-subtle" title={`Scheduled for Phase ${phase}`}>
      P{phase}
    </span>
  )
}
