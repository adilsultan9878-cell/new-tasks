import type { LucideIcon } from 'lucide-react'

import { NumberTicker } from '@/components/magic/NumberTicker'
import { SpotlightCard } from '@/components/magic/SpotlightCard'
import { cn } from '@/lib/cn'
import { titleCase } from '@/lib/format'
import type { CountBy } from '@/lib/types'

export function KpiTile({ label, value, icon: Icon, sub, tone = 'neutral' }: {
  label: string
  value: number
  icon: LucideIcon
  sub: string
  tone?: 'neutral' | 'critical'
}) {
  const hot = tone === 'critical' && value > 0
  return (
    <SpotlightCard className={cn('overflow-hidden p-4 sm:p-5', hot && 'border-critical/30')}>
      {hot && <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-critical/70 to-transparent" aria-hidden />}
      <div className="flex items-start justify-between gap-2">
        <p className="text-[13px] font-medium text-fg-muted">{label}</p>
        <span className={cn('flex size-8 items-center justify-center rounded-lg border border-line', hot ? 'bg-critical/10 text-critical' : 'bg-ink-800 text-accent')}>
          <Icon className="size-4" aria-hidden />
        </span>
      </div>
      <p className={cn('mt-3 text-3xl font-semibold tracking-tight', hot ? 'text-critical' : 'text-fg')} data-testid={`kpi-${label}`}>
        <NumberTicker value={value} />
      </p>
      <p className="mt-1 truncate text-xs text-fg-subtle">{sub}</p>
    </SpotlightCard>
  )
}

const SEVERITY_STYLE: Record<string, { color: string; label: string }> = {
  critical: { color: 'var(--color-critical)', label: 'Critical' },
  high: { color: 'var(--color-high)', label: 'High' },
  medium: { color: 'var(--color-medium)', label: 'Medium' },
  low: { color: 'var(--color-low)', label: 'Low' },
  info: { color: 'var(--color-info)', label: 'Info' },
}

/** Open alerts by severity. Each row carries its name and count, so color is never the only cue. */
export function SeverityBars({ data }: { data: CountBy[] }) {
  const max = Math.max(1, ...data.map((d) => d.count))
  return (
    <ul className="space-y-3" aria-label="Open alerts by severity">
      {data.map((d) => {
        const style = SEVERITY_STYLE[d.key] ?? { color: 'var(--color-info)', label: titleCase(d.key) }
        return (
          <li key={d.key} className="grid grid-cols-[72px_1fr_36px] items-center gap-3 text-sm" title={`${style.label}: ${d.count} open`}>
            <span className="flex items-center gap-2 text-fg-muted">
              <span className="size-2 rounded-sm" style={{ background: style.color }} aria-hidden />
              {style.label}
            </span>
            <span className="h-2 overflow-hidden rounded-full bg-ink-750">
              <span className="block h-full rounded-full transition-[width] duration-500" style={{ width: `${(d.count / max) * 100}%`, background: style.color, minWidth: d.count ? 6 : 0 }} />
            </span>
            <span className="tabular text-right text-fg">{d.count}</span>
          </li>
        )
      })}
    </ul>
  )
}

const DEVICE_STATUS: Record<string, { color: string; label: string }> = {
  online: { color: 'var(--color-ok)', label: 'Online' },
  degraded: { color: 'var(--color-medium)', label: 'Degraded' },
  offline: { color: 'var(--color-critical)', label: 'Offline' },
  unknown: { color: 'var(--color-info)', label: 'Unknown' },
}

export function DeviceHealthBar({ data, total }: { data: CountBy[]; total: number }) {
  const ordered = ['online', 'degraded', 'offline', 'unknown']
    .map((k) => ({ key: k, count: data.find((d) => d.key === k)?.count ?? 0 }))
    .filter((d) => d.count > 0)
  return (
    <div>
      <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-full" role="img" aria-label={ordered.map((d) => `${DEVICE_STATUS[d.key]!.label} ${d.count}`).join(', ')}>
        {ordered.map((d) => (
          <span key={d.key} style={{ width: `${(d.count / total) * 100}%`, background: DEVICE_STATUS[d.key]!.color }} />
        ))}
      </div>
      <ul className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
        {Object.entries(DEVICE_STATUS).map(([key, s]) => (
          <li key={key} className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-2 text-fg-muted">
              <span className="size-2 rounded-sm" style={{ background: s.color }} aria-hidden />
              {s.label}
            </span>
            <span className="tabular text-fg">{data.find((d) => d.key === key)?.count ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
