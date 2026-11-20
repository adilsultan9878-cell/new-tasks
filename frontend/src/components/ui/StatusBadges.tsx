import { cn } from '@/lib/cn'
import type { DeviceStatus, Severity } from '@/lib/types'

const SEVERITY: Record<Severity, { label: string; cls: string; dot: string }> = {
  critical: { label: 'Critical', cls: 'border-critical/35 bg-critical/10 text-[#ff8f93]', dot: 'bg-critical' },
  high: { label: 'High', cls: 'border-high/35 bg-high/10 text-high', dot: 'bg-high' },
  medium: { label: 'Medium', cls: 'border-medium/30 bg-medium/10 text-medium', dot: 'bg-medium' },
  low: { label: 'Low', cls: 'border-low/30 bg-low/10 text-[#7fb0f0]', dot: 'bg-low' },
  info: { label: 'Info', cls: 'border-line-strong bg-ink-750 text-fg-muted', dot: 'bg-info' },
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = SEVERITY[severity as Severity] ?? SEVERITY.info
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-none', s.cls)}>
      <span className={cn('size-1.5 rounded-full', s.dot)} aria-hidden />
      {s.label}
    </span>
  )
}

const DEVICE: Record<DeviceStatus, { label: string; dot: string; text: string }> = {
  online: { label: 'Online', dot: 'bg-ok', text: 'text-ok' },
  degraded: { label: 'Degraded', dot: 'bg-medium', text: 'text-medium' },
  offline: { label: 'Offline', dot: 'bg-critical', text: 'text-[#ff8f93]' },
  unknown: { label: 'Unknown', dot: 'bg-info', text: 'text-fg-muted' },
  decommissioned: { label: 'Revoked', dot: 'bg-ink-600', text: 'text-fg-subtle' },
}

export function DeviceStatusBadge({ status }: { status: DeviceStatus }) {
  const s = DEVICE[status] ?? DEVICE.unknown
  return (
    <span className={cn('inline-flex items-center gap-1.5 text-xs font-medium', s.text)}>
      <span className={cn('size-2 rounded-full', s.dot, status === 'online' && 'animate-pulse-dot')} aria-hidden />
      {s.label}
    </span>
  )
}

export function Meter({ label, value, warnAt = 80, critAt = 90 }: { label: string; value: number | undefined; warnAt?: number; critAt?: number }) {
  const v = value ?? 0
  const color = value === undefined ? 'bg-ink-600' : v >= critAt ? 'bg-critical' : v >= warnAt ? 'bg-medium' : 'bg-accent'
  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between text-xs">
        <span className="text-fg-muted">{label}</span>
        <span className="tabular font-medium text-fg">{value === undefined ? '—' : `${v.toFixed(0)}%`}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-ink-750" role="meter" aria-label={label} aria-valuenow={v} aria-valuemin={0} aria-valuemax={100}>
        <div className={cn('h-full rounded-full transition-[width] duration-500', color)} style={{ width: `${Math.min(100, v)}%` }} />
      </div>
    </div>
  )
}
