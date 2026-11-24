/**
 * Circular risk gauge. Adapted from Magic UI's AnimatedCircularProgressBar
 * (https://github.com/magicuidesign/magicui, MIT — see THIRD_PARTY_NOTICES.md).
 * Changes: colour follows the risk level, accessible meter semantics, no external deps.
 */
import type { CSSProperties, ReactNode } from 'react'

import { cn } from '@/lib/cn'

const R = 45
const CIRCUMFERENCE = 2 * Math.PI * R

export function RiskGauge({ value, color, label, children, className }: {
  value: number
  color: string
  label: string
  children?: ReactNode
  className?: string
}) {
  const pct = Math.max(0, Math.min(100, Math.round(value)))
  const dash = (pct / 100) * CIRCUMFERENCE
  return (
    <div className={cn('relative size-36', className)} role="meter" aria-label={label} aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
      <svg viewBox="0 0 100 100" className="size-full -rotate-90" aria-hidden>
        <circle cx="50" cy="50" r={R} fill="none" strokeWidth="8" className="stroke-ink-750" />
        <circle
          cx="50" cy="50" r={R} fill="none" strokeWidth="8" strokeLinecap="round"
          style={{ stroke: color, strokeDasharray: `${dash} ${CIRCUMFERENCE}`, transition: 'stroke-dasharray 1s ease, stroke 1s ease', filter: `drop-shadow(0 0 6px ${color})` } as CSSProperties}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">{children ?? <span className="tabular text-3xl font-semibold">{pct}</span>}</div>
    </div>
  )
}
