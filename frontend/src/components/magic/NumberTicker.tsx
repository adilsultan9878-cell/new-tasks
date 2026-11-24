/**
 * Counts up to a number once. Adapted from Magic UI's NumberTicker
 * (https://github.com/magicuidesign/magicui, MIT — see THIRD_PARTY_NOTICES.md).
 * Changes: requestAnimationFrame instead of the motion library; honours prefers-reduced-motion;
 * the target value is exposed as data-value.
 */
import { useEffect, useRef, useState } from 'react'

import { cn } from '@/lib/cn'

function reducedMotion(): boolean {
  return typeof window === 'undefined' || !window.matchMedia || window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

export function NumberTicker({ value, className, durationMs = 900 }: { value: number; className?: string; durationMs?: number }) {
  const reduce = reducedMotion()
  const [shown, setShown] = useState(0)
  const from = useRef(0)

  useEffect(() => {
    if (reduce || typeof requestAnimationFrame === 'undefined') return
    const start = performance.now()
    const begin = from.current
    let frame = 0
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs)
      const next = Math.round(begin + (value - begin) * (1 - Math.pow(1 - t, 3)))
      from.current = next
      setShown(next)
      if (t < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [value, durationMs, reduce])

  const display = reduce || typeof requestAnimationFrame === 'undefined' ? value : shown
  return (
    <span className={cn('tabular inline-block', className)} data-value={value}>
      {display.toLocaleString('en-US')}
    </span>
  )
}
