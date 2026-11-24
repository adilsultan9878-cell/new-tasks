/**
 * A light beam travelling around the border of its (relative, rounded) parent. Adapted from
 * Magic UI's BorderBeam (https://github.com/magicuidesign/magicui, MIT — see THIRD_PARTY_NOTICES.md).
 * Changes: pure CSS offset-path animation (keyframes in index.css) instead of the motion library.
 */
import type { CSSProperties } from 'react'

export function BorderBeam({ size = 120, duration = 9, from = 'var(--color-accent)', to = 'var(--color-violet)' }: {
  size?: number
  duration?: number
  from?: string
  to?: string
}) {
  return (
    <div className="border-beam pointer-events-none absolute inset-0 rounded-[inherit]" aria-hidden>
      <div
        className="border-beam-dot"
        style={{ width: size, offsetPath: `rect(0 auto auto 0 round ${size}px)`, animationDuration: `${duration}s`, '--beam-from': from, '--beam-to': to } as CSSProperties}
      />
    </div>
  )
}
