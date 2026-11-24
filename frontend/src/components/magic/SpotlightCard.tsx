/**
 * Card whose border and surface light up where the pointer is. Adapted from Magic UI's MagicCard
 * (https://github.com/magicuidesign/magicui, MIT — see THIRD_PARTY_NOTICES.md).
 * Changes: CSS custom properties instead of the motion library; works as a plain card on touch.
 */
import type { HTMLAttributes, PointerEvent } from 'react'

import { cn } from '@/lib/cn'

export function SpotlightCard({ className, children, ...props }: HTMLAttributes<HTMLDivElement>) {
  const move = (e: PointerEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    e.currentTarget.style.setProperty('--mx', `${e.clientX - rect.left}px`)
    e.currentTarget.style.setProperty('--my', `${e.clientY - rect.top}px`)
  }
  return (
    <div onPointerMove={move} className={cn('spotlight-card', className)} {...props}>
      {children}
    </div>
  )
}
