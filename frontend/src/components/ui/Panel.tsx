import type { ReactNode } from 'react'

import { cn } from '@/lib/cn'

interface PanelProps {
  title?: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
  /** Remove body padding (tables that run edge to edge). */
  flush?: boolean
}

export function Panel({ title, description, actions, children, className, bodyClassName, flush }: PanelProps) {
  return (
    <section className={cn('panel animate-rise', className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3 sm:px-5">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold tracking-tight text-fg">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-fg-subtle">{description}</p>}
          </div>
          {actions && <div className="flex max-w-full flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn(!flush && 'p-4 sm:p-5', bodyClassName)}>{children}</div>
    </section>
  )
}
