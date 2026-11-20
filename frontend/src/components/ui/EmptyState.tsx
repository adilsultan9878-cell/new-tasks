import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'

import { cn } from '@/lib/cn'

export function EmptyState({ icon: Icon, title, children, action, className }: {
  icon: LucideIcon
  title: string
  children?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-col items-center justify-center px-4 py-6 text-center', className)}>
      <div className="mb-3 flex size-10 items-center justify-center rounded-xl border border-line-strong bg-ink-800 text-fg-subtle">
        <Icon className="size-5" aria-hidden />
      </div>
      <p className="text-sm font-medium text-fg">{title}</p>
      {children && <p className="mt-1 max-w-xs text-xs leading-relaxed text-fg-subtle">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
