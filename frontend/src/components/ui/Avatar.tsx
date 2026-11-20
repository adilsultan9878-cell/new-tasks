import { cn } from '@/lib/cn'
import { initials } from '@/lib/format'

export function Avatar({ name, className }: { name: string; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex size-8 shrink-0 items-center justify-center rounded-full border border-line-strong bg-gradient-to-br from-ink-700 to-ink-800 text-[11px] font-semibold text-fg',
        className,
      )}
      aria-hidden
    >
      {initials(name)}
    </span>
  )
}
