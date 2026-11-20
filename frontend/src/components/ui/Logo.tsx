import { cn } from '@/lib/cn'

export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={cn('size-8', className)} aria-hidden>
      <defs>
        <linearGradient id="sx-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#22d3ee" />
          <stop offset="1" stopColor="#3b82f6" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="9" fill="#0c1016" stroke="rgb(148 163 184 / 0.18)" />
      <path d="M16 5.5l8.5 3.3v6.4c0 5.3-3.6 9.5-8.5 11.2-4.9-1.7-8.5-5.9-8.5-11.2V8.8L16 5.5z" fill="none" stroke="url(#sx-g)" strokeWidth="1.8" />
      <path d="M11.8 16.2l2.9 2.9 5.6-6.1" fill="none" stroke="#22d3ee" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function Wordmark({ compact = false }: { compact?: boolean }) {
  return (
    <span className="flex items-center gap-2.5">
      <LogoMark />
      {!compact && (
        <span className="leading-none">
          <span className="block text-[13px] font-semibold tracking-[0.14em] text-fg">SENTINEL X</span>
          <span className="mt-1 block text-[10px] font-medium tracking-[0.22em] text-fg-subtle">AEGIS NEXUS</span>
        </span>
      )}
    </span>
  )
}
