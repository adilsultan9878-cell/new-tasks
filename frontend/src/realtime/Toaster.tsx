import { ShieldAlert, X } from 'lucide-react'
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'

import { cn } from '@/lib/cn'

interface Toast {
  id: number
  title: string
  body?: string
  tone: 'critical' | 'info'
}

interface ToastApi {
  push: (toast: Omit<Toast, 'id'>) => void
}

const ToastContext = createContext<ToastApi>({ push: () => {} })
const MAX_VISIBLE = 4
const TTL_MS = 7000

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), [])
  const push = useCallback(
    (toast: Omit<Toast, 'id'>) => {
      const id = Date.now() + Math.random()
      setToasts((t) => [...t.slice(-(MAX_VISIBLE - 1)), { ...toast, id }])
      window.setTimeout(() => dismiss(id), TTL_MS)
    },
    [dismiss],
  )
  const api = useMemo(() => ({ push }), [push])
  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(22rem,calc(100vw-2rem))] flex-col gap-2" aria-live="assertive" role="region" aria-label="Live alerts">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="alert"
            className={cn(
              'pointer-events-auto flex animate-rise items-start gap-3 rounded-xl border bg-ink-850/95 p-3 shadow-2xl shadow-black/50 backdrop-blur-md',
              t.tone === 'critical' ? 'border-critical/35' : 'border-line-strong',
            )}
          >
            <ShieldAlert className={cn('mt-0.5 size-4 shrink-0', t.tone === 'critical' ? 'text-critical' : 'text-accent')} aria-hidden />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-fg">{t.title}</p>
              {t.body && <p className="mt-0.5 truncate text-xs text-fg-muted">{t.body}</p>}
            </div>
            <button onClick={() => dismiss(t.id)} className="rounded p-0.5 text-fg-subtle hover:text-fg" aria-label="Dismiss">
              <X className="size-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToasts(): ToastApi {
  return useContext(ToastContext)
}
