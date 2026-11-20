import { X } from 'lucide-react'
import { useEffect, useRef, type ReactNode } from 'react'

/** Accessible modal built on the native <dialog> element (focus trap + Esc handled by the browser). */
export function Dialog({ open, onClose, title, description, children }: {
  open: boolean
  onClose: () => void
  title: string
  description?: string
  children: ReactNode
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (open && !el.open) el.showModal()
    if (!open && el.open) el.close()
  }, [open])
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => e.target === ref.current && onClose()}
      className="m-auto w-[calc(100%-2rem)] max-w-md rounded-xl border border-line-strong bg-ink-850 p-0 text-fg shadow-2xl backdrop:bg-black/60 backdrop:backdrop-blur-sm open:animate-rise"
      aria-labelledby="dialog-title"
    >
      <div className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
        <div>
          <h2 id="dialog-title" className="text-sm font-semibold">{title}</h2>
          {description && <p className="mt-1 text-xs text-fg-subtle">{description}</p>}
        </div>
        <button onClick={onClose} className="rounded-md p-1 text-fg-subtle hover:bg-ink-750 hover:text-fg" aria-label="Close dialog">
          <X className="size-4" />
        </button>
      </div>
      <div className="px-5 py-4">{children}</div>
    </dialog>
  )
}
