import { Building2, CornerDownLeft, LogOut, Plus, Search } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type ComponentType } from 'react'
import { useNavigate } from 'react-router-dom'

import { useAuth } from '@/auth/AuthContext'
import { MODULES } from '@/config/modules'
import { cn } from '@/lib/cn'
import type { Membership } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

interface Item {
  id: string
  label: string
  hint: string
  icon: ComponentType<{ className?: string }>
  run: () => void
}

/** Global search (Ctrl/⌘+K) over modules, organizations and account actions. */
export function CommandPalette({ open, onClose, memberships }: { open: boolean; onClose: () => void; memberships: Membership[] }) {
  const navigate = useNavigate()
  const { logout } = useAuth()
  const { orgId, can } = useOrg()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const dialogRef = useRef<HTMLDialogElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const items = useMemo<Item[]>(() => {
    const go = (path: string) => () => {
      onClose()
      navigate(path)
    }
    return [
      ...MODULES.filter((m) => !m.permission || can(m.permission)).map((m) => ({
        id: `m-${m.key}`,
        label: m.name,
        hint: m.status === 'live' ? 'Module' : `Planned · Phase ${m.phase}`,
        icon: m.icon,
        run: go(`/org/${orgId}${m.path ? `/${m.path}` : ''}`),
      })),
      ...memberships
        .filter((m) => m.organization.id !== orgId)
        .map((m) => ({ id: `o-${m.organization.id}`, label: `Switch to ${m.organization.name}`, hint: 'Organization', icon: Building2, run: go(`/org/${m.organization.id}`) })),
      { id: 'new-org', label: 'Create organization', hint: 'Action', icon: Plus, run: go('/onboarding') },
      { id: 'logout', label: 'Sign out', hint: 'Action', icon: LogOut, run: () => { onClose(); void logout() } },
    ]
  }, [memberships, orgId, can, navigate, onClose, logout])

  const q = query.trim().toLowerCase()
  const filtered = q ? items.filter((i) => i.label.toLowerCase().includes(q) || i.hint.toLowerCase().includes(q)) : items

  useEffect(() => {
    const el = dialogRef.current
    if (!el) return
    if (open && !el.open) {
      setQuery('')
      setActive(0)
      el.showModal()
      requestAnimationFrame(() => inputRef.current?.focus())
    }
    if (!open && el.open) el.close()
  }, [open])

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((a) => Math.min(a + 1, filtered.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => Math.max(a - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      filtered[active]?.run()
    }
  }

  return (
    <dialog
      ref={dialogRef}
      onClose={onClose}
      onClick={(e) => e.target === dialogRef.current && onClose()}
      aria-label="Search"
      className="mx-auto mt-[12vh] w-[calc(100%-2rem)] max-w-xl rounded-xl border border-line-strong bg-ink-850 p-0 text-fg shadow-2xl backdrop:bg-black/60 backdrop:backdrop-blur-sm"
    >
      <div className="flex items-center gap-2.5 border-b border-line px-4">
        <Search className="size-4 text-fg-subtle" aria-hidden />
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value)
            setActive(0)
          }}
          onKeyDown={onKeyDown}
          placeholder="Search modules, organizations, actions…"
          className="h-12 flex-1 bg-transparent text-sm text-fg placeholder:text-fg-subtle focus:outline-none"
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-results"
          aria-activedescendant={filtered[active] ? `palette-${filtered[active].id}` : undefined}
        />
        <kbd className="rounded border border-line-strong px-1.5 py-0.5 font-mono text-[10px] text-fg-subtle">ESC</kbd>
      </div>
      <ul id="palette-results" role="listbox" className="max-h-[50vh] overflow-y-auto p-1.5">
        {filtered.length === 0 && <li className="px-3 py-6 text-center text-sm text-fg-subtle">No results for “{query}”</li>}
        {filtered.map((item, idx) => {
          const Icon = item.icon
          return (
            <li
              key={item.id}
              id={`palette-${item.id}`}
              role="option"
              aria-selected={idx === active}
              onMouseEnter={() => setActive(idx)}
              onClick={item.run}
              className={cn('flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm', idx === active ? 'bg-ink-750 text-fg' : 'text-fg-muted')}
            >
              <Icon className="size-4 shrink-0" />
              <span className="flex-1 truncate">{item.label}</span>
              <span className="text-[11px] text-fg-subtle">{item.hint}</span>
              {idx === active && <CornerDownLeft className="size-3.5 text-fg-subtle" aria-hidden />}
            </li>
          )
        })}
      </ul>
    </dialog>
  )
}
