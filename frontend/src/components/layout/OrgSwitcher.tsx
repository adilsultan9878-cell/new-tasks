import { Check, ChevronsUpDown, Plus } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'

import { Popover } from '@/components/ui/Popover'
import { cn } from '@/lib/cn'
import type { Membership } from '@/lib/types'

export function OrgSwitcher({ memberships, current, collapsed }: { memberships: Membership[]; current: Membership; collapsed?: boolean }) {
  const navigate = useNavigate()
  const org = current.organization
  return (
    <Popover
      label="Switch organization"
      className="w-64 p-1.5"
      trigger={({ open, toggle }) => (
        <button
          onClick={toggle}
          aria-expanded={open}
          aria-label={`Organization: ${org.name}. Switch organization`}
          className={cn(
            'flex w-full items-center gap-2.5 rounded-lg border border-line bg-ink-850 p-2 text-left transition-colors hover:border-line-strong hover:bg-ink-800',
            collapsed && 'justify-center p-1.5',
          )}
        >
          <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-gradient-to-br from-accent/25 to-electric/25 text-[11px] font-bold text-accent">
            {org.name.slice(0, 2).toUpperCase()}
          </span>
          {!collapsed && (
            <>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[13px] font-medium text-fg">{org.name}</span>
                <span className="block truncate text-[11px] text-fg-subtle">{current.role.name}</span>
              </span>
              <ChevronsUpDown className="size-3.5 shrink-0 text-fg-subtle" aria-hidden />
            </>
          )}
        </button>
      )}
    >
      {(close) => (
        <div>
          <p className="px-2 pb-1 pt-1.5 text-[11px] font-medium uppercase tracking-wider text-fg-subtle">Organizations</p>
          <ul>
            {memberships.map((m) => (
              <li key={m.organization.id}>
                <button
                  onClick={() => {
                    close()
                    navigate(`/org/${m.organization.id}`)
                  }}
                  className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-ink-750"
                >
                  <span className="min-w-0 flex-1 truncate">{m.organization.name}</span>
                  <span className="text-[11px] text-fg-subtle">{m.role.name}</span>
                  {m.organization.id === org.id && <Check className="size-3.5 text-accent" aria-label="Current" />}
                </button>
              </li>
            ))}
          </ul>
          <div className="mt-1 border-t border-line pt-1">
            <Link to="/onboarding" onClick={close} className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg-muted hover:bg-ink-750 hover:text-fg">
              <Plus className="size-3.5" /> New organization
            </Link>
          </div>
        </div>
      )}
    </Popover>
  )
}
