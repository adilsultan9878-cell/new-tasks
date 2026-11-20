import { LogOut, Settings } from 'lucide-react'
import { Link } from 'react-router-dom'

import { useAuth } from '@/auth/AuthContext'
import { Avatar } from '@/components/ui/Avatar'
import { Popover } from '@/components/ui/Popover'
import { useOrg } from '@/org/OrgContext'

export function UserMenu() {
  const { user, logout } = useAuth()
  const { orgId, membership } = useOrg()
  if (!user) return null
  return (
    <Popover
      label="Account"
      align="right"
      className="w-64 p-1.5"
      trigger={({ open, toggle }) => (
        <button onClick={toggle} aria-expanded={open} aria-label="Account menu" className="flex items-center gap-2 rounded-lg p-1 hover:bg-ink-800">
          <Avatar name={user.full_name} />
        </button>
      )}
    >
      {(close) => (
        <div>
          <div className="px-2.5 py-2">
            <p className="truncate text-sm font-medium text-fg">{user.full_name}</p>
            <p className="truncate text-xs text-fg-subtle">{user.email}</p>
            <p className="mt-1.5 text-[11px] text-fg-subtle">
              {membership.role.name} · {membership.organization.name}
            </p>
          </div>
          <div className="my-1 border-t border-line" />
          <Link to={`/org/${orgId}/settings`} onClick={close} className="flex items-center gap-2 rounded-md px-2.5 py-1.5 text-sm text-fg-muted hover:bg-ink-750 hover:text-fg">
            <Settings className="size-4" /> Account & security
          </Link>
          <button
            onClick={() => {
              close()
              void logout()
            }}
            className="flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-sm text-fg-muted hover:bg-ink-750 hover:text-fg"
          >
            <LogOut className="size-4" /> Sign out
          </button>
        </div>
      )}
    </Popover>
  )
}
