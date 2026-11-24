import { Sparkles } from 'lucide-react'
import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'

import { Wordmark } from '@/components/ui/Logo'
import { MODULE_GROUPS, MODULES, type PlatformModule } from '@/config/modules'
import { cn } from '@/lib/cn'
import type { Membership } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

import { OrgSwitcher } from './OrgSwitcher'

function NavItem({ to, end, label, icon: Icon, collapsed, onNavigate, trailing }: {
  to: string
  end?: boolean
  label: string
  icon: PlatformModule['icon']
  collapsed: boolean
  onNavigate?: () => void
  trailing?: ReactNode
}) {
  return (
    <NavLink
      to={to}
      end={end}
      onClick={onNavigate}
      title={collapsed ? label : undefined}
      className={({ isActive }) =>
        cn(
          'group relative flex h-8 items-center gap-2.5 rounded-lg px-2.5 text-[13px] transition-colors',
          isActive ? 'bg-gradient-to-r from-accent/15 to-violet/10 text-fg' : 'text-fg-muted hover:bg-ink-800 hover:text-fg',
          collapsed && 'justify-center px-0',
        )
      }
    >
      {({ isActive }) => (
        <>
          {isActive && <span className="brand-gradient absolute inset-y-1.5 left-0 w-0.5 rounded-full" aria-hidden />}
          <Icon className={cn('size-4 shrink-0', isActive ? 'text-accent' : '')} aria-hidden />
          {!collapsed && (
            <>
              <span className="min-w-0 flex-1 truncate">{label}</span>
              {trailing}
            </>
          )}
        </>
      )}
    </NavLink>
  )
}

/** Simple navigation: only modules that work today. Planned ones live on the Roadmap page. */
export function Sidebar({ memberships, collapsed, onNavigate }: {
  memberships: Membership[]
  collapsed: boolean
  onNavigate?: () => void
}) {
  const { orgId, membership, can } = useOrg()
  const live = MODULES.filter((m) => m.status === 'live' && (!m.permission || can(m.permission)))
  const planned = MODULES.filter((m) => m.status === 'planned').length
  const base = `/org/${orgId}`
  return (
    <nav aria-label="Main" className="flex h-full flex-col">
      <div className={cn('flex h-14 items-center border-b border-line px-4', collapsed && 'justify-center px-2')}>
        <Wordmark compact={collapsed} />
      </div>
      <div className={cn('px-3 pt-3', collapsed && 'px-2')}>
        <OrgSwitcher memberships={memberships} current={membership} collapsed={collapsed} />
      </div>
      <div className="flex-1 space-y-4 overflow-y-auto px-3 py-3.5">
        {MODULE_GROUPS.map((group) => {
          const items = live.filter((m) => m.group === group.key)
          if (!items.length) return null
          return (
            <div key={group.key}>
              {!collapsed && group.key !== 'overview' && (
                <p className="mb-1 flex items-baseline justify-between px-2.5 text-[11px] font-semibold text-fg-subtle">
                  {group.label}
                  {group.caption && <span className="font-mono text-[9.5px] font-normal tracking-wider text-fg-subtle/60">{group.caption}</span>}
                </p>
              )}
              {collapsed && group.key !== 'overview' && <div className="mx-2 mb-2 border-t border-line" />}
              <div className="space-y-0.5">
                {items.map((m) => (
                  <NavItem key={m.key} to={`${base}${m.path ? `/${m.path}` : ''}`} end={m.path === ''} label={m.navName ?? m.name}
                    icon={m.icon} collapsed={collapsed} onNavigate={onNavigate} />
                ))}
              </div>
            </div>
          )
        })}
      </div>
      {planned > 0 && (
        <div className={cn('border-t border-line p-3', collapsed && 'px-2')}>
          <NavItem to={`${base}/roadmap`} label="What's next" icon={Sparkles} collapsed={collapsed} onNavigate={onNavigate}
            trailing={<span className="rounded-full bg-violet/15 px-1.5 py-px text-[10.5px] font-medium text-[#c4b5fd]">{planned}</span>} />
        </div>
      )}
    </nav>
  )
}
