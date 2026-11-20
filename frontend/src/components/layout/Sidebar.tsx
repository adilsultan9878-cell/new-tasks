import { NavLink } from 'react-router-dom'

import { PhaseBadge } from '@/components/ui/Badge'
import { Wordmark } from '@/components/ui/Logo'
import { MODULE_GROUPS, MODULES, type PlatformModule } from '@/config/modules'
import { cn } from '@/lib/cn'
import type { Membership } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

import { OrgSwitcher } from './OrgSwitcher'

function NavItem({ module, orgId, collapsed, onNavigate }: { module: PlatformModule; orgId: string; collapsed: boolean; onNavigate?: () => void }) {
  const Icon = module.icon
  const to = `/org/${orgId}${module.path ? `/${module.path}` : ''}`
  return (
    <NavLink
      to={to}
      end={module.path === ''}
      onClick={onNavigate}
      title={collapsed ? `${module.name}${module.status === 'planned' ? ` (Phase ${module.phase})` : ''}` : undefined}
      className={({ isActive }) =>
        cn(
          'group relative flex h-7 items-center gap-2.5 rounded-md px-2.5 text-[13px] transition-colors',
          isActive ? 'bg-ink-750 text-fg' : 'text-fg-muted hover:bg-ink-800 hover:text-fg',
          module.status === 'planned' && !isActive && 'text-fg-subtle',
          collapsed && 'justify-center px-0',
        )
      }
    >
      {({ isActive }) => (
        <>
          {isActive && <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-accent" aria-hidden />}
          <Icon className={cn('size-4 shrink-0', isActive ? 'text-accent' : '')} aria-hidden />
          {!collapsed && (
            <>
              <span className="min-w-0 flex-1 truncate">{module.navName ?? module.name}</span>
              {module.status === 'planned' && <PhaseBadge phase={module.phase} />}
            </>
          )}
        </>
      )}
    </NavLink>
  )
}

export function Sidebar({ memberships, collapsed, onNavigate }: {
  memberships: Membership[]
  collapsed: boolean
  onNavigate?: () => void
}) {
  const { orgId, membership, can } = useOrg()
  const visible = MODULES.filter((m) => !m.permission || can(m.permission))
  return (
    <nav aria-label="Main" className="flex h-full flex-col">
      <div className={cn('flex h-14 items-center border-b border-line px-4', collapsed && 'justify-center px-2')}>
        <Wordmark compact={collapsed} />
      </div>
      <div className={cn('px-3 pt-3', collapsed && 'px-2')}>
        <OrgSwitcher memberships={memberships} current={membership} collapsed={collapsed} />
      </div>
      <div className="flex-1 space-y-3.5 overflow-y-auto px-3 py-3.5">
        {MODULE_GROUPS.map((group) => {
          const items = visible.filter((m) => m.group === group.key)
          if (!items.length) return null
          return (
            <div key={group.key}>
              {!collapsed && group.key !== 'overview' && (
                <p className="mb-1 flex items-baseline gap-2 px-2.5 text-[10.5px] font-semibold uppercase tracking-[0.14em] text-fg-subtle">
                  {group.label}
                  {group.caption && <span className="font-normal normal-case tracking-normal text-fg-subtle/70">{group.caption}</span>}
                </p>
              )}
              {collapsed && group.key !== 'overview' && <div className="mx-2 mb-2 border-t border-line" />}
              <div className="space-y-0.5">
                {items.map((m) => (
                  <NavItem key={m.key} module={m} orgId={orgId} collapsed={collapsed} onNavigate={onNavigate} />
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </nav>
  )
}
