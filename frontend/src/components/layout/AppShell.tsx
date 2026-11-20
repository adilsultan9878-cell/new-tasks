import { Menu, PanelLeftClose, PanelLeftOpen, Search, X } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'

import { cn } from '@/lib/cn'
import { readPref, writePref } from '@/lib/storage'
import type { Membership } from '@/lib/types'

import { CommandPalette } from './CommandPalette'
import { Notifications } from './Notifications'
import { Sidebar } from './Sidebar'
import { UserMenu } from './UserMenu'

export function AppShell({ memberships }: { memberships: Membership[] }) {
  const [collapsed, setCollapsed] = useState(() => readPref('sidebar-collapsed') === '1')
  const [paletteOpen, setPaletteOpen] = useState(false)
  const location = useLocation()
  // The drawer remembers the path it was opened on, so any navigation closes it.
  const [drawerPath, setDrawerPath] = useState<string | null>(null)
  const mobileOpen = drawerPath === location.pathname
  const setMobileOpen = (open: boolean) => setDrawerPath(open ? location.pathname : null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen(true)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const toggle = () =>
    setCollapsed((c) => {
      writePref('sidebar-collapsed', c ? '0' : '1')
      return !c
    })
  const closePalette = useCallback(() => setPaletteOpen(false), [])
  const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)

  return (
    <div className="flex min-h-screen">
      {/* Desktop sidebar */}
      <aside
        className={cn(
          'sticky top-0 hidden h-screen shrink-0 border-r border-line bg-ink-900/70 backdrop-blur-md transition-[width] duration-200 lg:block',
          collapsed ? 'w-[68px]' : 'w-64',
        )}
      >
        <Sidebar memberships={memberships} collapsed={collapsed} />
      </aside>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <div className="absolute inset-0 animate-fade-in bg-black/60 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-72 max-w-[85vw] animate-rise border-r border-line bg-ink-900">
            <button onClick={() => setMobileOpen(false)} className="absolute right-3 top-3.5 z-10 rounded-md p-1.5 text-fg-subtle hover:bg-ink-800" aria-label="Close navigation">
              <X className="size-4" />
            </button>
            <Sidebar memberships={memberships} collapsed={false} onNavigate={() => setMobileOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-line bg-canvas/75 px-4 backdrop-blur-md sm:px-6">
          <button onClick={() => setMobileOpen(true)} className="-ml-1.5 rounded-md p-1.5 text-fg-muted hover:bg-ink-800 lg:hidden" aria-label="Open navigation">
            <Menu className="size-5" />
          </button>
          <button
            onClick={toggle}
            className="-ml-1.5 hidden rounded-md p-1.5 text-fg-subtle hover:bg-ink-800 hover:text-fg lg:block"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
          </button>
          <button
            onClick={() => setPaletteOpen(true)}
            className="flex h-9 w-full max-w-md items-center gap-2.5 rounded-lg border border-line bg-ink-900/80 px-3 text-sm text-fg-subtle transition-colors hover:border-line-strong hover:text-fg-muted"
            aria-label="Search (Ctrl+K)"
          >
            <Search className="size-4" aria-hidden />
            <span className="flex-1 truncate text-left">Search modules and actions…</span>
            <kbd className="hidden rounded border border-line-strong px-1.5 py-0.5 font-mono text-[10px] sm:inline">{isMac ? '⌘' : 'Ctrl'} K</kbd>
          </button>
          <div className="ml-auto flex items-center gap-1">
            <Notifications />
            <UserMenu />
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6 lg:py-8">
          <Outlet />
        </main>
      </div>
      <CommandPalette open={paletteOpen} onClose={closePalette} memberships={memberships} />
    </div>
  )
}
