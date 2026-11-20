import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bell, BellOff } from 'lucide-react'

import { EmptyState } from '@/components/ui/EmptyState'
import { Popover } from '@/components/ui/Popover'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { relativeTime } from '@/lib/format'
import type { Notification } from '@/lib/types'
import { qk } from '@/org/queries'

export function Notifications() {
  const queryClient = useQueryClient()
  const { data } = useQuery({
    queryKey: qk.notifications,
    queryFn: () => api<{ items: Notification[]; unread: number }>('/notifications'),
    refetchInterval: 60_000,
  })
  const markRead = useMutation({
    mutationFn: (id: string) => api(`/notifications/${id}/read`, { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.notifications }),
  })
  const markAll = useMutation({
    mutationFn: () => api('/notifications/read-all', { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.notifications }),
  })
  const unread = data?.unread ?? 0

  return (
    <Popover
      label="Notifications"
      align="right"
      className="w-[min(22rem,calc(100vw-2rem))]"
      trigger={({ open, toggle }) => (
        <button
          onClick={toggle}
          aria-expanded={open}
          aria-label={unread ? `Notifications, ${unread} unread` : 'Notifications'}
          className="relative flex size-9 items-center justify-center rounded-lg text-fg-muted hover:bg-ink-800 hover:text-fg"
        >
          <Bell className="size-4" />
          {unread > 0 && (
            <span className="absolute right-1.5 top-1.5 flex min-w-4 items-center justify-center rounded-full bg-accent px-1 text-[10px] font-semibold leading-4 text-ink-900">
              {unread > 9 ? '9+' : unread}
            </span>
          )}
        </button>
      )}
    >
      {() => (
        <div>
          <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
            <p className="text-sm font-semibold">Notifications</p>
            {unread > 0 && (
              <button onClick={() => markAll.mutate()} className="text-xs text-accent hover:underline">
                Mark all read
              </button>
            )}
          </div>
          {!data?.items.length ? (
            <EmptyState icon={BellOff} title="You're all caught up">
              Membership changes appear here now; security alerts will once event ingestion ships (Phase 2).
            </EmptyState>
          ) : (
            <ul className="max-h-80 overflow-y-auto p-1.5">
              {data.items.map((n) => (
                <li key={n.id}>
                  <button
                    onClick={() => !n.read_at && markRead.mutate(n.id)}
                    className={cn('flex w-full gap-3 rounded-lg px-2.5 py-2 text-left hover:bg-ink-750', n.read_at && 'opacity-60')}
                  >
                    <span className={cn('mt-1.5 size-1.5 shrink-0 rounded-full', n.read_at ? 'bg-transparent' : 'bg-accent')} aria-hidden />
                    <span className="min-w-0">
                      <span className="block text-sm text-fg">{n.title}</span>
                      {n.body && <span className="block text-xs text-fg-subtle">{n.body}</span>}
                      <span className="mt-0.5 block text-[11px] text-fg-subtle">{relativeTime(n.created_at)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Popover>
  )
}
