import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, ScrollText } from 'lucide-react'
import { useState } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { dateTime, relativeTime } from '@/lib/format'
import type { AuditLog, Page } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

const PAGE_SIZE = 25
const ACTION_FILTERS = [
  ['', 'All actions'],
  ['org.', 'Organization'],
  ['member.', 'Membership'],
  ['authz.', 'Authorization'],
] as const

export function AuditLogPage() {
  const { orgId } = useOrg()
  const [offset, setOffset] = useState(0)
  const [action, setAction] = useState('')
  const [outcome, setOutcome] = useState('')
  const params = { limit: PAGE_SIZE, offset, action, outcome }
  const logs = useQuery({
    queryKey: qk.audit(orgId, params),
    queryFn: () => api<Page<AuditLog>>(`/organizations/${orgId}/audit-logs`, { query: params }),
    placeholderData: keepPreviousData,
  })
  const total = logs.data?.total ?? 0

  return (
    <div>
      <PageHeader eyebrow="Administration" title="Audit log" description="Append-only trail of security-relevant actions in this organization — including failures and permission denials. Records cannot be edited or deleted through the platform." />
      <Panel
        title="Events"
        description={logs.data ? `${total} record${total === 1 ? '' : 's'}` : undefined}
        flush
        actions={
          <div className="flex gap-2">
            <Select aria-label="Filter by action" className="h-8 w-36 text-xs" value={action} onChange={(e) => { setAction(e.target.value); setOffset(0) }}>
              {ACTION_FILTERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
            <Select aria-label="Filter by outcome" className="h-8 w-32 text-xs" value={outcome} onChange={(e) => { setOutcome(e.target.value); setOffset(0) }}>
              <option value="">Any outcome</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="denied">Denied</option>
            </Select>
          </div>
        }
      >
        {logs.isPending ? (
          <div className="space-y-3 p-5">{Array.from({ length: 5 }, (_, i) => <Skeleton key={i} className="h-9" />)}</div>
        ) : logs.isError ? (
          <div className="p-5"><ErrorNotice error={logs.error} /></div>
        ) : logs.data.items.length === 0 ? (
          <EmptyState icon={ScrollText} title="No matching audit records" />
        ) : (
          <div className="relative overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-fg-subtle">
                  <th className="px-5 py-2.5 font-medium">Time</th>
                  <th className="px-3 py-2.5 font-medium">Action</th>
                  <th className="px-3 py-2.5 font-medium">Actor</th>
                  <th className="px-3 py-2.5 font-medium">Details</th>
                  <th className="px-5 py-2.5 font-medium">Outcome</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {logs.data.items.map((log) => (
                  <tr key={log.id} className="align-top hover:bg-ink-850/60">
                    <td className="whitespace-nowrap px-5 py-2.5 text-fg-muted" title={dateTime(log.created_at)}>{relativeTime(log.created_at)}</td>
                    <td className="px-3 py-2.5 font-mono text-xs text-fg">{log.action}</td>
                    <td className="px-3 py-2.5">
                      <span className="block text-fg">{log.actor?.full_name ?? (log.actor_type === 'user' ? 'Deleted user' : log.actor_type)}</span>
                      {log.ip_address && <span className="font-mono text-[11px] text-fg-subtle">{log.ip_address}</span>}
                    </td>
                    <td className="max-w-xs px-3 py-2.5 text-xs text-fg-muted">
                      {Object.entries(log.details).map(([k, v]) => (
                        <span key={k} className="mr-2 inline-block">
                          <span className="text-fg-subtle">{k}:</span> {Array.isArray(v) ? v.join(', ') : String(v)}
                        </span>
                      ))}
                      {log.request_id && <span className="block font-mono text-[10px] text-fg-subtle">req {log.request_id.slice(0, 12)}</span>}
                    </td>
                    <td className="px-5 py-2.5">
                      <Badge tone={log.outcome === 'success' ? 'ok' : log.outcome === 'denied' ? 'critical' : 'warn'}>{log.outcome}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between border-t border-line px-5 py-3 text-xs text-fg-subtle">
            <span>{offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}</span>
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" icon={<ChevronLeft className="size-3.5" />} disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>Previous</Button>
              <Button size="sm" variant="secondary" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset((o) => o + PAGE_SIZE)}>Next <ChevronRight className="size-3.5" /></Button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  )
}
