import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileSearch } from 'lucide-react'
import { useState } from 'react'

import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { relativeTime } from '@/lib/format'
import type { Investigation, InvestigationDetail, Page, SubjectType } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { InvestigationView, VerdictBadge } from './InvestigationView'

export function useRunInvestigation(onDone: (inv: InvestigationDetail) => void) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { subject_type: SubjectType; subject: string }) =>
      api<InvestigationDetail>(`/organizations/${orgId}/investigations`, { method: 'POST', body }),
    onSuccess: (inv) => {
      onDone(inv)
      void queryClient.invalidateQueries({ queryKey: ['investigations', orgId] })
      void queryClient.invalidateQueries({ queryKey: ['indicators', orgId] })
    },
  })
}

export function InvestigationHistory({ types, title = 'Recent investigations' }: { types: SubjectType[]; title?: string }) {
  const { orgId } = useOrg()
  const [open, setOpen] = useState<string | null>(null)
  const key = types.join(',')
  const list = useQuery({
    queryKey: qk.investigations(orgId, key),
    queryFn: () => api<Page<Investigation>>(`/organizations/${orgId}/investigations`, { query: { subject_type: key, limit: 20 } }),
  })
  return (
    <Panel title={title} description={list.data ? `${list.data.total} total` : undefined} flush>
      {list.isPending ? <div className="space-y-2 p-5"><Skeleton className="h-9" /><Skeleton className="h-9" /></div>
        : list.isError ? <div className="p-5"><ErrorNotice error={list.error} /></div>
        : list.data.items.length === 0 ? <EmptyState icon={FileSearch} title="No investigations yet">Results are saved here with their evidence and timeline.</EmptyState>
        : (
          <ul className="divide-y divide-line">
            {list.data.items.map((inv) => (
              <li key={inv.id}>
                <button onClick={() => setOpen(inv.id)} className="flex w-full items-center gap-3 px-5 py-2.5 text-left text-sm hover:bg-ink-850/60">
                  <VerdictBadge verdict={inv.verdict} />
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg" title={inv.subject}>{inv.subject}</span>
                  <span className="tabular w-10 text-right text-xs text-fg-muted">{inv.risk_score ?? '—'}</span>
                  <span className="w-20 text-right text-xs text-fg-subtle">{relativeTime(inv.created_at)}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      {open && <InvestigationDialog id={open} onClose={() => setOpen(null)} />}
    </Panel>
  )
}

export function InvestigationDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const { orgId } = useOrg()
  const detail = useQuery({ queryKey: qk.investigation(orgId, id), queryFn: () => api<InvestigationDetail>(`/organizations/${orgId}/investigations/${id}`) })
  return (
    <Dialog open onClose={onClose} size="xl" title={detail.data?.title ?? 'Investigation'} description={detail.data ? `Investigation ${detail.data.id.slice(0, 8)}` : undefined}>
      {detail.isError ? <ErrorNotice error={detail.error} /> : detail.data ? <InvestigationView inv={detail.data} /> : <Skeleton className="h-64" />}
    </Dialog>
  )
}
