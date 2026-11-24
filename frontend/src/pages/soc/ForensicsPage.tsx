import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { FileLock2 } from 'lucide-react'

import { PageHeader } from '@/components/layout/PageHeader'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import type { EvidenceItem, Page } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { EvidenceRow } from './IncidentPage'

export function ForensicsPage() {
  const { orgId } = useOrg()
  const evidence = useQuery({
    queryKey: qk.evidence(orgId, { limit: 100 }),
    queryFn: () => api<Page<EvidenceItem>>(`/organizations/${orgId}/evidence`, { query: { limit: 100 } }),
    placeholderData: keepPreviousData,
  })
  return (
    <div>
      <PageHeader eyebrow="SENTINEL X · Respond" title="Forensics Lab"
        description="The evidence vault across all incidents. Every item is hashed with SHA-256 when collected and cannot be changed; each download and verification is added to its chain of custody." />
      <Panel title="Evidence vault" description={evidence.data ? `${evidence.data.total} item${evidence.data.total === 1 ? '' : 's'}` : undefined}>
        {evidence.isPending ? <Skeleton className="h-32" /> : evidence.isError ? <ErrorNotice error={evidence.error} />
          : evidence.data.items.length === 0 ? <EmptyState icon={FileLock2} title="No evidence yet">Add files, notes or hashes from an incident.</EmptyState>
          : <ul className="space-y-2.5">{evidence.data.items.map((e) => <EvidenceRow key={e.id} item={e} showIncident />)}</ul>}
      </Panel>
    </div>
  )
}
