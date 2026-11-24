import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bug, ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react'
import { useState } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog } from '@/components/ui/Dialog'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Input } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api } from '@/lib/api'
import { cn } from '@/lib/cn'
import { dateTime, formatNumber, relativeTime } from '@/lib/format'
import type { Page, Vulnerability, VulnerabilityDetail, VulnerabilityStats } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

import { SafeExternalLink } from './InvestigationView'

const PAGE = 25

function Cvss({ score }: { score: number | null }) {
  if (score === null) return <span className="text-fg-subtle">—</span>
  const cls = score >= 9 ? 'text-critical' : score >= 7 ? 'text-high' : score >= 4 ? 'text-medium' : 'text-fg-muted'
  return <span className={cn('tabular font-semibold', cls)}>{score.toFixed(1)}</span>
}

export function VulnerabilitiesPage() {
  const { orgId, can } = useOrg()
  const queryClient = useQueryClient()
  const [q, setQ] = useState('')
  const [ransomware, setRansomware] = useState(false)
  const [offset, setOffset] = useState(0)
  const [cve, setCve] = useState<string | null>(null)
  const params = { q, kev_only: true, ransomware_only: ransomware, limit: PAGE, offset }
  const stats = useQuery({ queryKey: qk.vulnStats, queryFn: () => api<VulnerabilityStats>('/vulnerabilities/stats') })
  const list = useQuery({ queryKey: qk.vulns(params), queryFn: () => api<Page<Vulnerability>>('/vulnerabilities', { query: params }), placeholderData: keepPreviousData })
  const sync = useMutation({
    mutationFn: () => api<{ total: number; added: number; catalog_version: string }>(`/organizations/${orgId}/vulnerabilities/sync-kev`, { method: 'POST' }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] }),
  })
  const lookup = q.trim().toUpperCase()
  const isCve = /^CVE-\d{4}-\d{4,7}$/.test(lookup)
  const total = list.data?.total ?? 0

  return (
    <div>
      <PageHeader eyebrow="NEXUS ZERO · Threat hunting" title="Vulnerability Intelligence"
        description="CISA's catalogue of vulnerabilities known to be exploited in the wild, enriched on demand with CVSS data from NIST's National Vulnerability Database."
        actions={can('intel:manage') && <Button icon={<RefreshCw className={cn('size-4', sync.isPending && 'animate-spin')} />} loading={sync.isPending} onClick={() => sync.mutate()}>Refresh from CISA</Button>} />
      {sync.error && <div className="mb-4"><ErrorNotice error={sync.error} /></div>}
      {sync.data && <p className="mb-4 rounded-lg border border-ok/25 bg-ok/[0.07] px-3 py-2 text-sm text-ok" role="status">Catalogue {sync.data.catalog_version}: {formatNumber(sync.data.total)} entries ({sync.data.added} new).</p>}

      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[['Known exploited', stats.data?.kev_total], ['Used by ransomware', stats.data?.ransomware_total], ['CVEs cached', stats.data?.total]].map(([label, value]) => (
          <div key={String(label)} className="panel px-4 py-3">
            <p className="text-xs text-fg-muted">{label}</p>
            <p className="tabular mt-1 text-2xl font-semibold">{value === undefined ? '—' : formatNumber(Number(value))}</p>
          </div>
        ))}
        <div className="panel px-4 py-3">
          <p className="text-xs text-fg-muted">Last refreshed</p>
          <p className="mt-1 text-sm font-medium">{stats.data?.last_kev_sync ? relativeTime(stats.data.last_kev_sync) : 'Never'}</p>
        </div>
      </div>

      <Panel title="CISA Known Exploited Vulnerabilities" description={list.data ? `${formatNumber(total)} matching` : undefined} flush
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-1.5 text-xs text-fg-muted"><input type="checkbox" className="accent-[var(--color-accent)]" checked={ransomware} onChange={(e) => { setRansomware(e.target.checked); setOffset(0) }} /> Ransomware only</label>
            <Input aria-label="Search CVE, vendor or product" placeholder="CVE, vendor, product…" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0) }} className="h-8 w-48 text-xs" />
            {isCve && <Button size="sm" variant="primary" onClick={() => setCve(lookup)}>Open {lookup}</Button>}
          </div>
        }>
        {list.isPending ? <div className="space-y-2 p-5">{Array.from({ length: 5 }, (_, i) => <Skeleton key={i} className="h-9" />)}</div>
          : list.isError ? <div className="p-5"><ErrorNotice error={list.error} /></div>
          : list.data.items.length === 0 ? (
            <EmptyState icon={Bug} title={stats.data?.kev_total ? 'No matching vulnerabilities' : 'Catalogue not loaded yet'}>
              {stats.data?.kev_total ? 'Try another search, or open any CVE by its ID.' : can('intel:manage') ? 'Use “Refresh from CISA” to download the catalogue.' : 'Ask an analyst or admin to refresh it.'}
            </EmptyState>
          ) : (
            <div className="relative overflow-x-auto">
              <table className="w-full min-w-[760px] text-sm">
                <thead><tr className="border-b border-line text-left text-xs text-fg-subtle">
                  <th className="px-5 py-2.5 font-medium">CVE</th><th className="px-3 py-2.5 font-medium">Vulnerability</th>
                  <th className="px-3 py-2.5 font-medium">Vendor · product</th><th className="px-3 py-2.5 font-medium">CVSS</th><th className="px-5 py-2.5 font-medium">Added to KEV</th>
                </tr></thead>
                <tbody className="divide-y divide-line">
                  {list.data.items.map((v) => (
                    <tr key={v.cve_id} tabIndex={0} onClick={() => setCve(v.cve_id)} onKeyDown={(e) => e.key === 'Enter' && setCve(v.cve_id)} className="cursor-pointer hover:bg-ink-850/60" aria-label={`Open ${v.cve_id}`}>
                      <td className="whitespace-nowrap px-5 py-2.5 font-mono text-xs text-accent">{v.cve_id}</td>
                      <td className="px-3 py-2.5 text-fg">{v.title}{v.known_ransomware_use && <Badge tone="critical" className="ml-2">ransomware</Badge>}</td>
                      <td className="px-3 py-2.5 text-fg-muted">{v.vendor} · {v.product}</td>
                      <td className="px-3 py-2.5"><Cvss score={v.cvss_score} /></td>
                      <td className="whitespace-nowrap px-5 py-2.5 text-fg-muted">{v.kev_date_added ? new Date(v.kev_date_added).toLocaleDateString() : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        {total > PAGE && (
          <div className="flex items-center justify-between border-t border-line px-5 py-3 text-xs text-fg-subtle">
            <span>{offset + 1}–{Math.min(offset + PAGE, total)} of {formatNumber(total)}</span>
            <div className="flex gap-2">
              <Button size="sm" icon={<ChevronLeft className="size-3.5" />} disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE))}>Previous</Button>
              <Button size="sm" disabled={offset + PAGE >= total} onClick={() => setOffset((o) => o + PAGE)}>Next <ChevronRight className="size-3.5" /></Button>
            </div>
          </div>
        )}
      </Panel>
      {cve && <CveDialog id={cve} onClose={() => setCve(null)} />}
    </div>
  )
}

function CveDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const detail = useQuery({ queryKey: qk.vuln(id), queryFn: () => api<VulnerabilityDetail>(`/vulnerabilities/${id}`), retry: false })
  const v = detail.data
  return (
    <Dialog open onClose={onClose} size="lg" title={id} description={v?.title ?? undefined}>
      {detail.isError ? <ErrorNotice error={detail.error} /> : !v ? <Skeleton className="h-48" /> : (
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-fg-muted">CVSS</span> <Cvss score={v.cvss_score} />
            {v.severity && <Badge tone={v.severity === 'critical' || v.severity === 'high' ? 'critical' : 'warn'}>{v.severity}</Badge>}
            {v.in_cisa_kev && <Badge tone="critical">Known exploited (CISA KEV)</Badge>}
            {v.known_ransomware_use && <Badge tone="critical">Used in ransomware campaigns</Badge>}
          </div>
          {v.nvd_error && <p className="text-xs text-medium">NVD details unavailable right now: {v.nvd_error}</p>}
          {v.description && <p className="text-fg-muted">{v.description}</p>}
          {v.cvss_vector && <p className="break-all font-mono text-[11px] text-fg-subtle">{v.cvss_vector}</p>}
          {v.kev_required_action && (
            <div className="rounded-lg border border-critical/25 bg-critical/[0.04] p-3">
              <p className="text-xs font-medium text-fg">Required action (CISA)</p>
              <p className="mt-1 text-xs text-fg-muted">{v.kev_required_action}</p>
              {v.kev_due_date && <p className="mt-1 text-xs text-fg-subtle">Federal due date: {new Date(v.kev_due_date).toLocaleDateString()}</p>}
            </div>
          )}
          <dl className="grid grid-cols-2 gap-3 text-xs">
            <div><dt className="text-fg-subtle">Vendor · product</dt><dd className="text-fg">{v.vendor ?? '—'} · {v.product ?? '—'}</dd></div>
            <div><dt className="text-fg-subtle">Weakness</dt><dd className="text-fg">{v.cwes.join(', ') || '—'}</dd></div>
            <div><dt className="text-fg-subtle">Published</dt><dd className="text-fg">{dateTime(v.published_at)}</dd></div>
            <div><dt className="text-fg-subtle">Data fetched</dt><dd className="text-fg">{relativeTime(v.fetched_at)}</dd></div>
          </dl>
          {v.references.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-medium text-fg-muted">References</p>
              <ul className="space-y-1 text-xs">{v.references.slice(0, 8).map((r) => <li key={r} className="truncate"><SafeExternalLink href={r}>{new URL(r).hostname}</SafeExternalLink></li>)}</ul>
            </div>
          )}
          <p className="text-xs text-fg-subtle">Sources: <SafeExternalLink href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}>NVD</SafeExternalLink>{v.in_cisa_kev && <> · <SafeExternalLink href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</SafeExternalLink></>}</p>
        </div>
      )}
    </Dialog>
  )
}
