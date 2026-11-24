import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, ChartColumn, Download, FileText } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { SpotlightCard } from '@/components/magic/SpotlightCard'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api, downloadFile } from '@/lib/api'
import { dateTime, relativeTime } from '@/lib/format'
import type { Page, ReportDetail, ReportSummary } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

export function ReportsPage() {
  const { orgId, can } = useOrg()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [days, setDays] = useState('30')
  const reports = useQuery({ queryKey: qk.reports(orgId), queryFn: () => api<Page<ReportSummary>>(`/organizations/${orgId}/reports`, { query: { limit: 100 } }) })
  const generate = useMutation({
    mutationFn: () => api<ReportDetail>(`/organizations/${orgId}/reports`, { method: 'POST', body: { report_type: 'executive', period_days: Number(days) } }),
    onSuccess: (r) => { void queryClient.invalidateQueries({ queryKey: ['reports', orgId] }); navigate(`/org/${orgId}/reports/${r.id}`) },
  })
  return (
    <div>
      <PageHeader eyebrow="SENTINEL X · Respond" title="Reports"
        description="Incident and executive reports built from your organization's own records — alert and incident counts, response times and actions. Nothing is AI-written."
        actions={can('reports:manage') ? <>
          <Select aria-label="Period" value={days} onChange={(e) => setDays(e.target.value)} className="h-9 w-36 text-xs">
            <option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option>
          </Select>
          <Button variant="primary" icon={<ChartColumn className="size-4" />} loading={generate.isPending} onClick={() => generate.mutate()}>Executive summary</Button>
        </> : undefined}
      />
      {generate.isError && <div className="mb-4"><ErrorNotice error={generate.error} /></div>}
      <Panel title="All reports" description={reports.data ? `${reports.data.total} total` : undefined} flush>
        {reports.isPending ? <div className="p-5"><Skeleton className="h-24" /></div> : reports.isError ? <div className="p-5"><ErrorNotice error={reports.error} /></div>
          : reports.data.items.length === 0 ? <EmptyState icon={FileText} title="No reports yet">Generate an executive summary here, or an incident report from an incident.</EmptyState>
          : (
            <ul className="divide-y divide-line">
              {reports.data.items.map((r) => (
                <li key={r.id}>
                  <Link to={`/org/${orgId}/reports/${r.id}`} className="flex items-center gap-3 px-5 py-3 text-sm hover:bg-ink-850/60">
                    <FileText className="size-4 text-accent" aria-hidden />
                    <span className="min-w-0 flex-1 truncate text-fg">{r.title}</span>
                    <Badge tone={r.report_type === 'executive' ? 'accent' : 'neutral'}>{r.report_type}</Badge>
                    <span className="text-xs text-fg-subtle">{relativeTime(r.created_at)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
      </Panel>
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <SpotlightCard className="p-4">
      <p className="text-xs text-fg-subtle">{label}</p>
      <p className="tabular mt-1 text-2xl font-semibold text-fg">{value ?? '—'}</p>
    </SpotlightCard>
  )
}

const hours = (v: unknown) => (typeof v === 'number' ? (v < 1 ? `${Math.round(v * 60)} min` : `${v.toFixed(1)} h`) : '—')

export function ReportPage() {
  const { reportId = '' } = useParams()
  const { orgId } = useOrg()
  const [downloadError, setDownloadError] = useState<unknown>(null)
  const report = useQuery({ queryKey: qk.report(orgId, reportId), queryFn: () => api<ReportDetail>(`/organizations/${orgId}/reports/${reportId}`) })
  const back = <Link to={`/org/${orgId}/reports`} className="inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg"><ArrowLeft className="size-3.5" /> Reports</Link>
  if (report.isError) return <div className="space-y-4">{back}<ErrorNotice error={report.error} /></div>
  if (!report.data) return <div className="space-y-4">{back}<Skeleton className="h-64" /></div>
  const r = report.data
  const m = r.metrics as Record<string, unknown>
  return (
    <div>
      <div className="mb-3">{back}</div>
      <PageHeader eyebrow={r.report_type === 'executive' ? 'Executive summary' : 'Incident report'} title={r.title}
        description={`Generated ${dateTime(r.created_at)} · deterministic, no AI-written text`}
        actions={<Button icon={<Download className="size-4" />} onClick={() => { setDownloadError(null); downloadFile(`/organizations/${orgId}/reports/${r.id}/download`, 'report.md').catch(setDownloadError) }}>Download (.md)</Button>} />
      {downloadError !== null && <div className="mb-4"><ErrorNotice error={downloadError} /></div>}
      {r.report_type === 'executive' && (
        <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Metric label="Alerts raised" value={m.alerts as number} />
          <Metric label="Mean time to acknowledge" value={hours(m.mean_time_to_acknowledge_hours)} />
          <Metric label="Incidents opened / closed" value={`${m.incidents_opened ?? 0} / ${m.incidents_closed ?? 0}`} />
          <Metric label="Mean time to resolve" value={hours(m.mean_time_to_resolve_hours)} />
        </div>
      )}
      <Panel title="Report">
        <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed text-fg-muted">{r.markdown}</pre>
      </Panel>
    </div>
  )
}
