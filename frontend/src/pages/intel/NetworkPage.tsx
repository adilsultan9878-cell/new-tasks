import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Network, Trash2, Upload } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice, Skeleton } from '@/components/ui/Feedback'
import { Field, Input } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api, ApiError } from '@/lib/api'
import { relativeTime } from '@/lib/format'
import type { NetworkAsset, NetworkScope, ScanImportResult } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'

const RISKY = new Set([21, 23, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017, 4444, 31337])
const MAX_FILE = 5_000_000

export function NetworkPage() {
  const { orgId, can } = useOrg()
  const manage = can('network:manage')
  const assets = useQuery({ queryKey: qk.assets(orgId), queryFn: () => api<NetworkAsset[]>(`/organizations/${orgId}/network/assets`) })
  return (
    <div>
      <PageHeader eyebrow="NEXUS ZERO · Threat hunting" title="Network Security Monitor"
        description="Inventory of hosts and exposed services in the ranges your organization is authorized to assess. SENTINEL X never scans on its own: import results from your own scanner, and agents report their listening ports." />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel title="Network assets" description={assets.data ? `${assets.data.length} hosts` : undefined} flush>
          {assets.isPending ? <div className="space-y-2 p-5"><Skeleton className="h-9" /><Skeleton className="h-9" /></div>
            : assets.isError ? <div className="p-5"><ErrorNotice error={assets.error} /></div>
            : assets.data.length === 0 ? <EmptyState icon={Network} title="No assets yet">Declare an authorized scope, then import an Nmap XML report or enroll agents.</EmptyState> : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-sm">
                  <thead><tr className="border-b border-line text-left text-xs text-fg-subtle">
                    <th className="px-5 py-2.5 font-medium">Host</th><th className="px-3 py-2.5 font-medium">Open ports</th>
                    <th className="px-3 py-2.5 font-medium">Source</th><th className="px-5 py-2.5 font-medium">Last seen</th>
                  </tr></thead>
                  <tbody className="divide-y divide-line">
                    {assets.data.map((a) => (
                      <tr key={a.id} className="align-top">
                        <td className="px-5 py-2.5">
                          <p className="font-mono text-xs text-fg">{a.ip_address}</p>
                          <p className="text-xs text-fg-subtle">{a.hostname ?? '—'}{a.vendor ? ` · ${a.vendor}` : ''}</p>
                          {!a.in_authorized_scope && <Badge tone="warn" className="mt-1">outside declared scopes</Badge>}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex flex-wrap gap-1">
                            {a.open_ports.length === 0 && <span className="text-xs text-fg-subtle">none</span>}
                            {a.open_ports.map((p) => {
                              const svc = a.services.find((s) => s.port === p)
                              return (
                                <span key={p} title={svc ? [svc.service, svc.product].filter(Boolean).join(' · ') : undefined}
                                  className={RISKY.has(p) ? 'rounded-md border border-critical/35 bg-critical/10 px-1.5 py-0.5 font-mono text-[11px] text-[#ff8f93]' : 'rounded-md border border-line-strong bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-fg-muted'}>
                                  {p}{svc?.service ? `/${svc.service}` : ''}
                                </span>
                              )
                            })}
                          </div>
                        </td>
                        <td className="px-3 py-2.5"><Badge>{a.source}</Badge></td>
                        <td className="px-5 py-2.5 text-xs text-fg-muted">{relativeTime(a.last_seen_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
        </Panel>
        <div className="space-y-5">
          <Scopes manage={manage} />
          {manage && <ImportScan />}
        </div>
      </div>
    </div>
  )
}

function Scopes({ manage }: { manage: boolean }) {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ cidr: '', label: '', attest_authorized: false })
  const scopes = useQuery({ queryKey: qk.scopes(orgId), queryFn: () => api<NetworkScope[]>(`/organizations/${orgId}/network/scopes`) })
  const add = useMutation({
    mutationFn: () => api(`/organizations/${orgId}/network/scopes`, { method: 'POST', body: { ...form, cidr: form.cidr.trim(), label: form.label.trim() } }),
    onSuccess: () => { setForm({ cidr: '', label: '', attest_authorized: false }); void queryClient.invalidateQueries({ queryKey: qk.scopes(orgId) }) },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api(`/organizations/${orgId}/network/scopes/${id}`, { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.scopes(orgId) }),
  })
  const needsAttestation = add.error instanceof ApiError && add.error.code === 'attestation_required'
  const submit = (e: FormEvent) => { e.preventDefault(); add.mutate() }
  return (
    <Panel title="Authorized scopes" description="Only hosts inside these ranges are recorded" flush>
      <ul className="divide-y divide-line">
        {scopes.data?.map((s) => (
          <li key={s.id} className="flex items-center gap-3 px-5 py-2.5 text-sm">
            <span className="font-mono text-xs text-fg">{s.cidr}</span>
            <span className="min-w-0 flex-1 truncate text-xs text-fg-muted">{s.label}</span>
            <Badge tone={s.is_private ? 'neutral' : 'warn'}>{s.is_private ? 'private' : 'public · attested'}</Badge>
            {manage && <button onClick={() => remove.mutate(s.id)} className="rounded p-1 text-fg-subtle hover:bg-ink-750 hover:text-fg" aria-label={`Remove scope ${s.cidr}`}><Trash2 className="size-3.5" /></button>}
          </li>
        ))}
        {scopes.data?.length === 0 && <li className="px-5 py-3 text-xs text-fg-subtle">No scopes declared.</li>}
      </ul>
      {manage && (
        <form onSubmit={submit} className="space-y-2 border-t border-line p-4" noValidate>
          {add.error && !needsAttestation && <ErrorNotice error={add.error} />}
          <div className="grid grid-cols-[1fr_1fr] gap-2">
            <Field label="CIDR">{({ id }) => <Input id={id} className="h-9 font-mono text-xs" placeholder="192.168.1.0/24" value={form.cidr} onChange={(e) => setForm((f) => ({ ...f, cidr: e.target.value }))} />}</Field>
            <Field label="Label">{({ id }) => <Input id={id} className="h-9 text-xs" placeholder="Office LAN" value={form.label} onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))} />}</Field>
          </div>
          {(needsAttestation || form.attest_authorized) && (
            <label className="flex items-start gap-2 rounded-lg border border-medium/30 bg-medium/[0.06] p-2.5 text-xs text-fg-muted">
              <input type="checkbox" className="mt-0.5 accent-[var(--color-accent)]" checked={form.attest_authorized} onChange={(e) => setForm((f) => ({ ...f, attest_authorized: e.target.checked }))} />
              This is a public range. I confirm my organization owns it or has written authorization to assess it.
            </label>
          )}
          <Button type="submit" size="sm" loading={add.isPending} disabled={!form.cidr.trim() || !form.label.trim()}>Add scope</Button>
          <p className="text-[11px] text-fg-subtle">Ranges larger than /16 (IPv4) or /48 (IPv6) are refused.</p>
        </form>
      )}
    </Panel>
  )
}

function ImportScan() {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const upload = useMutation({
    mutationFn: (body: { filename: string; content: string }) => api<ScanImportResult>(`/organizations/${orgId}/network/imports`, { method: 'POST', body }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: qk.assets(orgId) }); void queryClient.invalidateQueries({ queryKey: ['events', orgId] }) },
  })
  const onFile = async (file: File | undefined) => {
    setError(null)
    if (!file) return
    if (file.size > MAX_FILE) return setError('File is larger than 5 MB.')
    upload.mutate({ filename: file.name, content: await file.text() })
  }
  const r = upload.data
  return (
    <Panel title="Import scan results" description="Nmap XML (nmap -oX scan.xml …)">
      <label className="flex cursor-pointer flex-col items-center gap-2 rounded-xl border border-dashed border-line-strong bg-ink-900/50 px-4 py-5 text-center hover:border-accent/50">
        <Upload className="size-5 text-fg-subtle" aria-hidden />
        <span className="text-sm text-fg">{upload.isPending ? 'Importing…' : 'Choose an Nmap XML file'}</span>
        <span className="text-xs text-fg-subtle">Hosts outside your scopes are discarded</span>
        <input type="file" accept=".xml,text/xml" className="sr-only" aria-label="Choose an Nmap XML file" onChange={(e) => { void onFile(e.target.files?.[0]); e.target.value = '' }} />
      </label>
      {error && <p className="mt-2 text-xs text-critical">{error}</p>}
      {upload.error && <div className="mt-3"><ErrorNotice error={upload.error} /></div>}
      {r && (
        <p className="mt-3 rounded-lg border border-line bg-ink-900/60 p-3 text-xs text-fg-muted" role="status">
          {r.imported} of {r.hosts_in_file} hosts imported ({r.out_of_scope} outside scope discarded) · {r.new_assets} new · {r.new_services} newly exposed services · {r.events} events raised
        </p>
      )}
    </Panel>
  )
}
