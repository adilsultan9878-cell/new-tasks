import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { api, ApiError } from '@/lib/api'
import { dateTime, titleCase } from '@/lib/format'
import type { Membership } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'
import { qk } from '@/org/queries'
import { INDUSTRIES } from '@/pages/onboarding/CreateOrganizationPage'

export function OrganizationPage() {
  const { membership, orgId, can } = useOrg()
  const org = membership.organization
  const editable = can('org:update')
  const queryClient = useQueryClient()
  const [form, setForm] = useState({ name: org.name, industry: org.industry ?? '', description: org.description ?? '' })
  const [saved, setSaved] = useState(false)

  const save = useMutation({
    mutationFn: () =>
      api<Membership>(`/organizations/${orgId}`, {
        method: 'PATCH',
        body: { name: form.name.trim(), industry: form.industry || null, description: form.description.trim() || null },
      }),
    onSuccess: async () => {
      setSaved(true)
      await queryClient.invalidateQueries({ queryKey: qk.memberships })
    },
  })
  const err = save.error instanceof ApiError ? save.error : null
  const dirty = form.name !== org.name || form.industry !== (org.industry ?? '') || form.description !== (org.description ?? '')

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    setSaved(false)
    save.mutate()
  }

  return (
    <div>
      <PageHeader eyebrow="Administration" title="Organization" description="Profile of this tenant. All security data you add is scoped to it." />
      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <Panel title="Profile" description={editable ? 'Owners and administrators can edit' : 'Read-only for your role'}>
          <form onSubmit={onSubmit} className="space-y-4" noValidate>
            {save.error && !err?.details && <ErrorNotice error={save.error} />}
            <Field label="Name" error={err?.fieldError('name')}>
              {({ id, describedBy, invalid }) => (
                <Input id={id} aria-describedby={describedBy} invalid={invalid} disabled={!editable} value={form.name} maxLength={120} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
              )}
            </Field>
            <Field label="Industry" error={err?.fieldError('industry')}>
              {({ id, describedBy, invalid }) => (
                <Select id={id} aria-describedby={describedBy} invalid={invalid} disabled={!editable} value={form.industry} onChange={(e) => setForm((f) => ({ ...f, industry: e.target.value }))}>
                  <option value="">Not specified</option>
                  {INDUSTRIES.map((i) => (
                    <option key={i} value={i}>
                      {titleCase(i)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Description" error={err?.fieldError('description')}>
              {({ id, describedBy, invalid }) => (
                <Textarea id={id} aria-describedby={describedBy} invalid={invalid} disabled={!editable} maxLength={1000} value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
              )}
            </Field>
            {editable && (
              <div className="flex items-center gap-3">
                <Button type="submit" variant="primary" loading={save.isPending} disabled={!dirty || form.name.trim().length < 2}>
                  Save changes
                </Button>
                {saved && !dirty && <span className="text-xs text-ok" role="status">Saved · recorded in audit log</span>}
              </div>
            )}
          </form>
        </Panel>
        <div className="space-y-5">
          <Panel title="Tenant">
            <dl className="space-y-3 text-sm">
              {[
                ['Organization ID', <span key="id" className="font-mono text-xs break-all">{org.id}</span>],
                ['URL slug', <span key="s" className="font-mono text-xs">{org.slug}</span>],
                ['Plan', <Badge key="p" tone="accent">{titleCase(org.plan)}</Badge>],
                ['Members', membership.member_count],
                ['Created', dateTime(org.created_at)],
                ['Your role', membership.role.name],
              ].map(([k, v]) => (
                <div key={String(k)} className="flex items-start justify-between gap-4">
                  <dt className="text-fg-subtle">{k}</dt>
                  <dd className="text-right text-fg">{v}</dd>
                </div>
              ))}
            </dl>
          </Panel>
          <div className="flex gap-2.5 rounded-xl border border-line bg-ink-900/50 p-4 text-xs leading-relaxed text-fg-subtle">
            <Lock className="mt-0.5 size-3.5 shrink-0 text-accent" aria-hidden />
            Organization deletion and ownership transfer are intentionally not available yet; they will require re-authentication and a confirmation window.
          </div>
        </div>
      </div>
    </div>
  )
}
