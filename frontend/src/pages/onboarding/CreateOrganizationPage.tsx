import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Building2, Lock } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { useAuth } from '@/auth/AuthContext'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { Wordmark } from '@/components/ui/Logo'
import { api, ApiError } from '@/lib/api'
import type { Membership } from '@/lib/types'
import { qk, useMemberships } from '@/org/queries'

export const INDUSTRIES = ['education', 'research', 'finance', 'healthcare', 'government', 'technology', 'manufacturing', 'retail', 'energy', 'other']

function slugPreview(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 56)
}

export function CreateOrganizationPage() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const memberships = useMemberships()
  const [form, setForm] = useState({ name: '', industry: '', description: '' })

  const create = useMutation({
    mutationFn: () =>
      api<Membership>('/organizations', {
        method: 'POST',
        body: { name: form.name.trim(), industry: form.industry || null, description: form.description.trim() || null },
      }),
    onSuccess: async (m) => {
      await queryClient.invalidateQueries({ queryKey: qk.memberships })
      navigate(`/org/${m.organization.id}`, { replace: true })
    },
  })

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    create.mutate()
  }
  const err = create.error instanceof ApiError ? create.error : null
  const hasOrgs = (memberships.data?.length ?? 0) > 0

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex h-14 items-center justify-between border-b border-line px-4 sm:px-6">
        <Wordmark />
        <div className="flex items-center gap-3 text-sm text-fg-muted">
          <span className="hidden sm:inline">{user?.email}</span>
          <Button variant="ghost" size="sm" onClick={() => void logout()}>
            Sign out
          </Button>
        </div>
      </header>
      <main className="flex flex-1 items-start justify-center px-4 py-12 sm:py-20">
        <div className="w-full max-w-lg animate-rise">
          {hasOrgs && (
            <Link to="/" className="mb-6 inline-flex items-center gap-1.5 text-sm text-fg-muted hover:text-fg">
              <ArrowLeft className="size-4" /> Back to console
            </Link>
          )}
          <div className="mb-6 flex size-11 items-center justify-center rounded-xl border border-line-strong bg-ink-850 text-accent">
            <Building2 className="size-5" />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{hasOrgs ? 'Create another organization' : `Welcome${user ? `, ${user.full_name.split(' ')[0]}` : ''}`}</h1>
          <p className="mt-2 text-sm text-fg-muted">
            An organization is an isolated tenant: its devices, events, incidents and audit trail are never visible to any other organization. You will be its owner.
          </p>
          <form onSubmit={onSubmit} className="panel mt-8 space-y-4 p-5 sm:p-6" noValidate>
            {create.error && !err?.details && <ErrorNotice error={create.error} />}
            <Field label="Organization name" error={err?.fieldError('name')} hint={form.name.trim().length >= 2 ? <>URL: <span className="font-mono">/{slugPreview(form.name) || '…'}</span></> : 'e.g. your company, SOC team or research lab'}>
              {({ id, describedBy, invalid }) => (
                <Input id={id} aria-describedby={describedBy} invalid={invalid} required autoFocus minLength={2} maxLength={120} value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="Karachi Cyber Research Lab" />
              )}
            </Field>
            <Field label="Industry" error={err?.fieldError('industry')}>
              {({ id, describedBy, invalid }) => (
                <Select id={id} aria-describedby={describedBy} invalid={invalid} value={form.industry} onChange={(e) => setForm((f) => ({ ...f, industry: e.target.value }))}>
                  <option value="">Select (optional)</option>
                  {INDUSTRIES.map((i) => (
                    <option key={i} value={i}>
                      {i[0]!.toUpperCase() + i.slice(1)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Description" error={err?.fieldError('description')} hint="Optional · up to 1000 characters">
              {({ id, describedBy, invalid }) => (
                <Textarea id={id} aria-describedby={describedBy} invalid={invalid} maxLength={1000} value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} placeholder="What does this team protect?" />
              )}
            </Field>
            <Button type="submit" variant="primary" size="lg" className="w-full" loading={create.isPending} disabled={form.name.trim().length < 2}>
              Create organization
            </Button>
            <p className="flex items-start gap-2 text-xs text-fg-subtle">
              <Lock className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              Isolation is enforced twice: every API query is scoped to your membership, and PostgreSQL Row-Level Security blocks cross-tenant rows at the database.
            </p>
          </form>
        </div>
      </main>
    </div>
  )
}
