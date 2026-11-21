import { Fish, Mail } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input, Textarea } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { cn } from '@/lib/cn'
import type { InvestigationDetail } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

import { InvestigationHistory, useRunInvestigation } from './Investigations'
import { InvestigationView } from './InvestigationView'

export function PhishingPage() {
  const { can } = useOrg()
  const [tab, setTab] = useState<'url' | 'email'>('url')
  const [url, setUrl] = useState('')
  const [email, setEmail] = useState('')
  const [result, setResult] = useState<InvestigationDetail | null>(null)
  const run = useRunInvestigation(setResult)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    run.mutate(tab === 'url' ? { subject_type: 'url', subject: url.trim() } : { subject_type: 'email', subject: email })
  }
  return (
    <div>
      <PageHeader
        eyebrow="NEXUS ZERO · Threat hunting"
        title="Phishing & URL Analyzer"
        description="Paste a suspicious link or the full headers of an email. Links are analysed, never opened: only registries, DNS and threat-intelligence services are asked about them."
      />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-5">
          <Panel>
            <div role="tablist" aria-label="What to analyse" className="mb-4 inline-flex rounded-lg border border-line bg-ink-850 p-1">
              {([['url', 'Link / URL', Fish], ['email', 'Email headers', Mail]] as const).map(([key, label, Icon]) => (
                <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
                  className={cn('flex items-center gap-2 rounded-md px-3 py-1.5 text-sm', tab === key ? 'bg-ink-700 text-fg' : 'text-fg-muted hover:text-fg')}>
                  <Icon className="size-4" aria-hidden /> {label}
                </button>
              ))}
            </div>
            {!can('investigations:run') ? <p className="text-sm text-fg-muted">Your role can view results but cannot run investigations.</p> : (
              <form onSubmit={submit} className="space-y-3" noValidate>
                {run.error && <ErrorNotice error={run.error} />}
                {tab === 'url' ? (
                  <Field label="Suspicious link" hint="e.g. http://paypa1-secure.com/verify — it will not be visited">
                    {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" autoComplete="off" spellCheck={false} className="font-mono text-xs" />}
                  </Field>
                ) : (
                  <Field label="Full email headers (and optionally the body)" hint="Gmail: ⋮ → Show original. Outlook: File → Properties → Internet headers.">
                    {({ id, describedBy }) => <Textarea id={id} aria-describedby={describedBy} value={email} onChange={(e) => setEmail(e.target.value)} className="min-h-48 font-mono text-[11px]" placeholder={'Received: from …\nAuthentication-Results: …\nFrom: …\nSubject: …'} spellCheck={false} />}
                  </Field>
                )}
                <Button type="submit" variant="primary" loading={run.isPending} disabled={tab === 'url' ? !url.trim() : !email.trim()}>Analyse</Button>
              </form>
            )}
          </Panel>
          {result && <Panel title="Result" description={result.title}><InvestigationView inv={result} /></Panel>}
        </div>
        <InvestigationHistory types={['url', 'email']} />
      </div>
    </div>
  )
}
