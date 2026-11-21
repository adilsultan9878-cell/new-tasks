import { FileSearch, Lock } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { PageHeader } from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { Field, Input } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import type { InvestigationDetail } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

import { InvestigationHistory, useRunInvestigation } from './Investigations'
import { InvestigationView } from './InvestigationView'

const MAX_LOCAL_FILE = 512 * 1024 * 1024

async function sha256Hex(file: File): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer())
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

export function FileHashPage() {
  const { can } = useOrg()
  const [hash, setHash] = useState('')
  const [fileInfo, setFileInfo] = useState<string | null>(null)
  const [hashing, setHashing] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const [result, setResult] = useState<InvestigationDetail | null>(null)
  const run = useRunInvestigation(setResult)

  const onFile = async (file: File | undefined) => {
    setLocalError(null)
    if (!file) return
    if (file.size > MAX_LOCAL_FILE) {
      setLocalError('File is larger than 512 MB; compute the hash with a local tool instead.')
      return
    }
    setHashing(true)
    try {
      setHash(await sha256Hex(file))
      setFileInfo(`${file.name} · ${(file.size / 1024).toFixed(1)} KB · hashed in your browser`)
    } finally {
      setHashing(false)
    }
  }
  const submit = (e: FormEvent) => {
    e.preventDefault()
    run.mutate({ subject_type: 'hash', subject: hash.trim() })
  }
  return (
    <div>
      <PageHeader eyebrow="NEXUS ZERO · Threat hunting" title="File & Hash Analyzer"
        description="Look up a file by its fingerprint in malware-intelligence databases. Files are never uploaded or executed." />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="space-y-5">
          <Panel>
            {!can('investigations:run') ? <p className="text-sm text-fg-muted">Your role can view results but cannot run investigations.</p> : (
              <form onSubmit={submit} className="space-y-4" noValidate>
                {run.error && <ErrorNotice error={run.error} />}
                <label className="flex cursor-pointer flex-col items-center gap-2 rounded-xl border border-dashed border-line-strong bg-ink-900/50 px-4 py-6 text-center hover:border-accent/50">
                  <FileSearch className="size-6 text-fg-subtle" aria-hidden />
                  <span className="text-sm text-fg">{hashing ? 'Computing SHA-256…' : 'Choose a file to fingerprint'}</span>
                  <span className="flex items-center gap-1.5 text-xs text-fg-subtle"><Lock className="size-3" /> The file stays on your computer — only its SHA-256 is sent.</span>
                  <input type="file" className="sr-only" onChange={(e) => void onFile(e.target.files?.[0])} aria-label="Choose a file to hash locally" />
                </label>
                {localError && <p className="text-xs text-critical">{localError}</p>}
                <Field label="Hash (MD5, SHA-1 or SHA-256)" hint={fileInfo ?? undefined}>
                  {({ id, describedBy }) => <Input id={id} aria-describedby={describedBy} value={hash} onChange={(e) => { setHash(e.target.value); setFileInfo(null) }} className="font-mono text-xs" spellCheck={false} autoComplete="off" />}
                </Field>
                <Button type="submit" variant="primary" loading={run.isPending} disabled={!hash.trim() || hashing}>Look up</Button>
              </form>
            )}
          </Panel>
          {result && <Panel title="Result" description={result.title}><InvestigationView inv={result} /></Panel>}
        </div>
        <InvestigationHistory types={['hash']} />
      </div>
    </div>
  )
}
