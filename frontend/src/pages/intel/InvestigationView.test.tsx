import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { InvestigationDetail } from '@/lib/types'

import { InvestigationView, VerdictBadge, verdictStyle } from './InvestigationView'

describe('VerdictBadge', () => {
  it('maps known verdicts', () => {
    render(<VerdictBadge verdict="malicious" />)
    expect(screen.getByText('Malicious')).toBeInTheDocument()
  })

  it('falls back to the neutral badge for unexpected values instead of crashing', () => {
    expect(verdictStyle('something-new').label).toBe('No known threat found')
    render(<VerdictBadge verdict="something-new" />)
    expect(screen.getByText('No known threat found')).toBeInTheDocument()
  })
})

describe('InvestigationView', () => {
  it('separates verified intelligence from deterministic checks and shows source status', () => {
    const inv: InvestigationDetail = {
      id: 'i1', subject_type: 'url', subject: 'http://paypa1-secure.com/verify', title: 'URL: http://paypa1-secure.com/verify',
      status: 'completed', verdict: 'malicious', risk_score: 88, created_at: '', completed_at: '2026-11-21T10:00:00Z',
      summary: 'Malicious — risk 88/100.', ai_assessment: null,
      verified_findings: [
        { code: 'new_domain', title: 'Domain registered 3 days ago', detail: 'd', severity: 'high', score: 30, source: 'rdap', kind: 'intel', data: {} },
        { code: 'brand_in_domain', title: 'Uses the brand “paypal”', detail: 'd', severity: 'high', score: 35, source: 'heuristic', kind: 'heuristic', data: {} },
      ],
      timeline: [{ at: '', step: 'Input validated and normalized', status: 'ok' }],
      details: { checks: [{ source: 'urlhaus', status: 'not_configured', detail: 'set ABUSECH_AUTH_KEY to enable', duration_ms: 0 }] },
    }
    render(<InvestigationView inv={inv} />)
    const intel = screen.getByRole('heading', { name: 'Verified intelligence' }).parentElement!
    expect(intel).toHaveTextContent('Domain registered 3 days ago')
    expect(intel).not.toHaveTextContent('Uses the brand')
    expect(screen.getByRole('heading', { name: 'Deterministic checks' }).parentElement!).toHaveTextContent('Uses the brand')
    expect(screen.getByText(/not configured — set ABUSECH_AUTH_KEY/)).toBeInTheDocument()
    expect(screen.getByRole('meter', { name: 'Risk score' })).toHaveAttribute('aria-valuenow', '88')
  })
})
