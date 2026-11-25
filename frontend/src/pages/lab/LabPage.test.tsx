import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { LabDataset, LabExperiment } from '@/lib/types'
import { membership, mockApi, renderInOrg } from '@/test/utils'

import { LabPage } from './LabPage'

const dataset: LabDataset = {
  id: 'd1', name: 'Brute-force lab', description: null, source: 'upload', params: {}, row_count: 9,
  label_counts: { malicious: 5, benign: 3, unlabelled: 1 }, sha256: 'a'.repeat(64), includes_simulated: false,
  created_by_name: 'Sara', created_at: new Date().toISOString(), experiments: 0,
}
const score = { fired: 2, fired_unlabelled: 0, confusion: { tp: 2, fp: 0, fn: 3, tn: 3 }, precision: 1, recall: 0.4, f1: 0.5714, alerts_per_day: 2 }
const experiment: LabExperiment = {
  id: 'e1', dataset_id: 'd1', dataset_name: 'Brute-force lab', name: '3 failures / 10 min',
  rule: { mode: 'all', conditions: [{ field: 'event_type', op: 'eq', value: 'auth.failed_login' }], threshold: { count: 3, within_minutes: 10, per_device: true } },
  rule_sha256: 'b'.repeat(64), dataset_sha256: 'a'.repeat(64), engine_version: 'lab-1',
  results: {
    ...score, engine: 'lab-1', rows: 9, labelled: 8,
    baseline: { fired: 2, fired_unlabelled: 0, confusion: { tp: 1, fp: 1, fn: 4, tn: 2 }, precision: 0.5, recall: 0.2, f1: 0.2857, alerts_per_day: 2 },
    samples: { tp: [{ id: '1', title: 'Failed login 2', t: '' }], fn: [{ id: '2', title: 'Mimikatz detected', t: '' }], fp: [] },
  },
  created_by_name: 'Sara', created_at: new Date().toISOString(),
}

describe('LabPage', () => {
  it('runs a backtest and explains the score in plain words', async () => {
    const fetch = mockApi({ '/lab/datasets': [dataset], '/lab/experiments': [], 'POST /lab/experiments': experiment })
    renderInOrg(<LabPage />, { m: membership('owner', ['lab:read', 'lab:run']) })
    const list = await screen.findByRole('list', { name: 'Datasets' })
    expect(within(list).getByText('5 real')).toBeInTheDocument()
    await userEvent.selectOptions(screen.getByLabelText('Field 1'), 'severity')
    expect(screen.getByLabelText('Operator 1')).toHaveValue('gte')
    await userEvent.selectOptions(screen.getByLabelText('Field 1'), 'event_type')
    await userEvent.clear(screen.getByLabelText('Value 1'))
    await userEvent.type(screen.getByLabelText('Value 1'), 'auth.failed_login')
    await userEvent.clear(screen.getByLabelText('Count'))
    await userEvent.type(screen.getByLabelText('Count'), '3')
    await userEvent.click(screen.getByRole('button', { name: 'Run backtest' }))

    const call = fetch.mock.calls.find(([url, init]) => String(url).endsWith('/lab/experiments') && init?.method === 'POST')
    const body = JSON.parse(String(call?.[1]?.body))
    expect(body.rule).toEqual({ mode: 'all', conditions: [{ field: 'event_type', op: 'eq', value: 'auth.failed_login' }], threshold: { count: 3, within_minutes: 10, per_device: true } })
    expect(await screen.findByText('Caught 2 of 5 real attacks')).toBeInTheDocument()
    expect(screen.getByText('Of the real attacks, how many it catches')).toBeInTheDocument()
    expect(screen.getByText('Mimikatz detected')).toBeInTheDocument()
  })

  it('is read-only without lab:run and offers the reproducibility check', async () => {
    const fetch = mockApi({ '/lab/datasets': [dataset], '/lab/experiments': [experiment], 'POST /reproduce': { reproduced: true, checks: {}, engine_version: 'lab-1' } })
    renderInOrg(<LabPage />, { m: membership('viewer', ['lab:read']) })
    await screen.findByRole('list', { name: 'Datasets' })
    expect(screen.queryByRole('button', { name: 'Run backtest' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'New dataset' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Re-check' }))
    expect(await screen.findByText('Reproduced')).toBeInTheDocument()
    expect(fetch.mock.calls.some(([url]) => String(url).includes('/lab/experiments/e1/reproduce'))).toBe(true)
  })
})
