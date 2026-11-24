import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { OrgProvider } from '@/org/OrgContext'
import { membership } from '@/test/utils'

import { ModulePage } from './ModulePage'

function renderModule(key: string) {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter initialEntries={[`/org/x/m/${key}`]}>
        <OrgProvider membership={membership()}>
          <Routes>
            <Route path="/org/:orgId/m/:moduleKey" element={<ModulePage />} />
          </Routes>
        </OrgProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ModulePage', () => {
  it('shows a planned module as a roadmap with no fake action buttons', () => {
    renderModule('automation')
    expect(screen.getByRole('heading', { name: 'Workflow Automation' })).toBeInTheDocument()
    expect(screen.getByText('Planned · Phase 8')).toBeInTheDocument()
    expect(screen.queryAllByRole('button')).toHaveLength(0)
  })

  it('returns not-found for unknown modules', () => {
    renderModule('does-not-exist')
    expect(screen.getByText('Page not found')).toBeInTheDocument()
  })
})
