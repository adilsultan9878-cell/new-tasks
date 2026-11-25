import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { MODULES } from '@/config/modules'
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
    // Every real module is live now; a stand-in proves how future modules are presented.
    MODULES.push({ ...MODULES[0]!, key: 'future-module', name: 'Future Module', status: 'planned', phase: 11, path: 'm/future-module' })
    try {
      renderModule('future-module')
      expect(screen.getByRole('heading', { name: 'Future Module' })).toBeInTheDocument()
      expect(screen.getByText('Planned · Phase 11')).toBeInTheDocument()
      expect(screen.queryAllByRole('button')).toHaveLength(0)
    } finally {
      MODULES.pop()
    }
  })

  it('returns not-found for unknown modules', () => {
    renderModule('does-not-exist')
    expect(screen.getByText('Page not found')).toBeInTheDocument()
  })
})
