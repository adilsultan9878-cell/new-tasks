import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { MODULES } from '@/config/modules'
import { renderInOrg } from '@/test/utils'

import { RoadmapPage } from './RoadmapPage'

describe('RoadmapPage', () => {
  it('says so when every module is live', () => {
    renderInOrg(<RoadmapPage />)
    if (MODULES.every((m) => m.status === 'live')) expect(screen.getByText('Every module is live')).toBeInTheDocument()
  })

  it('lists every planned module with a link to its details', () => {
    renderInOrg(<RoadmapPage />)
    for (const m of MODULES.filter((x) => x.status === 'planned')) {
      expect(screen.getByRole('link', { name: new RegExp(m.name) })).toHaveAttribute('href', `/org/11111111-1111-1111-1111-111111111111/${m.path}`)
    }
    expect(screen.getByText(/4\. Security Brain/)).toBeInTheDocument()
  })
})
