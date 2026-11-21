import { screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { MODULES } from '@/config/modules'
import { membership, renderInOrg } from '@/test/utils'

import { Sidebar } from './Sidebar'

describe('Sidebar', () => {
  it('lists every platform module, marking planned ones with their phase', () => {
    const m = membership()
    renderInOrg(<Sidebar memberships={[m]} collapsed={false} />, { m })
    const nav = screen.getByRole('navigation', { name: 'Main' })
    const links = within(nav).getAllByRole('link')
    expect(links.length).toBe(MODULES.length)
    expect(within(nav).getByRole('link', { name: /Computer Vision/ })).toHaveTextContent('P6')
    expect(within(nav).getByRole('link', { name: /Phishing & URL/ })).not.toHaveTextContent('P3')
    expect(within(nav).getByRole('link', { name: 'Command Center' })).toHaveAttribute('href', `/org/${m.organization.id}`)
  })

  it('hides modules the role has no permission for', () => {
    const m = membership('viewer', ['dashboard:read', 'org:read'])
    renderInOrg(<Sidebar memberships={[m]} collapsed={false} />, { m })
    expect(screen.queryByRole('link', { name: /Users & Roles/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Audit Log/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Organization/ })).toBeInTheDocument()
  })
})
