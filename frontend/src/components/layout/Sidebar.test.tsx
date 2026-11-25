import { screen, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { MODULES } from '@/config/modules'
import { membership, renderInOrg } from '@/test/utils'

import { Sidebar } from './Sidebar'

describe('Sidebar', () => {
  it('lists only working modules and keeps planned ones on the roadmap page', () => {
    const m = membership()
    renderInOrg(<Sidebar memberships={[m]} collapsed={false} />, { m })
    const nav = screen.getByRole('navigation', { name: 'Main' })
    const live = MODULES.filter((x) => x.status === 'live' && (!x.permission || m.permissions.includes(x.permission)))
    const planned = MODULES.filter((x) => x.status === 'planned')
    expect(within(nav).getAllByRole('link')).toHaveLength(live.length + 1)
    expect(within(nav).queryByRole('link', { name: /Research Lab/ })).not.toBeInTheDocument()
    expect(within(nav).getByRole('link', { name: /What's next/ })).toHaveTextContent(String(planned.length))
    expect(within(nav).getByRole('link', { name: /What's next/ })).toHaveAttribute('href', `/org/${m.organization.id}/roadmap`)
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
