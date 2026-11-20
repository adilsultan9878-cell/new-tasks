import { createContext, useContext, type ReactNode } from 'react'

import type { Membership } from '@/lib/types'

interface OrgState {
  membership: Membership
  orgId: string
  can: (permission: string) => boolean
}

const OrgContext = createContext<OrgState | null>(null)

export function OrgProvider({ membership, children }: { membership: Membership; children: ReactNode }) {
  const perms = new Set(membership.permissions)
  const value: OrgState = {
    membership,
    orgId: membership.organization.id,
    can: (p) => perms.has(p),
  }
  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>
}

export function useOrg(): OrgState {
  const ctx = useContext(OrgContext)
  if (!ctx) throw new Error('useOrg must be used inside <OrgProvider>')
  return ctx
}
