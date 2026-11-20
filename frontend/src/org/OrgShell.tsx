import { ShieldOff } from 'lucide-react'
import { useEffect } from 'react'
import { Link, Navigate, useParams } from 'react-router-dom'

import { FullScreenLoader } from '@/auth/guards'
import { AppShell } from '@/components/layout/AppShell'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorNotice } from '@/components/ui/Feedback'
import { readPref, writePref } from '@/lib/storage'

import { RealtimeProvider } from '@/realtime/RealtimeProvider'

import { OrgProvider } from './OrgContext'
import { useMemberships } from './queries'

/** Resolves /org/:orgId against the caller's memberships (the API enforces the same rule). */
export function OrgShell() {
  const { orgId } = useParams()
  const memberships = useMemberships()
  const membership = memberships.data?.find((m) => m.organization.id === orgId)

  useEffect(() => {
    if (membership) writePref('last-org', membership.organization.id)
  }, [membership])

  if (memberships.isPending) return <FullScreenLoader label="Loading organization" />
  if (memberships.isError)
    return (
      <div className="mx-auto max-w-md p-8">
        <ErrorNotice error={memberships.error} />
      </div>
    )
  if (!membership)
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <EmptyState icon={ShieldOff} title="Organization not available" action={<Link to="/"><Button variant="primary">Go to my organizations</Button></Link>}>
          It does not exist or you are not a member. Access is limited to organizations you belong to.
        </EmptyState>
      </div>
    )
  return (
    <OrgProvider membership={membership}>
      <RealtimeProvider orgId={membership.organization.id}>
        <AppShell memberships={memberships.data} />
      </RealtimeProvider>
    </OrgProvider>
  )
}

export function RootRedirect() {
  const memberships = useMemberships()
  if (memberships.isPending) return <FullScreenLoader label="Loading organizations" />
  if (memberships.isError)
    return (
      <div className="mx-auto max-w-md p-8">
        <ErrorNotice error={memberships.error} />
      </div>
    )
  const list = memberships.data
  if (list.length === 0) return <Navigate to="/onboarding" replace />
  const last = readPref('last-org')
  const target = list.find((m) => m.organization.id === last) ?? list[0]!
  return <Navigate to={`/org/${target.organization.id}`} replace />
}
