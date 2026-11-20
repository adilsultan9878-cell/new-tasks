import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'

import { AuthProvider } from '@/auth/AuthContext'
import { PublicOnly, RequireAuth } from '@/auth/guards'
import { ApiError } from '@/lib/api'
import { OrgShell, RootRedirect } from '@/org/OrgShell'
import { ToastProvider } from '@/realtime/Toaster'
import { AuditLogPage } from '@/pages/audit/AuditLogPage'
import { LoginPage } from '@/pages/auth/LoginPage'
import { RegisterPage } from '@/pages/auth/RegisterPage'
import { SettingsPage } from '@/pages/account/SettingsPage'
import { CommandCenterPage } from '@/pages/dashboard/CommandCenterPage'
import { DevicesPage } from '@/pages/devices/DevicesPage'
import { EventsPage } from '@/pages/events/EventsPage'
import { ModulePage } from '@/pages/modules/ModulePage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { CreateOrganizationPage } from '@/pages/onboarding/CreateOrganizationPage'
import { MembersPage } from '@/pages/org/MembersPage'
import { OrganizationPage } from '@/pages/org/OrganizationPage'

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Never retry client errors (401/403/404 are answers, not glitches).
        retry: (count, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && count < 2,
        refetchOnWindowFocus: true,
      },
    },
  })
}

export const routes = [
  {
    element: <PublicOnly />,
    children: [
      { path: '/login', element: <LoginPage /> },
      { path: '/register', element: <RegisterPage /> },
    ],
  },
  {
    element: <RequireAuth />,
    children: [
      { path: '/', element: <RootRedirect /> },
      { path: '/onboarding', element: <CreateOrganizationPage /> },
      {
        path: '/org/:orgId',
        element: <OrgShell />,
        children: [
          { index: true, element: <CommandCenterPage /> },
          { path: 'devices', element: <DevicesPage /> },
          { path: 'events', element: <EventsPage /> },
          { path: 'organization', element: <OrganizationPage /> },
          { path: 'members', element: <MembersPage /> },
          { path: 'audit', element: <AuditLogPage /> },
          { path: 'settings', element: <SettingsPage /> },
          { path: 'm/:moduleKey', element: <ModulePage /> },
          { path: '*', element: <NotFoundPage embedded /> },
        ],
      },
    ],
  },
  { path: '*', element: <NotFoundPage /> },
]

const router = createBrowserRouter(routes)
const queryClient = createQueryClient()

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthProvider>
          <RouterProvider router={router} />
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  )
}
