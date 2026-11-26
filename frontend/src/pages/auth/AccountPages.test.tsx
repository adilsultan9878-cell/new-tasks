import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { AuthProvider } from '@/auth/AuthContext'
import type { AuthPolicy, InvitationInfo } from '@/lib/types'
import { mockApi } from '@/test/utils'

import { ForgotPasswordPage } from './ForgotPasswordPage'
import { InvitePage } from './InvitePage'
import { RegisterPage } from './RegisterPage'
import { ResetPasswordPage } from './ResetPasswordPage'

const TOKEN = 'tok_' + 'a'.repeat(40)
const policy = (over: Partial<AuthPolicy> = {}): AuthPolicy => ({
  registration: 'open', first_account: false, allowed_domains: [], password_reset: true,
  email_verification: true, email_verification_required: false, ...over,
})

function renderAt(path: string, element: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider>
          <Routes>
            <Route path="*" element={element} />
            <Route path="/" element={<p>home</p>} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('account pages', () => {
  it('forgot password: same answer for every address', async () => {
    const fetch = mockApi({ '/auth/policy': policy(), 'POST /auth/password-reset/request': { message: 'ok' } })
    renderAt('/forgot-password', <ForgotPasswordPage />)
    await userEvent.type(await screen.findByLabelText('Work email'), 'someone@example.com')
    await userEvent.click(screen.getByRole('button', { name: 'Send reset link' }))
    expect(await screen.findByText(/a reset link is on its way/)).toBeInTheDocument()
    const call = fetch.mock.calls.find(([url]) => String(url).includes('/password-reset/request'))
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ email: 'someone@example.com' })
  })

  it('forgot password: says plainly when e-mail is not set up', async () => {
    mockApi({ '/auth/policy': policy({ password_reset: false }) })
    renderAt('/forgot-password', <ForgotPasswordPage />)
    expect(await screen.findByText(/E-mail is not set up on this server/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Send reset link' })).not.toBeInTheDocument()
  })

  it('reset password reads the token from the link fragment', async () => {
    const fetch = mockApi({ 'POST /auth/password-reset/confirm': { message: 'Password changed.' } })
    renderAt(`/reset-password#token=${TOKEN}`, <ResetPasswordPage />)
    await userEvent.type(await screen.findByLabelText('New password'), 'Another-Strong-Passphrase-77')
    await userEvent.click(screen.getByRole('button', { name: 'Save new password' }))
    expect(await screen.findByText('Password changed.')).toBeInTheDocument()
    const call = fetch.mock.calls.find(([url]) => String(url).includes('/password-reset/confirm'))
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ token: TOKEN, password: 'Another-Strong-Passphrase-77' })
  })

  it('invite-only sign-up explains itself instead of showing a form', async () => {
    mockApi({ '/auth/policy': policy({ registration: 'invite_only' }) })
    renderAt('/register', <RegisterPage />)
    expect(await screen.findByText(/Sign-up on this server is by invitation/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create account' })).not.toBeInTheDocument()
  })

  it('an invitation for a new address creates the account and joins', async () => {
    const info: InvitationInfo = {
      organization_name: 'Karachi Blue Team', role: 'Security Analyst', email: 'new.analyst@example.com',
      email_hint: 'ne•••@example.com', expires_at: new Date(Date.now() + 86_400_000).toISOString(), account_exists: false,
    }
    const fetch = mockApi({
      'POST /invitations/lookup': info,
      'POST /auth/register': (body: unknown) => ({
        access_token: 'x', token_type: 'bearer', expires_in: 900,
        user: { id: 'u1', email: (body as { email: string }).email, full_name: 'New Analyst', email_verified: true, created_at: '', last_login_at: null },
      }),
    })
    renderAt(`/invite#token=${TOKEN}`, <InvitePage />)
    expect(await screen.findByText('Karachi Blue Team')).toBeInTheDocument()
    expect(screen.getByText(/as Security Analyst/)).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Full name'), 'New Analyst')
    await userEvent.type(screen.getByLabelText('Password'), 'Another-Strong-Passphrase-77')
    await userEvent.click(screen.getByRole('button', { name: 'Create account and join' }))
    await waitFor(() => expect(fetch.mock.calls.some(([url]) => String(url).includes('/auth/register'))).toBe(true))
    const call = fetch.mock.calls.find(([url]) => String(url).includes('/auth/register'))
    expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({ email: 'new.analyst@example.com', invitation_token: TOKEN })
  })
})
