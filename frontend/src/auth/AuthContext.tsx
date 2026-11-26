import { useQueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

import { api, refreshSession, setAccessToken, setSessionExpiredHandler } from '@/lib/api'
import { writePref } from '@/lib/storage'
import type { TokenResponse, User } from '@/lib/types'

type Status = 'loading' | 'authenticated' | 'anonymous'

interface AuthState {
  status: Status
  user: User | null
  login: (email: string, password: string) => Promise<User>
  register: (input: { email: string; password: string; full_name: string; invitation_token?: string }) => Promise<User>
  logout: () => Promise<void>
  setUser: (user: User) => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<Status>('loading')
  const [user, setUser] = useState<User | null>(null)

  const signOutLocally = useCallback(() => {
    setAccessToken(null)
    setUser(null)
    setStatus('anonymous')
    queryClient.clear()
  }, [queryClient])

  // Restore the session from the HttpOnly refresh cookie on first load.
  useEffect(() => {
    let cancelled = false
    refreshSession().then((data) => {
      if (cancelled) return
      if (data) {
        setUser(data.user)
        setStatus('authenticated')
      } else {
        setStatus('anonymous')
      }
    })
    setSessionExpiredHandler(signOutLocally)
    return () => {
      cancelled = true
      setSessionExpiredHandler(null)
    }
  }, [signOutLocally])

  const accept = useCallback((data: TokenResponse) => {
    setAccessToken(data.access_token)
    setUser(data.user)
    setStatus('authenticated')
    return data.user
  }, [])

  const login = useCallback(
    async (email: string, password: string) =>
      accept(await api<TokenResponse>('/auth/login', { method: 'POST', body: { email, password }, auth: false })),
    [accept],
  )

  const register = useCallback(
    async (input: { email: string; password: string; full_name: string; invitation_token?: string }) =>
      accept(await api<TokenResponse>('/auth/register', { method: 'POST', body: input, auth: false })),
    [accept],
  )

  const logout = useCallback(async () => {
    try {
      await api('/auth/logout', { method: 'POST', auth: false })
    } finally {
      writePref('last-org', null)
      signOutLocally()
    }
  }, [signOutLocally])

  const value = useMemo<AuthState>(
    () => ({ status, user, login, register, logout, setUser }),
    [status, user, login, register, logout],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}

/** The signed-in user, or null outside an AuthProvider (e.g. isolated component tests). */
export function useCurrentUser(): User | null {
  return useContext(AuthContext)?.user ?? null
}
