import { useQuery } from '@tanstack/react-query'

import { api } from '@/lib/api'
import type { AuthPolicy } from '@/lib/types'

/** Who may sign up and which e-mail features this server offers (public, cached). */
export function useAuthPolicy() {
  return useQuery({
    queryKey: ['auth-policy'],
    queryFn: () => api<AuthPolicy>('/auth/policy', { auth: false }),
    staleTime: 5 * 60_000,
  })
}

/** Link tokens travel in the URL fragment (#token=…), which browsers never send to a server. */
export function tokenFromHash(hash: string): string {
  return new URLSearchParams(hash.replace(/^#/, '')).get('token') ?? ''
}
