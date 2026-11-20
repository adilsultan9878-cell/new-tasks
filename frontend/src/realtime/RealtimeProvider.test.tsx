import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { setAccessToken } from '@/lib/api'

import { RealtimeProvider, useRealtime } from './RealtimeProvider'
import { ToastProvider } from './Toaster'

class FakeSocket {
  static instances: FakeSocket[] = []
  url: string
  sent: string[] = []
  onopen: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  onclose: ((e: { code: number }) => void | Promise<void>) | null = null
  constructor(url: string) {
    this.url = url
    FakeSocket.instances.push(this)
  }
  send(data: string) {
    this.sent.push(data)
  }
  close() {}
  emit(msg: unknown) {
    this.onmessage?.({ data: JSON.stringify(msg) })
  }
}

function Status() {
  return <span data-testid="status">{useRealtime().status}</span>
}

function renderProvider(client = new QueryClient()) {
  return render(
    <QueryClientProvider client={client}>
      <ToastProvider>
        <RealtimeProvider orgId="org-1">
          <Status />
        </RealtimeProvider>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  FakeSocket.instances = []
  vi.stubGlobal('WebSocket', FakeSocket)
  setAccessToken('access-123')
})
afterEach(() => {
  vi.unstubAllGlobals()
  setAccessToken(null)
})

describe('RealtimeProvider', () => {
  it('authenticates with the in-memory token as its first message (never in the URL)', async () => {
    renderProvider()
    await vi.waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const ws = FakeSocket.instances[0]!
    expect(ws.url).toMatch(/^ws:\/\/.+\/api\/v1\/ws$/)
    expect(ws.url).not.toContain('access-123')
    act(() => ws.onopen?.())
    expect(JSON.parse(ws.sent[0]!)).toEqual({ type: 'auth', token: 'access-123', org_id: 'org-1' })
    expect(screen.getByTestId('status')).toHaveTextContent('connecting')
    act(() => ws.emit({ type: 'ready' }))
    expect(screen.getByTestId('status')).toHaveTextContent('live')
  })

  it('refreshes data and raises a toast for new alerts', async () => {
    const client = new QueryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    renderProvider(client)
    await vi.waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    const ws = FakeSocket.instances[0]!
    act(() => {
      ws.onopen?.()
      ws.emit({ type: 'ready' })
      ws.emit({ type: 'alert.created', data: { severity: 'critical', title: 'Ransomware note detected' } })
    })
    expect(await screen.findByRole('alert')).toHaveTextContent('Critical alert')
    expect(screen.getByRole('alert')).toHaveTextContent('Ransomware note detected')
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['alerts', 'org-1'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['dashboard', 'org-1'] })
  })

  it('stops retrying when access is forbidden', async () => {
    renderProvider()
    await vi.waitFor(() => expect(FakeSocket.instances).toHaveLength(1))
    // onclose is async: await the act so React flushes the state update.
    await act(async () => {
      await FakeSocket.instances[0]!.onclose?.({ code: 4403 })
    })
    expect(screen.getByTestId('status')).toHaveTextContent('offline')
    expect(FakeSocket.instances).toHaveLength(1)
  })
})
