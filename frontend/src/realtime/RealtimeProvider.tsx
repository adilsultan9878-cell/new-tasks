import { useQueryClient } from '@tanstack/react-query'
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

import { getAccessToken, refreshSession, websocketUrl } from '@/lib/api'
import { qk } from '@/org/queries'

import { useToasts } from './Toaster'

export type RealtimeStatus = 'connecting' | 'live' | 'reconnecting' | 'offline'

export interface RealtimeMessage {
  type: string
  data?: Record<string, unknown>
  ts?: string
}

interface RealtimeState {
  status: RealtimeStatus
  lastEventAt: number | null
}

const RealtimeContext = createContext<RealtimeState>({ status: 'offline', lastEventAt: null })

const MAX_BACKOFF_MS = 30_000
const UNAUTHENTICATED = 4401
const FORBIDDEN = 4403

/**
 * One WebSocket per open organization. Server messages invalidate the affected React Query caches
 * (so every page shows fresh data) and high-severity activity raises a toast.
 */
export function RealtimeProvider({ orgId, children }: { orgId: string; children: ReactNode }) {
  const queryClient = useQueryClient()
  const { push } = useToasts()
  const [status, setStatus] = useState<RealtimeStatus>('connecting')
  const [lastEventAt, setLastEventAt] = useState<number | null>(null)

  useEffect(() => {
    let socket: WebSocket | null = null
    let retry: number | undefined
    let attempt = 0
    let disposed = false

    const handle = (msg: RealtimeMessage) => {
      const d = msg.data ?? {}
      // The twin is a read model over devices, alerts, incidents and sensors: refresh it on any of them.
      if (/^(twin|device|alert|incident|sensor|camera)\./.test(msg.type)) {
        void queryClient.invalidateQueries({ queryKey: ['twin', orgId] })
      }
      switch (msg.type) {
        case 'event.created':
        case 'event.updated':
          setLastEventAt(Date.now())
          void queryClient.invalidateQueries({ queryKey: ['events', orgId] })
          void queryClient.invalidateQueries({ queryKey: qk.dashboard(orgId) })
          break
        case 'alert.created':
          void queryClient.invalidateQueries({ queryKey: ['alerts', orgId] })
          void queryClient.invalidateQueries({ queryKey: qk.dashboard(orgId) })
          void queryClient.invalidateQueries({ queryKey: qk.notifications })
          // High/critical events always raise an alert, so alerts are the single source of toasts.
          push({ tone: 'critical', title: `${String(d.severity ?? '').charAt(0).toUpperCase()}${String(d.severity ?? '').slice(1)} alert`, body: String(d.title ?? '') })
          break
        case 'sensor.updated':
          void queryClient.invalidateQueries({ queryKey: ['sensors', orgId] })
          void queryClient.invalidateQueries({ queryKey: ['hubs', orgId] })
          break
        case 'camera.updated':
          void queryClient.invalidateQueries({ queryKey: ['cameras', orgId] })
          break
        case 'incident.updated':
          void queryClient.invalidateQueries({ queryKey: ['incidents', orgId] })
          void queryClient.invalidateQueries({ queryKey: ['evidence', orgId] })
          void queryClient.invalidateQueries({ queryKey: qk.dashboard(orgId) })
          break
        case 'action.updated':
          void queryClient.invalidateQueries({ queryKey: ['actions', orgId] })
          void queryClient.invalidateQueries({ queryKey: ['incidents', orgId] })
          void queryClient.invalidateQueries({ queryKey: ['response', orgId] })
          void queryClient.invalidateQueries({ queryKey: qk.notifications })
          break
        case 'response.emergency_stop':
          void queryClient.invalidateQueries({ queryKey: ['response', orgId] })
          push({ tone: 'critical', title: d.engaged ? 'Emergency stop engaged' : 'Emergency stop released', body: d.engaged ? 'All response actions are on hold.' : 'Response actions can run again.' })
          break
        case 'automation.run':
          void queryClient.invalidateQueries({ queryKey: ['automation', orgId] })
          void queryClient.invalidateQueries({ queryKey: qk.notifications })
          if (d.status === 'awaiting_approval') push({ tone: 'info', title: 'Workflow waiting for approval', body: String(d.workflow_name ?? '') })
          break
        case 'automation.delivery':
          void queryClient.invalidateQueries({ queryKey: ['automation', orgId] })
          break
        case 'report.created':
          void queryClient.invalidateQueries({ queryKey: ['reports', orgId] })
          break
        case 'alert.updated':
          void queryClient.invalidateQueries({ queryKey: ['alerts', orgId] })
          void queryClient.invalidateQueries({ queryKey: qk.dashboard(orgId) })
          break
        case 'brain.run_completed':
          void queryClient.invalidateQueries({ queryKey: ['brain', orgId] })
          void queryClient.invalidateQueries({ queryKey: ['alerts', orgId] })
          void queryClient.invalidateQueries({ queryKey: ['devices', orgId] })
          break
        case 'investigation.completed':
          void queryClient.invalidateQueries({ queryKey: ['investigations', orgId] })
          void queryClient.invalidateQueries({ queryKey: qk.dashboard(orgId) })
          break
        case 'device.updated':
          void queryClient.invalidateQueries({ queryKey: ['devices', orgId] })
          void queryClient.invalidateQueries({ queryKey: ['enrollment-tokens', orgId] })
          void queryClient.invalidateQueries({ queryKey: qk.dashboard(orgId) })
          break
      }
    }

    const schedule = () => {
      if (disposed) return
      setStatus('reconnecting')
      const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** attempt) * (0.75 + Math.random() * 0.5)
      attempt += 1
      retry = window.setTimeout(() => void connect(), delay)
    }

    const connect = async () => {
      if (disposed) return
      let token = getAccessToken()
      if (!token) token = (await refreshSession())?.access_token ?? null
      if (disposed) return
      if (!token) {
        setStatus('offline')
        return
      }
      const ws = new WebSocket(websocketUrl())
      socket = ws
      ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', token, org_id: orgId }))
      ws.onmessage = (e) => {
        let msg: RealtimeMessage
        try {
          msg = JSON.parse(String(e.data)) as RealtimeMessage
        } catch {
          return
        }
        if (msg.type === 'ready') {
          attempt = 0
          setStatus('live')
          // Anything that happened while disconnected is picked up by a refetch.
          void queryClient.invalidateQueries({ queryKey: qk.dashboard(orgId) })
        } else handle(msg)
      }
      ws.onclose = async (e) => {
        if (disposed || socket !== ws) return
        if (e.code === FORBIDDEN) {
          setStatus('offline')
          return
        }
        if (e.code === UNAUTHENTICATED) {
          const refreshed = await refreshSession()
          if (!refreshed) {
            setStatus('offline')
            return
          }
        }
        schedule()
      }
    }

    void connect()
    return () => {
      disposed = true
      window.clearTimeout(retry)
      socket?.close(1000, 'leaving organization')
    }
  }, [orgId, queryClient, push])

  return <RealtimeContext.Provider value={{ status, lastEventAt }}>{children}</RealtimeContext.Provider>
}

export function useRealtime(): RealtimeState {
  return useContext(RealtimeContext)
}
