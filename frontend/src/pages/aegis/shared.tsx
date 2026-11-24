import { useMutation, useQueryClient } from '@tanstack/react-query'
import { FlaskConical, Trash2 } from 'lucide-react'
import { useState } from 'react'

import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ErrorNotice } from '@/components/ui/Feedback'
import { api } from '@/lib/api'
import type { ReadingPoint, SimulatorResult } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

export function SimulatedBadge() {
  return <Badge tone="warn" className="uppercase tracking-wide">Simulated</Badge>
}

function useInvalidateAegis() {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  return () => {
    for (const key of ['sensors', 'hubs', 'cameras', 'events', 'alerts', 'devices', 'dashboard']) {
      void queryClient.invalidateQueries({ queryKey: [key, orgId] })
    }
  }
}

/** Run or clear the hardware simulator. Everything it creates is labelled and kept out of metrics. */
export function SimulatorControls({ hasSimulated }: { hasSimulated: boolean }) {
  const { orgId, can } = useOrg()
  const invalidate = useInvalidateAegis()
  const [confirm, setConfirm] = useState(false)
  const run = useMutation({
    mutationFn: () => api<SimulatorResult>(`/organizations/${orgId}/simulator/run`, { method: 'POST' }),
    onSuccess: invalidate,
  })
  const clear = useMutation({
    mutationFn: () => api<Record<string, number>>(`/organizations/${orgId}/simulator`, { method: 'DELETE' }),
    onSuccess: () => { invalidate(); setConfirm(false) },
  })
  if (!can('devices:manage')) return null
  return (
    <div className="flex flex-wrap items-center gap-2">
      {hasSimulated && (confirm
        ? <Button variant="danger" icon={<Trash2 className="size-4" />} loading={clear.isPending} onClick={() => clear.mutate()}>Yes, remove simulated data</Button>
        : <Button variant="ghost" icon={<Trash2 className="size-4" />} onClick={() => setConfirm(true)}>Clear simulation</Button>)}
      <Button variant={hasSimulated ? 'secondary' : 'primary'} icon={<FlaskConical className="size-4" />} loading={run.isPending} onClick={() => run.mutate()}>
        {hasSimulated ? 'Run simulator again' : 'Try the simulator'}
      </Button>
      {(run.isError || clear.isError) && <div className="w-full"><ErrorNotice error={run.error ?? clear.error} /></div>}
    </div>
  )
}

/** Tiny dependency-free line chart with an optional threshold line. */
export function Sparkline({ points, max, min, alert }: { points: ReadingPoint[]; max?: number; min?: number; alert?: boolean }) {
  if (points.length < 2) return <div className="h-12 rounded-lg bg-ink-850/60" aria-hidden />
  const values = points.map((p) => p.v)
  const lo = Math.min(...values, ...(min !== undefined ? [min] : []))
  const hi = Math.max(...values, ...(max !== undefined ? [max] : []))
  const span = hi - lo || 1
  const y = (v: number) => 44 - ((v - lo) / span) * 40
  const path = points.map((p, i) => `${(i / (points.length - 1)) * 100},${y(p.v).toFixed(2)}`).join(' ')
  const stroke = alert ? 'var(--color-critical)' : 'var(--color-accent)'
  return (
    <svg viewBox="0 0 100 48" preserveAspectRatio="none" className="h-12 w-full" role="img" aria-label={`Last ${points.length} readings`}>
      {[max, min].filter((v): v is number => v !== undefined).map((v) => (
        <line key={v} x1="0" x2="100" y1={y(v)} y2={y(v)} stroke="var(--color-medium)" strokeWidth="0.6" strokeDasharray="2 2" vectorEffect="non-scaling-stroke" />
      ))}
      <polyline points={path} fill="none" stroke={stroke} strokeWidth="1.6" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
    </svg>
  )
}
