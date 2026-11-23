import { useMutation, useQueryClient } from '@tanstack/react-query'
import { BrainCircuit } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'
import { api } from '@/lib/api'
import type { BrainRunDetail, BrainSubject, RiskLevel } from '@/lib/types'
import { useOrg } from '@/org/OrgContext'

const LEVEL: Record<RiskLevel, { label: string; cls: string; bar: string }> = {
  critical: { label: 'Critical', cls: 'border-critical/40 bg-critical/10 text-[#ff8f93]', bar: 'bg-critical' },
  high: { label: 'High', cls: 'border-high/35 bg-high/10 text-high', bar: 'bg-high' },
  medium: { label: 'Medium', cls: 'border-medium/30 bg-medium/10 text-medium', bar: 'bg-medium' },
  low: { label: 'Low', cls: 'border-low/30 bg-low/10 text-[#7fb0f0]', bar: 'bg-low' },
  info: { label: 'Info', cls: 'border-line-strong bg-ink-750 text-fg-muted', bar: 'bg-ink-600' },
}

/** Same thresholds as the backend scoring model (app/brain/scoring.py). */
export function levelForScore(score: number): RiskLevel {
  return score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : score >= 10 ? 'low' : 'info'
}

/** Unknown levels from the API fall back to the neutral style (never crash). */
export function levelStyle(level: RiskLevel | string | null | undefined) {
  return LEVEL[(level ?? 'info') as RiskLevel] ?? LEVEL.info
}

export function RiskBadge({ level, score, className }: { level: RiskLevel | string | null; score: number | null; className?: string }) {
  const s = levelStyle(level)
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-none', s.cls, className)}
      title={`Risk ${score ?? '—'}/100 (${s.label.toLowerCase()})`}>
      <span className="tabular">{score ?? '—'}</span>
      <span className="opacity-80">{s.label}</span>
    </span>
  )
}

export function PriorityBadge({ priority }: { priority: string | null }) {
  if (!priority) return null
  const tone = priority === 'P1' ? 'border-critical/40 text-[#ff8f93]' : priority === 'P2' ? 'border-high/40 text-high' : priority === 'P3' ? 'border-medium/35 text-medium' : 'border-line-strong text-fg-muted'
  return <span className={cn('rounded border px-1 py-px font-mono text-[10.5px] font-semibold leading-none', tone)} title="Triage priority">{priority}</span>
}

export function ScoreMeter({ score, level }: { score: number; level: RiskLevel | string | null }) {
  return (
    <div className="h-2 overflow-hidden rounded-full bg-ink-750" role="meter" aria-label="Risk score" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100}>
      <div className={cn('h-full rounded-full transition-[width] duration-500', levelStyle(level).bar)} style={{ width: `${Math.max(2, score)}%` }} />
    </div>
  )
}

export const SUBJECT_LABEL: Record<BrainSubject, string> = {
  alert: 'Alert triage',
  device: 'Device risk',
  organization: 'Organization posture',
}

export const AGENT_TITLE: Record<string, string> = {
  orchestrator: 'Orchestrator',
  triage: 'Alert Triage',
  device: 'Device Risk',
  exposure: 'Network Exposure',
  intel: 'Threat-Intel Correlation',
  posture: 'Security Posture',
}

/** Run an analysis and open its result. */
export function useAnalyze() {
  const { orgId } = useOrg()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  return useMutation({
    mutationFn: (body: { subject_type: BrainSubject; subject_id?: string }) =>
      api<BrainRunDetail>(`/organizations/${orgId}/brain/runs`, { method: 'POST', body }),
    onSuccess: (run) => {
      queryClient.setQueryData(['brain', orgId, 'run', run.id], run)
      void queryClient.invalidateQueries({ queryKey: ['brain', orgId] })
      void queryClient.invalidateQueries({ queryKey: ['alerts', orgId] })
      void queryClient.invalidateQueries({ queryKey: ['devices', orgId] })
      navigate(`/org/${orgId}/brain/runs/${run.id}`)
    },
  })
}

export function AnalyzeButton({ subjectType, subjectId, label = 'Analyze', size = 'sm', variant = 'secondary' }: {
  subjectType: BrainSubject
  subjectId?: string
  label?: string
  size?: 'sm' | 'md'
  variant?: 'primary' | 'secondary' | 'ghost'
}) {
  const { can } = useOrg()
  const analyze = useAnalyze()
  if (!can('brain:run')) return null
  return (
    <Button size={size} variant={variant} loading={analyze.isPending} icon={<BrainCircuit className="size-3.5" />}
      onClick={() => analyze.mutate({ subject_type: subjectType, subject_id: subjectId })}
      title={analyze.isError ? (analyze.error as Error).message : 'Run the deterministic Security Brain on this subject'}>
      {label}
    </Button>
  )
}
