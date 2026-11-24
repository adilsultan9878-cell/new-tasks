import { ArrowRight, CircleCheck } from 'lucide-react'
import { Link } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { SpotlightCard } from '@/components/magic/SpotlightCard'
import { COMPLETED_PHASE, MODULES, PHASES } from '@/config/modules'
import { cn } from '@/lib/cn'
import { useOrg } from '@/org/OrgContext'

/** Everything that is not built yet, in one simple place — instead of crowding the sidebar. */
export function RoadmapPage() {
  const { orgId } = useOrg()
  const planned = MODULES.filter((m) => m.status === 'planned')
  const phases = Array.from(new Set(planned.map((m) => m.phase))).sort((a, b) => a - b)
  return (
    <div>
      <PageHeader eyebrow="Roadmap" title="What's next"
        description="Modules that are designed but not built yet. Each one ships in its phase, fully working and tested — until then nothing here pretends to work." />

      <ol className="mb-8 flex flex-wrap gap-2" aria-label="Phases">
        {Object.entries(PHASES).map(([num, name]) => {
          const n = Number(num)
          const done = n <= COMPLETED_PHASE
          return (
            <li key={num} className={cn('flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs',
              done ? 'border-ok/25 bg-ok/[0.07] text-ok' : n === COMPLETED_PHASE + 1 ? 'border-violet/40 bg-violet/10 text-[#c4b5fd]' : 'border-line text-fg-subtle')}>
              {done && <CircleCheck className="size-3.5" aria-hidden />}
              {n}. {name}{n === COMPLETED_PHASE + 1 && ' · next'}
            </li>
          )
        })}
      </ol>

      <div className="space-y-8">
        {phases.map((phase) => (
          <section key={phase}>
            <h2 className="mb-3 text-sm font-semibold text-fg">Phase {phase} <span className="font-normal text-fg-subtle">· {PHASES[phase]}</span></h2>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {planned.filter((m) => m.phase === phase).map((m) => {
                const Icon = m.icon
                return (
                  <SpotlightCard key={m.key} className="p-5">
                    <Link to={`/org/${orgId}/${m.path}`} className="group flex h-full flex-col">
                      <span className="mb-3 grid size-10 place-items-center rounded-xl border border-line-strong bg-ink-850 text-accent"><Icon className="size-5" aria-hidden /></span>
                      <span className="font-medium text-fg">{m.name}</span>
                      <span className="mt-1 flex-1 text-sm text-fg-muted">{m.summary}</span>
                      <span className="mt-4 inline-flex items-center gap-1 text-xs text-accent">Details <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden /></span>
                    </Link>
                  </SpotlightCard>
                )
              })}
            </div>
          </section>
        ))}
      </div>
    </div>
  )
}
