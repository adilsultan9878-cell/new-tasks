import { ArrowLeft, CircleDashed, Construction } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'

import { PageHeader } from '@/components/layout/PageHeader'
import { Badge } from '@/components/ui/Badge'
import { Panel } from '@/components/ui/Panel'
import { COMPLETED_PHASE, MODULE_GROUPS, PHASES, findModule } from '@/config/modules'
import { useOrg } from '@/org/OrgContext'
import { NotFoundPage } from '@/pages/NotFoundPage'

/** Honest roadmap view for modules that are not built yet: no fake controls, no fake data. */
export function ModulePage() {
  const { moduleKey = '' } = useParams()
  const { orgId } = useOrg()
  const module = findModule(moduleKey)
  if (!module || module.status === 'live') return <NotFoundPage embedded />
  const Icon = module.icon
  const group = MODULE_GROUPS.find((g) => g.key === module.group)

  return (
    <div>
      <PageHeader
        eyebrow={group ? `${group.label}${group.caption ? ` · ${group.caption}` : ''}` : undefined}
        title={module.name}
        description={module.summary}
        actions={<Badge tone="warn">Planned · Phase {module.phase}</Badge>}
      />
      <div className="grid gap-5 lg:grid-cols-[1fr_340px]">
        <Panel title="What this module will do">
          <div className="flex flex-col items-center px-4 pb-6 pt-4 text-center">
            <div className="relative mb-5 flex size-16 items-center justify-center rounded-2xl border border-line-strong bg-ink-850 text-accent">
              <Icon className="size-7" aria-hidden />
              <span className="absolute -bottom-1.5 -right-1.5 flex size-6 items-center justify-center rounded-full border border-line-strong bg-ink-800 text-medium">
                <Construction className="size-3.5" aria-hidden />
              </span>
            </div>
            <p className="max-w-md text-sm text-fg-muted">
              This module is part of <span className="text-fg">Phase {module.phase} — {PHASES[module.phase]}</span>. Its database tables already exist and are tenant-isolated; the workflows and screens are not available yet, so nothing here pretends to work.
            </p>
          </div>
          <ul className="grid gap-2 sm:grid-cols-2">
            {module.capabilities.map((c) => (
              <li key={c} className="flex items-start gap-2.5 rounded-lg border border-line bg-ink-850/60 px-3 py-2.5 text-sm text-fg-muted">
                <CircleDashed className="mt-0.5 size-4 shrink-0 text-fg-subtle" aria-hidden />
                {c}
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Delivery roadmap">
          <ol className="relative space-y-3 border-l border-line pl-5">
            {Object.entries(PHASES).map(([num, name]) => {
              const n = Number(num)
              const state = n <= COMPLETED_PHASE ? 'done' : n === module.phase ? 'target' : 'other'
              return (
                <li key={num} className="relative text-sm">
                  <span
                    className={
                      state === 'done'
                        ? 'absolute -left-[25px] top-1 size-2.5 rounded-full bg-ok'
                        : state === 'target'
                          ? 'absolute -left-[26px] top-0.5 size-3 rounded-full border-2 border-accent bg-canvas'
                          : 'absolute -left-[24px] top-1.5 size-1.5 rounded-full bg-ink-600'
                    }
                    aria-hidden
                  />
                  <span className={state === 'target' ? 'font-medium text-accent' : state === 'done' ? 'text-fg' : 'text-fg-subtle'}>
                    Phase {num} · {name}
                  </span>
                  {state === 'done' && <span className="ml-2 text-xs text-ok">complete</span>}
                  {state === 'target' && <span className="ml-2 text-xs text-fg-subtle">this module</span>}
                </li>
              )
            })}
          </ol>
          <Link to={`/org/${orgId}/roadmap`} className="mt-5 inline-flex items-center gap-1.5 text-sm text-fg-muted hover:text-fg">
            <ArrowLeft className="size-4" /> Back to What's next
          </Link>
        </Panel>
      </div>
    </div>
  )
}
