import { Cctv, Radar, ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'

import { Wordmark } from '@/components/ui/Logo'

const PILLARS = [
  { icon: Cctv, name: 'AEGIS ONE', text: 'Intelligent environment protection — cameras, sensors and IoT.' },
  { icon: Radar, name: 'NEXUS ZERO', text: 'AI-assisted threat hunting grounded in verified intelligence.' },
  { icon: ShieldCheck, name: 'SENTINEL X', text: 'Security operations with human-approved, audited response.' },
]

export function AuthLayout({ title, subtitle, children, footer }: { title: string; subtitle: string; children: ReactNode; footer: ReactNode }) {
  return (
    <div className="grid min-h-screen lg:grid-cols-[1.05fr_1fr]">
      <aside className="relative hidden overflow-hidden border-r border-line bg-ink-900/60 lg:flex lg:flex-col lg:justify-between lg:p-12">
        <div className="grid-bg pointer-events-none absolute inset-0" aria-hidden />
        <div className="pointer-events-none absolute -left-32 top-1/3 size-[520px] rounded-full bg-accent/10 blur-[120px]" aria-hidden />
        <div className="relative">
          <Wordmark />
        </div>
        <div className="relative max-w-md">
          <p className="text-[11px] font-medium uppercase tracking-[0.2em] text-accent">Detect · Understand · Protect · Automate</p>
          <h2 className="mt-4 text-3xl font-semibold leading-tight tracking-tight text-fg">
            One intelligent platform.
            <br />
            <span className="bg-gradient-to-r from-accent to-electric bg-clip-text text-transparent">Complete digital awareness.</span>
          </h2>
          <ul className="mt-10 space-y-5">
            {PILLARS.map(({ icon: Icon, name, text }) => (
              <li key={name} className="flex gap-3.5">
                <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-line-strong bg-ink-850 text-accent">
                  <Icon className="size-4" aria-hidden />
                </span>
                <span>
                  <span className="block text-[13px] font-semibold tracking-wide text-fg">{name}</span>
                  <span className="block text-sm text-fg-muted">{text}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-xs text-fg-subtle">For authorized environments only. Every action is audited.</p>
      </aside>
      <main className="flex items-center justify-center px-4 py-12 sm:px-8">
        <div className="w-full max-w-sm animate-rise">
          <div className="mb-8 lg:hidden">
            <Wordmark />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-1.5 text-sm text-fg-muted">{subtitle}</p>
          <div className="mt-8">{children}</div>
          <div className="mt-8 text-sm text-fg-muted">{footer}</div>
        </div>
      </main>
    </div>
  )
}
