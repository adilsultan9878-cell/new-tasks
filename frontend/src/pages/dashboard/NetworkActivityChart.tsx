import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, type TooltipContentProps } from 'recharts'
import type { NameType, ValueType } from 'recharts/types/component/DefaultTooltipContent'

// Loaded lazily: the charting library is only downloaded once there is data to plot.
function ActivityTooltip({ active, payload }: TooltipContentProps<ValueType, NameType>) {
  if (!active || !payload?.length) return null
  const point = payload[0]!.payload as { bucket: string; count: number }
  const start = new Date(point.bucket)
  return (
    <div className="rounded-lg border border-line-strong bg-ink-850/95 px-3 py-2 text-xs shadow-xl backdrop-blur">
      <p className="text-fg-subtle">
        {start.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} – {new Date(start.getTime() + 3_600_000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
      </p>
      <p className="tabular mt-0.5 font-medium text-fg">{point.count} network events</p>
    </div>
  )
}

export default function NetworkActivityChart({ data }: { data: { bucket: string; count: number }[] }) {
  const rows = data.map((d) => ({ ...d, label: new Date(d.bucket).toLocaleTimeString([], { hour: '2-digit' }) }))
  return (
    <>
      <div className="h-52" aria-hidden>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={rows} margin={{ top: 8, right: 4, bottom: 0, left: -12 }}>
            <defs>
              <linearGradient id="net-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.28} />
                <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="rgb(148 163 184 / 0.08)" />
            <XAxis dataKey="label" tickLine={false} axisLine={false} tick={{ fill: '#677386', fontSize: 11 }} interval={3} />
            <YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={{ fill: '#677386', fontSize: 11 }} domain={[0, (max: number) => Math.max(4, max)]} />
            <Tooltip content={ActivityTooltip} cursor={{ stroke: 'rgb(148 163 184 / 0.35)', strokeWidth: 1 }} />
            <Area type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={2} fill="url(#net-fill)" activeDot={{ r: 4, stroke: '#090c11', strokeWidth: 2, fill: '#22d3ee' }} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <table className="sr-only">
        <caption>Network events per hour, last 24 hours</caption>
        <thead>
          <tr>
            <th>Hour starting</th>
            <th>Events</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.bucket}>
              <td>{new Date(r.bucket).toLocaleString()}</td>
              <td>{r.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}
