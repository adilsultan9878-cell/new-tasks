import type { Severity, Twin, TwinDevice } from '@/lib/types'

export interface Placement {
  x: number
  y: number
  auto: boolean
}

/** Saved positions win; devices that were never placed line up along the front of the floor. */
export function placements(twin: Twin, overrides: Record<string, { x: number; y: number }> = {}): Record<string, Placement> {
  const out: Record<string, Placement> = {}
  const unplaced = twin.devices.filter((d) => !overrides[d.id] && !d.position)
  const spacing = Math.min(8, (twin.floor.width - 8) / Math.max(1, unplaced.length))
  unplaced.forEach((d, i) => {
    out[d.id] = { x: 4 + spacing * (i + 0.5), y: twin.floor.depth - 4, auto: true }
  })
  for (const d of twin.devices) {
    const o = overrides[d.id]
    if (o) out[d.id] = { ...o, auto: false }
    else if (d.position) out[d.id] = { x: d.position.x, y: d.position.y, auto: false }
  }
  return out
}

/** The area a floor point falls in (the smallest one when areas overlap). */
export function areaAt(twin: Twin, x: number, y: number): string | null {
  const hits = twin.areas.filter((a) => x >= a.x && x <= a.x + a.w && y >= a.y && y <= a.y + a.h)
  hits.sort((a, b) => a.w * a.h - b.w * b.h)
  return hits[0]?.name ?? null
}

export function clampToFloor(twin: Twin, x: number, y: number): { x: number; y: number } {
  const round = (v: number) => Math.round(v * 10) / 10
  return { x: round(Math.min(twin.floor.width, Math.max(0, x))), y: round(Math.min(twin.floor.depth, Math.max(0, y))) }
}

export const STATUS_COLOR: Record<string, string> = {
  online: '#2fbf71',
  degraded: '#fab219',
  offline: '#f0565b',
  unknown: '#8b98a9',
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#f0565b',
  high: '#ec835a',
  medium: '#fab219',
  low: '#3987e5',
  info: '#8b98a9',
}

export function statusColor(d: Pick<TwinDevice, 'status'>): string {
  return STATUS_COLOR[d.status] ?? STATUS_COLOR.unknown!
}

/** Marker height grows with the Security Brain risk score (1.5 m baseline, up to 7.5 m). */
export function markerHeight(d: Pick<TwinDevice, 'risk_score'>): number {
  return 1.5 + ((d.risk_score ?? 0) / 100) * 6
}
