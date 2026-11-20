// Mirrors backend/app/schemas. Keep in sync when the API changes.

export interface User {
  id: string
  email: string
  full_name: string
  email_verified: boolean
  created_at: string
  last_login_at: string | null
}

export interface TokenResponse {
  access_token: string
  token_type: 'bearer'
  expires_in: number
  user: User
}

export interface Role {
  key: 'owner' | 'admin' | 'analyst' | 'viewer' | string
  name: string
  description: string | null
  rank: number
}

export interface RoleWithPermissions extends Role {
  permissions: string[]
}

export interface Organization {
  id: string
  name: string
  slug: string
  description: string | null
  industry: string | null
  plan: string
  created_at: string
}

export interface Membership {
  organization: Organization
  role: Role
  permissions: string[]
  member_count: number
}

export interface Member {
  id: string
  user_id: string
  email: string
  full_name: string
  role: Role
  status: string
  joined_at: string
}

export interface CountBy {
  key: string
  count: number
}

export interface DashboardSummary {
  generated_at: string
  devices_total: number
  devices_by_status: CountBy[]
  device_health_avg: number | null
  active_events: number
  events_last_24h: number
  open_incidents: number
  critical_alerts: number
  open_alerts_by_severity: CountBy[]
  network_activity_24h: { bucket: string; count: number }[]
  recent_investigations: {
    id: string
    title: string
    subject_type: string
    status: string
    verdict: string
    risk_score: number | null
    created_at: string
  }[]
  recent_agent_runs: {
    id: string
    agent_name: string
    status: string
    trigger: string
    created_at: string
    finished_at: string | null
  }[]
  agent_runs_24h_by_status: CountBy[]
  members: number
  simulated_records_excluded: number
  system: SystemHealth
}

export interface SystemHealth {
  api: string
  version: string
  environment: string
  database: {
    status: string
    latency_ms: number | null
    engine: string
    row_level_security: 'enforced' | 'bypassed_by_role' | 'not_supported' | 'unknown'
  }
  realtime: string
  uptime_seconds: number
}

export interface AuditLog {
  id: string
  action: string
  outcome: 'success' | 'failure' | 'denied'
  actor_type: string
  actor: { id: string; email: string; full_name: string } | null
  target_type: string | null
  target_id: string | null
  ip_address: string | null
  user_agent: string | null
  request_id: string | null
  details: Record<string, unknown>
  created_at: string
}

export interface Page<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface Notification {
  id: string
  organization_id: string | null
  kind: string
  title: string
  body: string | null
  link: string | null
  severity: string
  read_at: string | null
  created_at: string
}

export interface SessionInfo {
  id: string
  created_at: string
  last_used_at: string | null
  expires_at: string
  ip_address: string | null
  user_agent: string | null
  current: boolean
}
