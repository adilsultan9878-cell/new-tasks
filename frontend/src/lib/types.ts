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
  recent_events: {
    id: string
    title: string
    severity: string
    category: string
    device_name: string | null
    occurrence_count: number
    occurred_at: string
  }[]
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

// ---------------------------------------------------------------- Phase 2: devices & events
export type DeviceStatus = 'online' | 'offline' | 'degraded' | 'unknown' | 'decommissioned'

export interface Device {
  id: string
  name: string
  device_type: string
  hostname: string | null
  os: string | null
  ip_address: string | null
  mac_address: string | null
  status: DeviceStatus
  enrollment_status: 'pending' | 'enrolled' | 'revoked'
  health_score: number | null
  agent_version: string | null
  enrolled_at: string | null
  last_seen_at: string | null
  is_simulated: boolean
  created_at: string
}

export interface AgentConfig {
  heartbeat_interval_seconds: number
  collectors: ('system' | 'network' | 'ports')[]
  thresholds: { cpu_percent: number; memory_percent: number; disk_percent: number }
}

export interface DeviceDetail extends Device {
  telemetry: {
    cpu_percent?: number
    memory_percent?: number
    disk_percent?: number
    uptime_seconds?: number
    process_count?: number
    listening_ports?: number[]
    interfaces?: { name: string; addresses: string[] }[]
    reported_at?: string
  }
  config: AgentConfig
  config_version: number
  credential_rotated_at: string | null
}

export interface EnrollmentToken {
  id: string
  label: string
  device_type: string
  max_uses: number
  use_count: number
  expires_at: string
  revoked_at: string | null
  last_used_at: string | null
  created_at: string
  state: 'active' | 'expired' | 'exhausted' | 'revoked'
}

export interface EnrollmentTokenCreated extends EnrollmentToken {
  token: string
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface SecurityEvent {
  id: string
  device_id: string | null
  device_name: string | null
  source: string
  category: string
  event_type: string
  severity: Severity
  status: 'new' | 'triaged' | 'closed'
  title: string
  occurred_at: string
  ingested_at: string
  occurrence_count: number
  last_occurred_at: string | null
  is_simulated: boolean
}

export interface Alert {
  id: string
  event_id: string | null
  title: string
  description: string | null
  severity: Severity
  status: string
  risk_score: number | null
  detection_rule: string | null
  created_at: string
}

export interface SecurityEventDetail extends SecurityEvent {
  description: string | null
  raw: Record<string, unknown>
  normalized: Record<string, unknown>
  alerts: Alert[]
}

export interface IngestResult {
  accepted: number
  deduplicated: number
  rejected: { index: number; reason: string }[]
  alerts_created: number
  event_ids: string[]
}
