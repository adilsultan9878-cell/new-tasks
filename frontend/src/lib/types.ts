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

// ---------------------------------------------------------------- Phase 3: NEXUS ZERO
export type SubjectType = 'url' | 'domain' | 'ip' | 'hash' | 'email'
export type Verdict = 'unknown' | 'benign' | 'suspicious' | 'malicious'

export interface IntelFinding {
  code: string
  title: string
  detail: string
  severity: Severity
  score: number
  source: string
  kind: 'intel' | 'heuristic' | 'context'
  data: Record<string, unknown>
}

export interface Investigation {
  id: string
  subject_type: SubjectType
  subject: string
  title: string
  status: string
  verdict: Verdict
  risk_score: number | null
  created_at: string
  completed_at: string | null
}

export interface SourceCheck {
  source: string
  status: 'ok' | 'not_configured' | 'unavailable' | 'skipped'
  detail: string
  duration_ms: number
}

export interface InvestigationDetail extends Investigation {
  summary: string | null
  verified_findings: IntelFinding[]
  ai_assessment: string | null
  timeline: { at: string; step: string; status: string; detail?: string; duration_ms?: number }[]
  details: Record<string, unknown> & { checks?: SourceCheck[]; indicators?: { type: string; value: string }[] }
}

export interface Indicator {
  id: string
  indicator_type: string
  value: string
  verdict: Verdict
  confidence: number
  source: 'analyst' | 'investigation' | string
  is_verified: boolean
  first_seen_at: string
  last_seen_at: string
  context: { note?: string; investigations?: string[] } & Record<string, unknown>
}

export interface IntelProvider {
  key: string
  name: string
  covers: string[]
  requires_key: string | null
  optional_key?: string | null
  url: string | null
  configured: boolean
  enabled: boolean
}

export interface Vulnerability {
  cve_id: string
  title: string | null
  vendor: string | null
  product: string | null
  cvss_score: number | null
  severity: string | null
  in_cisa_kev: boolean
  kev_date_added: string | null
  known_ransomware_use: boolean
}

export interface VulnerabilityDetail extends Vulnerability {
  description: string | null
  cvss_vector: string | null
  published_at: string | null
  last_modified_at: string | null
  kev_due_date: string | null
  kev_required_action: string | null
  cwes: string[]
  references: string[]
  source: string
  fetched_at: string
  nvd_error: string | null
}

export interface VulnerabilityStats {
  total: number
  kev_total: number
  ransomware_total: number
  last_kev_sync: string | null
}

export interface NetworkScope {
  id: string
  cidr: string
  label: string
  is_private: boolean
  created_at: string
}

export interface NetworkAsset {
  id: string
  ip_address: string
  hostname: string | null
  mac_address: string | null
  vendor: string | null
  open_ports: number[]
  services: { port: number; protocol: string; service: string | null; product: string | null }[]
  in_authorized_scope: boolean
  source: string
  device_id: string | null
  first_seen_at: string
  last_seen_at: string
}

export interface ScanImportResult {
  hosts_in_file: number
  imported: number
  out_of_scope: number
  new_assets: number
  new_services: number
  events: number
}
