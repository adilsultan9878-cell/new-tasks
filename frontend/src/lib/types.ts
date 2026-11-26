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
  rate_limiter?: 'memory' | 'redis' | 'redis_unavailable'
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
  /** Latest Security Brain device score (null until analysed). */
  risk_score: number | null
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
  incident_id?: string | null
  /** Latest Security Brain triage of this alert (null until analysed). */
  triage?: TriageSummary | null
}

export interface TriageSummary {
  run_id: string
  risk_score: number | null
  risk_level: RiskLevel | null
  priority: string | null
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

// ------------------------------------------------------------------ Security Brain (Phase 4)
export type RiskLevel = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type BrainSubject = 'alert' | 'device' | 'organization'
export type AgentName = 'triage' | 'device' | 'exposure' | 'intel' | 'posture'

export interface BrainFactor {
  key: string
  label: string
  agent: string
  points: number
  max_points: number
  has_data: boolean
  evidence: string
}

export interface BrainTraceEntry {
  seq: number
  agent: string
  tool: string
  args: Record<string, unknown>
  rows: number
  duration_ms: number
}

export interface EvidenceRef {
  type: string
  id: string
  label: string
}

export interface BrainRecommendation {
  code: string
  text: string
  urgency: 'now' | 'soon' | 'later'
  changes_system: boolean
  agent: string
  because: string
  evidence: EvidenceRef[]
  /** A response action the analyst can propose in one click (it still needs approval). */
  proposal?: { action_type: ActionType; target: Record<string, string> } | null
}

export interface BrainDecision {
  id: string
  agent_run_id: string
  decision_type: 'finding' | 'score' | 'classify' | 'recommend'
  agent_name: string | null
  severity: Severity | null
  summary: string
  rationale: string | null
  confidence: number | null
  is_ai_generated: boolean
  evidence_refs: EvidenceRef[]
  created_at: string
}

export interface BrainDecisionWithRun extends BrainDecision {
  subject_type: BrainSubject | null
  subject_label: string | null
}

export interface BrainRun {
  id: string
  agent_name: string
  trigger: 'manual' | 'alert' | string
  status: string
  model_provider: string | null
  subject_type: BrainSubject
  subject_id: string | null
  subject_label: string | null
  risk_score: number | null
  risk_level: RiskLevel | null
  coverage: number | null
  priority: string | null
  summary: string | null
  finding_count: number
  recommendation_count: number
  created_by: string | null
  created_at: string
  finished_at: string | null
}

export interface BrainRunDetail extends BrainRun {
  factors: BrainFactor[]
  trace: BrainTraceEntry[]
  recommendations: BrainRecommendation[]
  decisions: BrainDecision[]
  agents: AgentName[]
  lookback_days: number | null
  engine_version: string | null
}

export interface BrainAgent {
  name: AgentName
  title: string
  description: string
  subjects: BrainSubject[]
  tools: string[]
}

export interface BrainFactorModel {
  key: string
  label: string
  max_points: number
  agent: string
  description: string
}

export interface BrainStatus {
  engine: { provider: string; mode: string; model: string | null; ai_enabled: boolean; engine_version: string; description: string }
  auto_triage: boolean
  lookback_days: number
  agents: BrainAgent[]
  tools: { name: string; description: string }[]
  models: Record<BrainSubject, BrainFactorModel[]>
}

export interface BrainActivity {
  runs_total: number
  runs_by_trigger: Record<string, number>
  agents: { agent: AgentName; findings: number; recommendations: number; last_decision_at: string | null }[]
}

// --------------------------------------------------------------------- SENTINEL X SOC (Phase 5)
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'eradicated' | 'recovered' | 'closed'
export type ActionType = 'notify_team' | 'heighten_monitoring' | 'block_indicator' | 'revoke_device' | 'suspend_member'
export type ActionStatus = 'pending_approval' | 'approved' | 'rejected' | 'executing' | 'succeeded' | 'failed' | 'rolled_back' | 'cancelled'
export type Impact = 'low' | 'medium' | 'high'

export interface Incident {
  id: string
  reference: string
  title: string
  summary: string | null
  severity: Severity
  status: IncidentStatus
  assigned_to: string | null
  assignee_name: string | null
  opened_by: string | null
  opened_at: string
  closed_at: string | null
  updated_at: string
  alert_count: number
  pending_actions: number
}

export interface TimelineEntry {
  at: string
  kind: string
  text: string
  actor: string | null
  actor_id: string | null
}

export interface ApprovalInfo {
  id: string
  status: 'pending' | 'approved' | 'rejected' | 'expired'
  requested_by: string | null
  decided_by: string | null
  decided_by_name: string | null
  decided_at: string | null
  comment: string | null
  expires_at: string | null
}

export interface ResponseAction {
  id: string
  incident_id: string | null
  incident_reference: string | null
  proposed_by_run_id: string | null
  action_type: ActionType
  title: string | null
  reason: string | null
  impact: Impact
  reversible: boolean
  requires_approval: boolean
  status: ActionStatus
  target: Record<string, string>
  result: Record<string, unknown>
  requested_by: string | null
  requested_by_name: string | null
  executed_at: string | null
  rolled_back_at: string | null
  created_at: string
  approval: ApprovalInfo | null
}

export interface ActionTypeInfo {
  key: ActionType
  title: string
  impact: Impact
  reversible: boolean
  description: string
  target_fields: string[]
}

export interface EmergencyStopState {
  engaged: boolean
  reason: string | null
  at: string | null
  actor: string | null
}

export interface ResponseStatus {
  emergency_stop: EmergencyStopState
  pending_approvals: number
  approvers: number
  action_types: ActionTypeInfo[]
}

export interface CustodyEntry {
  at: string
  action: string
  actor: string | null
  note?: string | null
  sha256?: string | null
  result?: string | null
}

export interface EvidenceItem {
  id: string
  incident_id: string | null
  incident_reference: string | null
  evidence_type: 'file' | 'note' | 'external'
  title: string | null
  description: string | null
  filename: string | null
  content_type: string | null
  sha256: string | null
  size_bytes: number | null
  stored: boolean
  collected_by: string | null
  collected_at: string
  chain_of_custody: CustodyEntry[]
}

export interface ReportSummary {
  id: string
  incident_id: string | null
  title: string
  report_type: 'incident' | 'executive'
  status: string
  is_ai_generated: boolean
  generated_by: string | null
  created_at: string
}

export interface ReportDetail extends ReportSummary {
  markdown: string
  metrics: Record<string, unknown>
}

export interface IncidentDetail extends Incident {
  timeline: TimelineEntry[]
  alerts: Alert[]
  actions: ResponseAction[]
  evidence: EvidenceItem[]
  reports: ReportSummary[]
}

// ------------------------------------------------------------------------ AEGIS ONE (Phase 6)
export interface Sensor {
  id: string
  device_id: string | null
  device_name: string | null
  sensor_key: string | null
  name: string
  sensor_type: string
  unit: string | null
  status: string
  thresholds: { min?: number; max?: number; severity?: string }
  actuator_rules: ('led' | 'buzzer')[]
  in_breach: boolean
  last_value: number | null
  last_reading_at: string | null
  is_simulated: boolean
}

export interface ReadingPoint {
  t: string
  v: number
}

export interface ActuatorState {
  on: boolean
  source: 'manual' | 'rule' | 'idle'
  until?: string
  by?: string | null
  because?: string[]
}

export interface Hub {
  device_id: string
  name: string
  status: string
  is_simulated: boolean
  sensor_count: number
  actuators: Record<'led' | 'buzzer', ActuatorState>
}

export interface Zone {
  name: string
  x: number
  y: number
  w: number
  h: number
}

export interface Camera {
  id: string
  device_id: string | null
  device_name: string | null
  camera_key: string | null
  name: string
  status: string
  detection_enabled: boolean
  privacy_mode: boolean
  blur_people: boolean
  retention_days: number
  zones: Zone[]
  last_frame_at: string | null
  last_event_at: string | null
  snapshot_count: number
  is_simulated: boolean
}

export interface Snapshot {
  id: string
  camera_id: string
  event_type: string
  content_type: string
  captured_at: string
  expires_at: string
}

export interface SimulatorResult {
  hub_id: string
  sensors: number
  readings: number
  breaches: number
  detections: number
  actuators: Record<string, boolean>
}

// ---------------------------------------------------------------------- Digital Twin (Phase 7)
export interface TwinArea {
  id: string
  name: string
  x: number
  y: number
  w: number
  h: number
  simulated?: boolean
}

export interface TwinDevice {
  id: string
  name: string
  device_type: string
  status: string
  health_score: number | null
  risk_score: number | null
  ip_address: string | null
  segment: string | null
  is_simulated: boolean
  position: { x: number; y: number; area: string | null } | null
  open_alerts: number
  max_alert_severity: Severity | null
  open_incidents: { id: string; reference: string; title: string; severity: Severity; status: string }[]
  sensors: { id: string; name: string; sensor_type: string; unit: string | null; last_value: number | null; in_breach: boolean }[]
  cameras: { id: string; name: string; detection_enabled: boolean; zones: number; last_event_at: string | null }[]
}

export interface Twin {
  generated_at: string
  floor: { width: number; depth: number }
  areas: TwinArea[]
  devices: TwinDevice[]
  segments: { cidr: string; device_ids: string[] }[]
  stats: {
    devices: number
    online: number
    degraded: number
    offline: number
    open_alerts: number
    open_incidents: number
    sensors_in_breach: number
    simulated: number
    placed: number
  }
}

// ------------------------------------------------------------------------- automation (Phase 8)
export type TriggerType = 'event' | 'schedule' | 'manual' | 'webhook'
export type RunStatus = 'awaiting_approval' | 'succeeded' | 'failed' | 'rejected' | 'expired' | 'skipped'

export interface WorkflowStep {
  type: string
  [param: string]: unknown
}

export interface Workflow {
  id: string
  name: string
  description: string | null
  trigger_type: TriggerType
  trigger_config: { event?: string; min_severity?: string; include_simulated?: boolean; every_minutes?: number }
  trigger_label: string
  steps: { type: string; title: string; risk: string; params: Record<string, unknown> }[]
  requires_approval: boolean
  approval_forced: boolean
  enabled: boolean
  hook_path: string | null
  next_run_at: string | null
  last_run_at: string | null
  last_status: string | null
  owner_name: string | null
  created_at: string
  updated_at: string
}

export interface WorkflowSecret {
  workflow: Workflow
  secret: string
  hook_path: string
}

export interface AutomationRun {
  id: string
  workflow_id: string
  workflow_name: string
  status: RunStatus
  trigger_kind: TriggerType
  trigger_label: string
  steps: { type: string | null; title: string | null; risk: string | null; status: string; detail: string | null; link: string | null }[]
  context: Record<string, unknown>
  requested_by_name: string | null
  decided_by_name: string | null
  decided_at: string | null
  decision_comment: string | null
  expires_at: string | null
  error: string | null
  is_simulated: boolean
  created_at: string
  finished_at: string | null
}

export interface Webhook {
  id: string
  name: string
  provider: 'webhook' | 'n8n'
  url: string
  host: string
  description: string | null
  enabled: boolean
  failure_count: number
  last_error: string | null
  last_success_at: string | null
  created_at: string
  used_by: number
}

export interface WebhookSecret {
  webhook: Webhook
  secret: string
}

export interface Delivery {
  id: string
  webhook_id: string
  run_id: string | null
  event_type: string
  status: 'pending' | 'delivered' | 'failed'
  attempts: number
  next_attempt_at: string | null
  last_status_code: number | null
  last_error: string | null
  response_ms: number | null
  delivered_at: string | null
  is_simulated: boolean
  created_at: string
}

export interface AutomationOverview {
  workflows: number
  enabled: number
  webhooks: number
  awaiting_approval: number
  runs_today: number
  failed_today: number
  deliveries_pending: number
  deliveries_failed: number
  signing_key: 'dedicated' | 'jwt' | 'ephemeral'
  delivery_enabled: boolean
  private_targets_allowed: boolean
  emergency_stop: boolean
}

export interface Recipe {
  key: string
  name: string
  description: string
  trigger_type: TriggerType
  trigger_config: Workflow['trigger_config']
  steps: WorkflowStep[]
  requires_approval: boolean
  needs: string[]
}

export interface AutomationCatalog {
  trigger_types: { key: TriggerType; title: string }[]
  events: { key: string; title: string; description: string; filters: string[]; fields: string[] }[]
  schedules: { every_minutes: number; title: string }[]
  steps: { key: string; title: string; description: string; risk: string; permission: string | null; triggers: string[]; events: string[] }[]
  indicator_types: string[]
  audiences: string[]
  recipes: Recipe[]
  signature: { header: string; timestamp_header: string; algorithm: string; tolerance_seconds: number }
}

// --------------------------------------------------------------------------- research lab (Phase 9)
export type LabField = 'category' | 'event_type' | 'severity' | 'title' | 'source' | 'device'
export type LabOp = 'eq' | 'ne' | 'in' | 'contains' | 'not_contains' | 'startswith' | 'gte' | 'lte'

export interface LabCondition {
  field: LabField
  op: LabOp
  value: string | string[]
}

export interface LabRule {
  mode: 'all' | 'any'
  conditions: LabCondition[]
  threshold: { count: number; within_minutes: number; per_device: boolean } | null
}

export interface LabDataset {
  id: string
  name: string
  description: string | null
  source: 'events' | 'upload'
  params: Record<string, unknown>
  row_count: number
  label_counts: { malicious: number; benign: number; unlabelled: number }
  sha256: string
  includes_simulated: boolean
  created_by_name: string | null
  created_at: string
  experiments: number
}

export interface LabScore {
  fired: number
  fired_unlabelled: number
  confusion: { tp: number; fp: number; fn: number; tn: number }
  precision: number | null
  recall: number | null
  f1: number | null
  alerts_per_day: number
}

export interface LabExperiment {
  id: string
  dataset_id: string
  dataset_name: string | null
  name: string
  rule: LabRule
  rule_sha256: string
  dataset_sha256: string
  engine_version: string
  results: LabScore & {
    engine: string
    rows: number
    labelled: number
    baseline: LabScore
    samples: Record<'tp' | 'fp' | 'fn', { id: string; title: string; t: string }[]>
  }
  created_by_name: string | null
  created_at: string
}

export interface LabReproduction {
  reproduced: boolean
  checks: Record<string, boolean>
  engine_version: string
}

// ------------------------------------------------------------------- accounts (Phase 10)
export interface AuthPolicy {
  registration: 'open' | 'invite_only' | 'domains'
  first_account: boolean
  allowed_domains: string[]
  password_reset: boolean
  email_verification: boolean
  email_verification_required: boolean
}

export interface Invitation {
  id: string
  email: string
  role: { key: string; name: string; description: string | null; rank: number }
  invited_by_name: string | null
  emailed: boolean
  created_at: string
  expires_at: string
  status: 'pending' | 'expired'
}

export interface InvitationCreated {
  invitation: Invitation
  link: string | null
}

export interface InvitationInfo {
  organization_name: string
  role: string
  email: string
  email_hint: string
  expires_at: string
  account_exists: boolean
}
