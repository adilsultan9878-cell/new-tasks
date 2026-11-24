import {
  Activity,
  Bot,
  Box,
  BrainCircuit,
  Building2,
  Bug,
  Cctv,
  ChartColumn,
  Cpu,
  FileSearch,
  Fish,
  FlaskConical,
  LayoutDashboard,
  Microscope,
  MonitorSmartphone,
  Network,
  Radar,
  ScrollText,
  Settings,
  Siren,
  Users,
  Workflow,
  type LucideIcon,
} from 'lucide-react'

/**
 * The platform's module catalogue. `status: 'live'` modules are implemented end-to-end in the
 * current release; `planned` modules render an honest roadmap page (no fake controls) until the
 * phase that delivers them ships.
 */
export type ModuleStatus = 'live' | 'planned'

export interface PlatformModule {
  key: string
  name: string
  /** Shorter label for the sidebar, when the full name would truncate. */
  navName?: string
  group: ModuleGroupKey
  icon: LucideIcon
  status: ModuleStatus
  phase: number
  /** Route relative to /org/:orgId */
  path: string
  summary: string
  capabilities: string[]
  /** Permission required to see the module in navigation, if any. */
  permission?: string
}

export type ModuleGroupKey = 'overview' | 'nexus' | 'sentinel' | 'aegis' | 'admin'

export const MODULE_GROUPS: { key: ModuleGroupKey; label: string; caption: string }[] = [
  { key: 'overview', label: 'Overview', caption: '' },
  { key: 'sentinel', label: 'Respond', caption: 'SENTINEL X' },
  { key: 'aegis', label: 'Protect', caption: 'AEGIS ONE' },
  { key: 'nexus', label: 'Investigate', caption: 'NEXUS ZERO' },
  { key: 'admin', label: 'Admin', caption: '' },
]

/** Highest phase that has shipped (drives the roadmap timeline). */
export const COMPLETED_PHASE = 5

export const PHASES: Record<number, string> = {
  1: 'Foundation',
  2: 'Security Event Engine',
  3: 'NEXUS ZERO',
  4: 'Security Brain',
  5: 'SENTINEL X SOC',
  6: 'AEGIS ONE',
  7: 'Digital Twin',
  8: 'Automation',
  9: 'Hardening & Testing',
  10: 'Deployment',
}

export const MODULES: PlatformModule[] = [
  {
    key: 'command-center', name: 'Command Center', group: 'overview', icon: LayoutDashboard,
    status: 'live', phase: 1, path: '', permission: 'dashboard:read',
    summary: 'Unified, tenant-scoped view of devices, events, incidents, alerts, agents and system health.',
    capabilities: ['Real metrics from your organization only', 'Risk distribution', 'System health & RLS posture'],
  },
  // NEXUS ZERO
  {
    key: 'threat-intel', name: 'Threat Intelligence', group: 'nexus', icon: Radar, status: 'live', phase: 3,
    path: 'threat-intel', permission: 'intel:read',
    summary: 'Indicator management and enrichment from legitimate public sources, with verified facts kept separate from AI assessments.',
    capabilities: ['IP, domain and URL reputation', 'Indicator watchlists per organization', 'Source attribution on every finding', 'CISA KEV correlation'],
  },
  {
    key: 'phishing', name: 'Phishing & URL Analyzer', navName: 'Phishing & URL', group: 'nexus', icon: Fish, status: 'live', phase: 3,
    path: 'phishing', permission: 'intel:read',
    summary: 'Deterministic URL and email-header checks plus optional AI explanation, scored and recorded as investigations.',
    capabilities: ['URL structure & lookalike-domain checks', 'Email header (SPF/DKIM/DMARC) analysis', 'Risk score with evidence', 'Investigation timeline'],
  },
  {
    key: 'file-hash', name: 'File & Hash Analyzer', navName: 'File & Hash', group: 'nexus', icon: FileSearch, status: 'live', phase: 3,
    path: 'file-hash', permission: 'intel:read',
    summary: 'Hash look-ups and static file metadata against public malware-intelligence feeds. Files are never executed.',
    capabilities: ['MD5 / SHA-1 / SHA-256 look-ups', 'Static metadata extraction', 'Known-malware indicator matching'],
  },
  {
    key: 'vulnerabilities', name: 'Vulnerability Intelligence', navName: 'Vulnerabilities', group: 'nexus', icon: Bug, status: 'live', phase: 3,
    path: 'vulnerabilities', permission: 'intel:read',
    summary: 'CVE intelligence cached from NVD and the CISA Known Exploited Vulnerabilities catalogue.',
    capabilities: ['NVD CVE search & CVSS', 'CISA KEV flagging', 'Asset-to-CVE matching'],
  },
  {
    key: 'network', name: 'Network Security Monitor', navName: 'Network Monitor', group: 'nexus', icon: Network, status: 'live', phase: 3,
    path: 'network', permission: 'network:read',
    summary: 'Authorized-scope network monitoring for private lab environments: assets, exposed services and anomalous connections.',
    capabilities: ['Scope-locked Nmap discovery', 'Zeek / pcap log ingestion', 'Exposed-service tracking', 'No internet-wide scanning'],
  },
  // SENTINEL X
  {
    key: 'events', name: 'Security Events', navName: 'Security Events', group: 'sentinel', icon: Activity, status: 'live', phase: 2,
    path: 'events', permission: 'events:read',
    summary: 'Real-time stream of security events from enrolled agents and analysts, with deterministic detections and triage.',
    capabilities: ['Live WebSocket stream', 'De-duplication', 'Detection rules → alerts', 'Triage workflow'],
  },
  {
    key: 'ai-brain', name: 'Security Brain', group: 'sentinel', icon: BrainCircuit, status: 'live', phase: 4,
    path: 'brain', permission: 'brain:read',
    summary: 'Central orchestrator that runs specialised agents over alerts, devices and the whole organization and scores risk with a published, weighted model. Deterministic — no AI model is configured.',
    capabilities: ['Automatic triage of every new alert', 'Risk score with factor breakdown and data coverage', 'Playbook recommendations (advice only)', 'Downloadable Markdown reports'],
  },
  {
    key: 'agents', name: 'Agent Center', group: 'sentinel', icon: Bot, status: 'live', phase: 4,
    path: 'agents', permission: 'brain:read',
    summary: 'Specialised agents with bounded, read-only tools — no shell access, no network, no writes — and their full decision history.',
    capabilities: ['Triage, Device Risk, Exposure, Threat-Intel and Posture agents', 'Tool catalogue per agent', 'Decision history', 'Guardrails enforced by tests'],
  },
  {
    key: 'incidents', name: 'Incident Response Center', navName: 'Incident Response', group: 'sentinel', icon: Siren, status: 'live', phase: 5,
    path: 'incidents', permission: 'incidents:read',
    summary: 'Turn alerts into incidents and respond with allow-listed actions that need approval, can be rolled back and can be stopped at once.',
    capabilities: ['Alert → incident workflow', 'Approval-gated response actions', 'Rollback and emergency stop', 'Append-only timeline'],
  },
  {
    key: 'forensics', name: 'Digital Forensics Lab', navName: 'Forensics Lab', group: 'sentinel', icon: Microscope, status: 'live', phase: 5,
    path: 'forensics', permission: 'incidents:read',
    summary: 'Evidence vault with SHA-256 integrity and an append-only chain of custody.',
    capabilities: ['Files, notes and external hashes', 'Browser + server hashing', 'Verify and download with custody records', 'Immutable in the database'],
  },
  {
    key: 'automation', name: 'Workflow Automation', navName: 'Automation', group: 'sentinel', icon: Workflow, status: 'planned', phase: 8,
    path: 'm/automation',
    summary: 'Approved n8n workflows triggered by events, schedules or webhooks — with approval requirements per workflow.',
    capabilities: ['n8n integration', 'Signed webhooks', 'Scheduled & event triggers'],
  },
  {
    key: 'reports', name: 'Reports & Analytics', navName: 'Reports', group: 'sentinel', icon: ChartColumn, status: 'live', phase: 5,
    path: 'reports', permission: 'reports:read',
    summary: 'Incident and executive reports built from your own records: response times, alerts, incidents and actions. Nothing is AI-written.',
    capabilities: ['Incident reports', 'Executive summaries (MTTA, MTTR, false positives)', 'Markdown download'],
  },
  // AEGIS ONE
  {
    key: 'devices', name: 'Device Management', navName: 'Devices', group: 'aegis', icon: MonitorSmartphone, status: 'live', phase: 2,
    path: 'devices', permission: 'devices:read',
    summary: 'Enroll authorized devices with one-time tokens and the local security agent; monitor health and push approved configuration.',
    capabilities: ['Enrollment tokens', 'Per-device credentials', 'Live health & telemetry', 'Revocation'],
  },
  {
    key: 'vision', name: 'Computer Vision Security', navName: 'Computer Vision', group: 'aegis', icon: Cctv, status: 'planned', phase: 6,
    path: 'm/vision',
    summary: 'OpenCV motion and object detection on enrolled cameras with restricted zones and privacy controls. No identity recognition.',
    capabilities: ['Camera enrollment & health', 'Motion / object detection', 'Restricted-zone alerts', 'Timestamped snapshots'],
  },
  {
    key: 'iot', name: 'IoT Device Security', navName: 'IoT Security', group: 'aegis', icon: Cpu, status: 'planned', phase: 6,
    path: 'm/iot',
    summary: 'Arduino / ESP32 sensors over authenticated MQTT, with a built-in simulator for hardware-free testing.',
    capabilities: ['MQTT with per-device credentials', 'Sensor telemetry & thresholds', 'Hardware alert triggers', 'Simulator (clearly labelled)'],
  },
  {
    key: 'twin', name: 'Digital Twin', group: 'aegis', icon: Box, status: 'planned', phase: 7,
    path: 'm/twin',
    summary: 'Interactive Three.js environment of enrolled devices, connections and live events.',
    capabilities: ['3D site layout', 'Live device state', 'Incident locations', 'Simulated data clearly marked'],
  },
  // Administration
  {
    key: 'organization', name: 'Organization', group: 'admin', icon: Building2, status: 'live', phase: 1,
    path: 'organization', permission: 'org:read',
    summary: 'Organization profile and tenancy settings.',
    capabilities: ['Profile & industry', 'Isolated tenant data'],
  },
  {
    key: 'members', name: 'Users & Roles', group: 'admin', icon: Users, status: 'live', phase: 1,
    path: 'members', permission: 'members:read',
    summary: 'Members, role assignment and the permission matrix.',
    capabilities: ['Owner / Admin / Analyst / Viewer', 'Privilege-escalation guards', 'Last-owner protection'],
  },
  {
    key: 'audit', name: 'Audit Log', group: 'admin', icon: ScrollText, status: 'live', phase: 1,
    path: 'audit', permission: 'audit:read',
    summary: 'Append-only record of every security-relevant action, including failures and denials.',
    capabilities: ['Filter by action & outcome', 'Request IDs for tracing'],
  },
  {
    key: 'settings', name: 'System Settings', group: 'admin', icon: Settings, status: 'live', phase: 1,
    path: 'settings',
    summary: 'Platform status, security posture and your account security.',
    capabilities: ['API & database health', 'Row-Level Security posture', 'Sessions & password'],
  },
  {
    key: 'research', name: 'Research Lab', group: 'admin', icon: FlaskConical, status: 'planned', phase: 9,
    path: 'm/research',
    summary: 'Sandboxed space for detection-rule experiments and model evaluation on recorded, non-production data.',
    capabilities: ['Rule playground', 'Model evaluation datasets', 'Reproducible experiments'],
  },
]

export function findModule(key: string): PlatformModule | undefined {
  return MODULES.find((m) => m.key === key)
}
