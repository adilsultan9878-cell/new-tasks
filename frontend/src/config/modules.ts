import {
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
  { key: 'nexus', label: 'NEXUS ZERO', caption: 'Threat hunting' },
  { key: 'sentinel', label: 'SENTINEL X', caption: 'Security operations' },
  { key: 'aegis', label: 'AEGIS ONE', caption: 'Environment protection' },
  { key: 'admin', label: 'Administration', caption: '' },
]

export const PHASES: Record<number, string> = {
  1: 'Foundation',
  2: 'Security Event Engine',
  3: 'NEXUS ZERO',
  4: 'AI Brain',
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
    key: 'threat-intel', name: 'Threat Intelligence', group: 'nexus', icon: Radar, status: 'planned', phase: 3,
    path: 'm/threat-intel',
    summary: 'Indicator management and enrichment from legitimate public sources, with verified facts kept separate from AI assessments.',
    capabilities: ['IP, domain and URL reputation', 'Indicator watchlists per organization', 'Source attribution on every finding', 'CISA KEV correlation'],
  },
  {
    key: 'phishing', name: 'Phishing & URL Analyzer', navName: 'Phishing & URL', group: 'nexus', icon: Fish, status: 'planned', phase: 3,
    path: 'm/phishing',
    summary: 'Deterministic URL and email-header checks plus optional AI explanation, scored and recorded as investigations.',
    capabilities: ['URL structure & lookalike-domain checks', 'Email header (SPF/DKIM/DMARC) analysis', 'Risk score with evidence', 'Investigation timeline'],
  },
  {
    key: 'file-hash', name: 'File & Hash Analyzer', navName: 'File & Hash', group: 'nexus', icon: FileSearch, status: 'planned', phase: 3,
    path: 'm/file-hash',
    summary: 'Hash look-ups and static file metadata against public malware-intelligence feeds. Files are never executed.',
    capabilities: ['MD5 / SHA-1 / SHA-256 look-ups', 'Static metadata extraction', 'Known-malware indicator matching'],
  },
  {
    key: 'vulnerabilities', name: 'Vulnerability Intelligence', navName: 'Vulnerabilities', group: 'nexus', icon: Bug, status: 'planned', phase: 3,
    path: 'm/vulnerabilities',
    summary: 'CVE intelligence cached from NVD and the CISA Known Exploited Vulnerabilities catalogue.',
    capabilities: ['NVD CVE search & CVSS', 'CISA KEV flagging', 'Asset-to-CVE matching'],
  },
  {
    key: 'network', name: 'Network Security Monitor', navName: 'Network Monitor', group: 'nexus', icon: Network, status: 'planned', phase: 3,
    path: 'm/network',
    summary: 'Authorized-scope network monitoring for private lab environments: assets, exposed services and anomalous connections.',
    capabilities: ['Scope-locked Nmap discovery', 'Zeek / pcap log ingestion', 'Exposed-service tracking', 'No internet-wide scanning'],
  },
  // SENTINEL X
  {
    key: 'ai-brain', name: 'AI Security Brain', group: 'sentinel', icon: BrainCircuit, status: 'planned', phase: 4,
    path: 'm/ai-brain',
    summary: 'Central orchestrator that normalises events, runs deterministic checks first, then consults specialised agents.',
    capabilities: ['Pluggable providers (Ollama, hosted APIs)', 'Deterministic rules before AI', 'Risk scoring with rationale', 'Full decision audit trail'],
  },
  {
    key: 'agents', name: 'Autonomous Agent Center', navName: 'Agent Center', group: 'sentinel', icon: Bot, status: 'planned', phase: 4,
    path: 'm/agents',
    summary: 'Specialised investigation agents with bounded tools — no shell access, no uncontrolled changes.',
    capabilities: ['Threat Hunter, Phishing, Malware, Network agents', 'Run history & decisions', 'Human approval gates'],
  },
  {
    key: 'incidents', name: 'Incident Response Center', navName: 'Incident Response', group: 'sentinel', icon: Siren, status: 'planned', phase: 5,
    path: 'm/incidents',
    summary: 'Alert triage, incident lifecycle and controlled response actions with approvals, rollback plans and an emergency stop.',
    capabilities: ['Alert → incident workflow', 'Approval-gated response actions', 'Rollback tracking', 'Emergency stop'],
  },
  {
    key: 'forensics', name: 'Digital Forensics Lab', navName: 'Forensics Lab', group: 'sentinel', icon: Microscope, status: 'planned', phase: 5,
    path: 'm/forensics',
    summary: 'Evidence collection with SHA-256 integrity and chain-of-custody records.',
    capabilities: ['Evidence vault with hashing', 'Chain of custody', 'Investigation timelines'],
  },
  {
    key: 'automation', name: 'Workflow Automation', navName: 'Automation', group: 'sentinel', icon: Workflow, status: 'planned', phase: 8,
    path: 'm/automation',
    summary: 'Approved n8n workflows triggered by events, schedules or webhooks — with approval requirements per workflow.',
    capabilities: ['n8n integration', 'Signed webhooks', 'Scheduled & event triggers'],
  },
  {
    key: 'reports', name: 'Reports & Analytics', navName: 'Reports', group: 'sentinel', icon: ChartColumn, status: 'planned', phase: 5,
    path: 'm/reports',
    summary: 'Incident, executive and compliance-ready reports. AI-written sections are labelled as such.',
    capabilities: ['Incident reports', 'Executive summaries', 'Export to PDF'],
  },
  // AEGIS ONE
  {
    key: 'devices', name: 'Device Management', group: 'aegis', icon: MonitorSmartphone, status: 'planned', phase: 2,
    path: 'm/devices',
    summary: 'Enroll authorized devices with per-device credentials and the optional local security agent.',
    capabilities: ['Enrollment tokens', 'Device authentication', 'Health & last-seen tracking', 'Revocation'],
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
