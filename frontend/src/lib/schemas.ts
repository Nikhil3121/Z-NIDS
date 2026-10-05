/** Runtime-validated API contracts (mirrors backend/app/schemas). */
import { z } from "zod";

export const Severity = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof Severity>;
export const Classification = z.enum(["NORMAL", "KNOWN_ATTACK", "ANOMALOUS", "POTENTIAL_UNKNOWN"]);
export type Classification = z.infer<typeof Classification>;

export const page = <T extends z.ZodTypeAny>(item: T) =>
  z.object({ items: z.array(item), total: z.number(), page: z.number(), page_size: z.number(), pages: z.number() });
export type Page<T> = { items: T[]; total: number; page: number; page_size: number; pages: number };

const nullableStr = z.string().nullable();
const nullableNum = z.number().nullable();
const record = z.record(z.string(), z.unknown());

export const Role = z.object({ id: z.number(), name: z.string() });
export const Me = z.object({
  id: z.number(),
  email: z.string(),
  name: z.string(),
  role: Role,
  is_active: z.boolean(),
  last_login: nullableStr,
  created_at: z.string(),
  permissions: z.array(z.string()),
});
export type Me = z.infer<typeof Me>;
export const TokenResponse = z.object({ access_token: z.string(), expires_in: z.number(), user: Me });
export const User = Me.omit({ permissions: true });
export type User = z.infer<typeof User>;
export const Message = z.object({ message: z.string() });

export const SystemInfo = z.object({ environment: z.string(), demo_mode: z.boolean(), response_mode: z.string() });

export const Event = z.object({
  id: z.number(),
  ts: z.string(),
  src_ip: z.string(),
  src_port: nullableNum,
  dst_ip: z.string(),
  dst_port: nullableNum,
  protocol: z.string(),
  app_protocol: nullableStr,
  duration_ms: z.number(),
  packets_out: z.number(),
  packets_in: z.number(),
  bytes_out: z.number(),
  bytes_in: z.number(),
  tcp_flags: z.number(),
  conn_state: nullableStr,
  direction: z.string(),
  source_type: z.string(),
  sensor_id: nullableNum,
  raw_ref: nullableStr,
  is_demo: z.boolean(),
  processing_status: z.string(),
  classification: Classification.nullable(),
  anomaly_score: nullableNum,
  risk_score: nullableNum,
  ingested_at: z.string(),
  external_alert: record.nullable().optional(),
});
export type NetEvent = z.infer<typeof Event>;

export const Factor = z
  .object({
    feature: z.string().optional(),
    label: z.string().optional(),
    detail: z.string().optional(),
    value: z.unknown().optional(),
    source: z.string().optional(),
    z_score: z.number().optional(),
    ratio_to_baseline: z.number().nullable().optional(),
    contribution: z.number().nullable().optional(),
  })
  .loose();
export type Factor = z.infer<typeof Factor>;

export const Mitre = z.object({
  technique_id: z.string(),
  name: z.string(),
  tactic: z.string(),
  url: z.string(),
  confidence: z.number(),
  evidence: z.string(),
});
export type Mitre = z.infer<typeof Mitre>;

export const Detection = z.object({
  id: z.number(),
  event_id: nullableNum,
  ts: z.string(),
  classification: Classification,
  category: z.string(),
  detector: z.string(),
  detectors_fired: z.array(z.string()),
  src_ip: z.string(),
  src_port: nullableNum,
  dst_ip: z.string(),
  dst_port: nullableNum,
  protocol: z.string(),
  anomaly_score: nullableNum,
  confidence: z.number(),
  severity: Severity,
  risk_score: z.number(),
  risk_components: record,
  explanation: z.array(Factor),
  summary: z.string(),
  rule_id: nullableStr,
  model_version: nullableStr,
  predicted_family: nullableStr,
  is_demo: z.boolean(),
  mitre: z.array(Mitre),
});
export type Detection = z.infer<typeof Detection>;

export const Alert = z.object({
  id: z.number(),
  alert_type: z.string(),
  title: z.string(),
  description: z.string(),
  status: z.enum(["OPEN", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"]),
  severity: Severity,
  classification: Classification.nullable(),
  category: z.string(),
  src_ip: nullableStr,
  dst_ip: nullableStr,
  dst_port: nullableNum,
  risk_score: z.number(),
  occurrence_count: z.number(),
  first_seen: z.string(),
  last_seen: z.string(),
  primary_detection_id: nullableNum,
  incident_id: nullableNum,
  assigned_to_id: nullableNum,
  acknowledged_at: nullableStr,
  resolved_at: nullableStr,
  is_demo: z.boolean(),
  created_at: z.string(),
});
export type Alert = z.infer<typeof Alert>;

export const IncidentStatus = z.enum(["NEW", "ACKNOWLEDGED", "INVESTIGATING", "CONFIRMED", "CONTAINED", "RESOLVED"]);
export type IncidentStatus = z.infer<typeof IncidentStatus>;
export const UserRef = z.object({ id: z.number(), name: z.string(), email: z.string() });
export const Incident = z.object({
  id: z.number(),
  reference: z.string(),
  title: z.string(),
  severity: Severity,
  status: IncidentStatus,
  classification: Classification.nullable(),
  risk_score: z.number(),
  correlation_rule: nullableStr,
  primary_src_ip: nullableStr,
  first_seen: z.string(),
  last_seen: z.string(),
  assigned_to: UserRef.nullable(),
  resolution: nullableStr,
  is_demo: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type Incident = z.infer<typeof Incident>;

export const Asset = z.object({
  id: z.number(),
  ip_address: z.string(),
  hostname: nullableStr,
  mac_address: nullableStr,
  asset_type: z.string(),
  operating_system: nullableStr,
  environment: nullableStr,
  criticality: z.enum(["low", "medium", "high", "critical"]),
  owner: nullableStr,
  status: z.string(),
  notes: nullableStr,
  auto_discovered: z.boolean(),
  is_lab: z.boolean(),
  is_demo: z.boolean(),
  risk_score: z.number(),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type Asset = z.infer<typeof Asset>;

export const Activity = z.object({
  id: z.number(),
  activity_type: z.string(),
  from_value: nullableStr,
  to_value: nullableStr,
  message: z.string(),
  actor: UserRef.nullable(),
  created_at: z.string(),
});
export const EvidenceItem = z.object({
  id: z.number(),
  evidence_type: z.string(),
  event_id: nullableNum,
  detection_id: nullableNum,
  threat_intel_id: nullableNum,
  content: nullableStr,
  attachment: record.nullable(),
  created_by: UserRef.nullable(),
  created_at: z.string(),
});
export type EvidenceItem = z.infer<typeof EvidenceItem>;

export const ResponseAction = z.object({
  id: z.number(),
  action_type: z.string(),
  target: z.string(),
  reason: z.string(),
  status: z.string(),
  mode: z.string(),
  adapter: z.string(),
  incident_id: nullableNum,
  alert_id: nullableNum,
  requested_by_id: nullableNum,
  decided_by_id: nullableNum,
  decided_at: nullableStr,
  executed_at: nullableStr,
  result: record,
  created_at: z.string(),
});
export type ResponseAction = z.infer<typeof ResponseAction>;

export const TimelineItem = z
  .object({ ts: z.string(), kind: z.string(), id: z.number(), title: z.string() })
  .loose();

export const Investigation = z.object({
  incident: Incident,
  description: z.string(),
  resolution_notes: nullableStr,
  attack_chain: z.array(z.object({ stage: z.string(), category: z.string(), alert_id: z.number(), ts: z.string() }).loose()),
  summary: z.object({
    sources: z.array(z.string()),
    destinations: z.array(z.string()),
    alert_count: z.number(),
    detection_count: z.number(),
    stages: z.array(z.string()),
    risk_components: record.nullable(),
    primary_explanation: z.array(Factor),
  }),
  affected_assets: z.array(Asset.extend({ role: z.string() })),
  alerts: z.array(Alert),
  detections: z.array(Detection),
  timeline: z.array(TimelineItem),
  related_events: z.array(Event),
  related_events_visible: z.boolean(),
  related_incidents: z.array(Incident),
  threat_intelligence: z.array(
    z.object({ id: z.number(), ioc_value: z.string(), provider: z.string(), reputation: z.string(),
               confidence: z.number(), source: nullableStr, fetched_at: z.string() }),
  ),
  mitre: z.array(Mitre.extend({ detection_id: z.number() })),
  notes: z.array(EvidenceItem),
  evidence: z.array(EvidenceItem),
  response_actions: z.array(ResponseAction),
  activity: z.array(Activity),
  audit_history: z.array(record),
  audit_visible: z.boolean(),
});
export type Investigation = z.infer<typeof Investigation>;

export const Dashboard = z.object({
  generated_at: z.string(),
  window_hours: z.number(),
  demo_data_present: z.boolean(),
  overview: z.object({
    total_events: z.number(),
    traffic_bytes: z.number(),
    active_incidents: z.number(),
    critical_alerts: z.number(),
    open_alerts: z.number(),
    unknown_anomalies: z.number(),
    blocked_ips_lab: z.number(),
    response_actions_executed: z.number(),
    response_actions_pending: z.number(),
    assets_monitored: z.number(),
  }),
  live: z.object({ window_seconds: z.number(), events_per_sec: z.number(), connections_per_sec: z.number(),
                   bytes_per_sec: z.number() }),
  detection_distribution: z.object({ normal: z.number(), anomalous: z.number(), known_attack: z.number(),
                                     potential_unknown: z.number() }),
  severity: z.record(z.string(), z.number()),
  timeline: z.object({
    bucket_minutes: z.number(),
    points: z.array(z.object({ ts: z.string(), events: z.number(), bytes: z.number(), normal: z.number(),
                               anomalous: z.number(), known_attack: z.number(), potential_unknown: z.number() })),
  }),
  top_sources: z.array(z.object({ ip: z.string(), flows: z.number(), suspicious: z.number() })),
  top_destinations: z.array(z.object({ ip: z.string(), flows: z.number(), suspicious: z.number() })),
  protocols: z.array(z.object({ protocol: z.string(), flows: z.number() })),
  attack_trends: z.array(z.object({ hour: z.string(), category: z.string(), count: z.number() })),
  asset_risk: z.array(z.object({ id: z.number(), ip: z.string(), hostname: nullableStr, criticality: z.string(),
                                 risk_score: z.number(), asset_type: z.string() })),
});
export type Dashboard = z.infer<typeof Dashboard>;

export const UnknownRow = z.object({
  alert_id: z.number(),
  incident_id: nullableNum,
  incident_reference: nullableStr,
  incident_status: nullableStr,
  alert_status: z.string(),
  title: z.string(),
  src_ip: nullableStr,
  dst_ip: nullableStr,
  first_seen: z.string(),
  last_seen: z.string(),
  occurrences: z.number(),
  anomaly_score: nullableNum,
  confidence: nullableNum,
  risk_score: z.number(),
  severity: Severity,
  asset_criticality: nullableStr,
  asset_hostname: nullableStr,
  top_factors: z.array(z.string().nullable()),
  is_demo: z.boolean(),
});
export type UnknownRow = z.infer<typeof UnknownRow>;

export const Topology = z.object({
  window_minutes: z.number(),
  generated_at: z.string(),
  nodes: z.array(z.object({ id: z.string(), label: z.string(), kind: z.string(), ip: z.string().optional(),
                            criticality: z.string().nullable().optional(), status: z.string().nullable().optional(),
                            risk: z.number(), asset_id: z.number().nullable().optional(),
                            external_hosts: z.number().optional() })),
  edges: z.array(z.object({ source: z.string(), target: z.string(), flows: z.number(), bytes: z.number(),
                            suspicious: z.number(), max_risk: z.number(), highlight: z.boolean() })),
  sensors: z.array(z.object({ id: z.number(), name: z.string(), type: z.string(), last_seen: nullableStr })),
  truncated: z.boolean(),
});
export type Topology = z.infer<typeof Topology>;

export const Indicator = z.object({
  id: z.number(),
  ioc_type: z.string(),
  ioc_value: z.string(),
  provider: z.string(),
  confidence: z.number(),
  reputation: z.string(),
  source: nullableStr,
  tags: z.array(z.string()),
  raw_metadata: record,
  first_seen: nullableStr,
  last_seen: nullableStr,
  fetched_at: z.string(),
  expires_at: nullableStr,
});
export type Indicator = z.infer<typeof Indicator>;
export const ProviderStatus = z.object({
  provider: z.string(),
  status: z.string(),
  reason: nullableStr,
  supported_ioc_types: z.array(z.string()),
});

export const MitreTechnique = z.object({
  technique_id: z.string(),
  name: z.string(),
  tactic: z.string(),
  description: z.string(),
  url: z.string(),
  observed: z.number(),
  max_confidence: nullableNum,
});

export const MLModel = z.object({
  id: z.number(),
  name: z.string(),
  version: z.number(),
  tag: z.string(),
  model_type: z.string(),
  feature_version: z.string(),
  training_dataset: z.string(),
  dataset_sha256: z.string(),
  training_config: record,
  trained_at: z.string(),
  metrics: record,
  status: z.string(),
  artifact_path: z.string(),
  checksum_sha256: z.string(),
  notes: nullableStr,
  activated_at: nullableStr,
  created_at: z.string(),
});
export type MLModel = z.infer<typeof MLModel>;
export const Evaluation = z.object({
  id: z.number(),
  model_id: z.number(),
  dataset: z.string(),
  dataset_sha256: z.string(),
  heldout_families: z.array(z.string()),
  is_synthetic: z.boolean(),
  config: record,
  summary: record,
  confusion_matrix: z.record(z.string(), z.record(z.string(), z.number())),
  per_family: z.record(z.string(), record),
  created_at: z.string(),
});
export type Evaluation = z.infer<typeof Evaluation>;
export const DriftReport = z.object({
  id: z.number(),
  model_id: z.number(),
  window_start: z.string(),
  window_end: z.string(),
  sample_size: z.number(),
  threshold: z.number(),
  feature_psi: z.record(z.string(), z.number()),
  max_psi: z.number(),
  drifted: z.boolean(),
  alert_id: nullableNum,
  created_at: z.string(),
});
export type DriftReport = z.infer<typeof DriftReport>;

export const AuditEntry = z.object({
  id: z.number(),
  ts: z.string(),
  actor_id: nullableNum,
  actor_label: z.string(),
  action: z.string(),
  resource_type: nullableStr,
  resource_id: nullableStr,
  result: z.string(),
  ip_address: nullableStr,
  user_agent: nullableStr,
  request_id: nullableStr,
  details: record,
});
export type AuditEntry = z.infer<typeof AuditEntry>;

export const NotificationItem = z.object({
  id: z.number(),
  channel_type: z.string(),
  event_type: z.string(),
  title: z.string(),
  body: z.string(),
  resource_type: nullableStr,
  resource_id: nullableStr,
  delivery_status: z.string(),
  read_at: nullableStr,
  created_at: z.string(),
});
export type NotificationItem = z.infer<typeof NotificationItem>;
export const Preference = z.object({ event_type: z.string(), in_app: z.boolean(), email: z.boolean() });
export const Channel = z.object({
  id: z.number(),
  name: z.string(),
  channel_type: z.string(),
  target: z.string(),
  events: z.string(),
  min_severity: z.string(),
  is_active: z.boolean(),
  created_at: z.string(),
});
export const Sensor = z.object({
  id: z.number(),
  name: z.string(),
  sensor_type: z.string(),
  key_prefix: z.string(),
  location: nullableStr,
  is_active: z.boolean(),
  is_demo: z.boolean(),
  last_seen: nullableStr,
  events_received: z.number(),
  created_at: z.string(),
});
export type Sensor = z.infer<typeof Sensor>;

export const AssistantAnswer = z.object({
  answer: z.string(),
  mode: z.string(),
  model: nullableStr,
  citations: z.array(z.string()),
  notes: z.array(z.string()),
  evidence: z.array(z.object({ citation: z.string(), type: z.string(), record: record })),
});
export type AssistantAnswer = z.infer<typeof AssistantAnswer>;
