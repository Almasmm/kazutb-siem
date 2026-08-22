export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL" | string;

export interface ListResponse<T> {
  items: T[];
  total: number;
}

export interface OverviewMetricPoint {
  timestamp?: string;
  time?: string;
  count: number;
}

export interface OverviewBreakdown {
  name?: string;
  label?: string;
  title?: string;
  severity?: string;
  status?: string;
  count: number;
}

export interface OverviewDto {
  generated_at?: string;
  events_total?: number;
  findings_total?: number;
  alerts_total?: number;
  alerts_open?: number;
  critical_alerts?: number;
  high_alerts?: number;
  incidents_total?: number;
  incidents_open?: number;
  rules_total?: number;
  rules_enabled?: number;
  ingest_eps?: number;
  offline_sources?: number;
  parser_errors?: number;
  counts?: Record<string, number>;
  metrics?: Record<string, number>;
  platform?: Record<string, string | number>;
  severity_distribution?: OverviewBreakdown[];
  alerts_by_severity?: OverviewBreakdown[];
  alerts_by_status?: OverviewBreakdown[];
  alert_trend?: OverviewMetricPoint[];
  event_trend?: OverviewMetricPoint[];
  top_rules?: OverviewBreakdown[];
  recent_alerts?: AlertDto[];
  [key: string]: unknown;
}

export interface RiskComponent {
  label?: string;
  reason?: string;
  source?: string;
  delta?: number;
  score?: number;
}

export interface AlertDto {
  id: string;
  alert_id?: string;
  tenant_id?: string;
  title?: string;
  name?: string;
  description?: string;
  severity?: Severity;
  status?: string;
  disposition?: string;
  risk_score?: number;
  confidence?: number;
  rule_id?: string;
  rule_title?: string;
  rule?: { id?: string; title?: string; version?: string };
  source?: string;
  source_type?: string;
  event_count?: number;
  finding_count?: number;
  created_at?: string;
  updated_at?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  first_seen?: string;
  last_seen?: string;
  acknowledged_at?: string;
  assignee?: string;
  assignee_id?: string;
  asset_id?: string;
  asset_name?: string;
  user_name?: string;
  src_ip?: string;
  dst_ip?: string;
  mitre_techniques?: string[];
  mitre?: string[];
  entity?: { type?: string; id?: string; name?: string; label?: string };
  sla?: { acknowledge_by?: string; breached?: boolean; acknowledged_at?: string };
  event_ids?: string[];
  finding_ids?: string[];
  incident_id?: string;
  risk_breakdown?: RiskComponent[];
  version?: number;
  [key: string]: unknown;
}

export interface EventDto {
  id?: string;
  event_id?: string;
  tenant_id?: string;
  event_time?: string;
  ingest_time?: string;
  category?: string;
  class_name?: string;
  activity_name?: string;
  message?: string;
  severity?: Severity | number;
  confidence?: number;
  source?: string | Record<string, unknown>;
  source_type?: string;
  user_name?: string;
  user?: { id?: string; name?: string; is_privileged?: boolean };
  src_ip?: string;
  dst_ip?: string;
  device_name?: string;
  device?: { id?: string; hostname?: string; ip?: string; department?: string; criticality?: number };
  src_endpoint?: { ip?: string; port?: number; hostname?: string };
  dst_endpoint?: { ip?: string; port?: number; hostname?: string };
  raw?: unknown;
  [key: string]: unknown;
}

export interface FindingDto {
  id: string;
  finding_id?: string;
  title?: string;
  description?: string;
  severity?: Severity;
  confidence?: number;
  risk_score?: number;
  rule_id?: string;
  rule_title?: string;
  rule?: { id?: string; title?: string; version?: string };
  event_id?: string;
  event_time?: string;
  created_at?: string;
  asset_name?: string;
  user_name?: string;
  mitre_techniques?: string[];
  mitre?: string[];
  [key: string]: unknown;
}

export interface IncidentTimelineEntry {
  id?: string;
  timestamp?: string;
  created_at?: string;
  type?: string;
  action?: string;
  message?: string;
  actor?: string;
}

export interface IncidentDto {
  id: string;
  incident_id?: string;
  tenant_id?: string;
  title?: string;
  description?: string;
  summary?: string;
  severity?: Severity;
  status?: string;
  disposition?: string;
  created_at?: string;
  updated_at?: string;
  closed_at?: string;
  assignee?: string;
  assignee_id?: string;
  alert_ids?: string[];
  event_ids?: string[];
  finding_ids?: string[];
  entities?: Array<Record<string, unknown> | string>;
  mitre_techniques?: string[];
  mitre?: string[];
  risk_score?: number;
  allowed_transitions?: string[];
  timeline?: IncidentTimelineEntry[];
  closure_reason?: string;
  version?: number;
  [key: string]: unknown;
}

export interface RuleDto {
  id: string;
  rule_id?: string;
  title?: string;
  description?: string;
  severity?: Severity;
  confidence?: number;
  enabled?: boolean;
  status?: string;
  state?: string;
  type?: string;
  source?: string;
  version?: string | number;
  owner?: string;
  mitre_techniques?: string[];
  mitre?: string[];
  required_sources?: string[];
  required_data_sources?: string[];
  match_count?: number;
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
}

export interface AuditDto {
  id: string;
  audit_id?: string;
  tenant_id?: string;
  timestamp?: string;
  created_at?: string;
  actor?: string;
  actor_id?: string;
  action?: string;
  resource_type?: string;
  resource_id?: string;
  outcome?: string;
  ip_address?: string;
  trace_id?: string;
  request_id?: string;
  details?: unknown;
  metadata?: unknown;
  previous_hash?: string;
  hash?: string;
  [key: string]: unknown;
}

export interface CollectorDto {
  collector_id: string;
  tenant_id?: string;
  name: string;
  type: string;
  auth_subject?: string;
  state: "ACTIVE" | "REVOKED" | string;
  health: "ONLINE" | "OFFLINE" | "NEVER_SEEN" | "REVOKED" | string;
  capabilities?: string[];
  version?: string;
  observed_ip?: string;
  health_metadata?: Record<string, unknown>;
  last_seen_at?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ApiProblem {
  type?: string;
  title?: string;
  status?: number;
  code?: string;
  detail?: string;
  trace_id?: string;
  message?: string;
  field_errors?: Record<string, string[]>;
}
