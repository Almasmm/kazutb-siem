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

export interface EvidenceDto {
  evidence_id: string;
  tenant_id?: string;
  request_id?: string;
  case_id?: string;
  incident_id?: string;
  alert_id?: string;
  event_id?: string;
  filename: string;
  content_type: string;
  description?: string;
  size: number;
  sha256: string;
  status: string;
  failure?: string;
  retain_until?: string;
  legal_hold?: boolean;
  uploader?: string;
  metadata?: Record<string, unknown>;
  verified_at?: string;
  custody_head_hash?: string;
  created_at?: string;
  updated_at?: string;
}

export interface EvidenceCustodyDto {
  sequence: number;
  custody_id: string;
  evidence_id: string;
  actor: string;
  action: string;
  reason: string;
  request_id?: string;
  metadata?: Record<string, unknown>;
  previous_hash: string;
  hash: string;
  created_at: string;
}

export interface EvidenceVerificationDto {
  evidence_id: string;
  expected_sha256: string;
  actual_sha256: string;
  size: number;
  valid: boolean;
  verified_at: string;
}

export interface EvidenceCustodyResponse extends ListResponse<EvidenceCustodyDto> {
  chain_valid: boolean;
}

export interface ThreatIntelFeedDto {
  feed_id: string;
  name: string;
  kind: string;
  description?: string;
  state: string;
  source_url?: string;
  refresh_interval_seconds?: number;
  default_confidence?: number;
  tags?: string[];
  version: number;
  updated_at?: string;
}

export interface ThreatIndicatorDto {
  indicator_id: string;
  feed_id: string;
  type: string;
  value: string;
  normalized_value?: string;
  source?: string;
  confidence: number;
  reputation: string;
  first_seen?: string;
  last_seen?: string;
  valid_until?: string;
  tags?: string[];
  campaign?: string;
  malware?: string;
  threat_actors?: string[];
  description?: string;
  state: string;
  version: number;
  created_at?: string;
  updated_at?: string;
}

export interface ThreatIntelMatchDto {
  match_id: string;
  indicator_id: string;
  indicator_version?: number;
  feed_id?: string;
  event_id: string;
  type: string;
  value: string;
  matched_field: string;
  matched_value: string;
  confidence: number;
  reputation: string;
  matched_at: string;
}

export interface ThreatRetrosearchDto {
  indicator_id: string;
  start: string;
  end: string;
  candidate_events: number;
  events_matched: number;
  matches: ThreatIntelMatchDto[];
  returned: number;
  partial: boolean;
  duration_micros: number;
}

export interface UEBAFeatureDto {
  code: string;
  field: string;
  value?: string;
  score: number;
  baseline_frequency: number;
  explanation: string;
}

export interface UEBAAnomalyDto {
  anomaly_id: string;
  event_id: string;
  entity_type: string;
  entity_id: string;
  entity_name: string;
  peer_group?: string;
  title: string;
  severity: Severity;
  risk_score: number;
  confidence: number;
  features: UEBAFeatureDto[];
  explanation?: Record<string, unknown>;
  model_version: string;
  feature_version?: string;
  training_window_days?: number;
  baseline_observations?: number;
  status: string;
  version: number;
  feedback_by?: string;
  feedback_reason?: string;
  feedback_at?: string;
  created_at?: string;
  updated_at?: string;
}

export interface UEBABaselineDto {
  entity_type: string;
  entity_id: string;
  entity_name: string;
  peer_group?: string;
  model_version: string;
  feature_version?: string;
  training_window_days: number;
  observation_count: number;
  first_seen?: string;
  last_seen?: string;
  drift_score: number;
  drift_status: string;
  updated_at?: string;
}

export interface SOARPlaybookDto {
  playbook_id: string;
  name: string;
  description?: string;
  state: string;
  latest_version: number;
  published_version?: number;
  revision: number;
  updated_by?: string;
  created_at?: string;
  updated_at?: string;
}

export interface SOARNodeExecutionDto {
  node_execution_id: string;
  node_id: string;
  node_type: string;
  node_name: string;
  status: string;
  attempt: number;
  output?: Record<string, unknown>;
  error_code?: string;
  error_detail?: string;
  started_at?: string;
  completed_at?: string;
  updated_at?: string;
}

export interface SOARExecutionDto {
  execution_id: string;
  playbook_id: string;
  playbook_version: number;
  request_id: string;
  trigger_type: string;
  trigger_resource_type?: string;
  trigger_resource_id?: string;
  context?: Record<string, unknown>;
  status: string;
  version: number;
  triggered_by: string;
  created_at: string;
  updated_at?: string;
  started_at?: string;
  completed_at?: string;
  nodes?: SOARNodeExecutionDto[];
}

export interface SOARApprovalDecisionDto {
  approver: string;
  decision: string;
  reason: string;
  decided_at: string;
}

export interface SOARApprovalDto {
  approval_id: string;
  execution_id: string;
  node_execution_id: string;
  risk_level: number;
  required_approvals: number;
  status: string;
  requested_by: string;
  requested_at: string;
  expires_at: string;
  decided_at?: string;
  decisions?: SOARApprovalDecisionDto[];
}

export interface SOARConnectorDto {
  connector_id: string;
  name: string;
  kind: string;
  state: string;
  endpoint: string;
  auth_type: string;
  allowed_actions?: string[];
  timeout_seconds?: number;
  rate_limit_per_minute?: number;
  version: number;
  health_status: string;
  health_error_class?: string;
  health_detail?: string;
  last_tested_at?: string;
  updated_at?: string;
}

export interface AISOCPolicyDto {
  tenant_id: string;
  enabled: boolean;
  cloud_allowed: boolean;
  pii_redaction: boolean;
  maximum_context_items: number;
  local_model: string;
  cloud_model?: string;
  version: number;
  updated_by?: string;
  updated_at?: string;
}

export interface AISOCRecommendationDto {
  summary: string;
  key_findings: string[];
  investigation_steps: string[];
  suggested_queries: string[];
  sigma_draft?: string;
  parser_draft?: string;
  mitre: string[];
  limitations: string[];
  citations: Array<{ type: string; id: string }>;
  confidence: number;
  disclaimer: string;
}

export interface AISOCRequestDto {
  request_id: string;
  request_hash: string;
  function: string;
  question?: string;
  context_refs?: Array<{ type: string; id: string }>;
  status: string;
  provider: string;
  model: string;
  recommendation?: AISOCRecommendationDto;
  requested_by: string;
  prompt_injection_detected?: boolean;
  redaction_count?: number;
  failure_class?: string;
  failure_detail?: string;
  attempt?: number;
  version: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  updated_at?: string;
}

export interface AISOCDecisionDto {
  decision_id: string;
  request_id: string;
  decision: string;
  reason: string;
  decided_by: string;
  created_at: string;
}

export interface AISOCRequestDetailsDto {
  request: AISOCRequestDto;
  decision?: AISOCDecisionDto;
}

export interface RetentionPolicyDto {
  tenant_id: string;
  raw_days: number;
  normalized_days: number;
  findings_days: number;
  evidence_days: number;
  updated_by?: string;
  version: number;
  created_at?: string;
  updated_at?: string;
}

export interface HealthDto {
  status?: string;
  ready?: boolean;
  [key: string]: unknown;
}

export interface CaseParticipantDto {
  user_id: string;
  role: string;
  added_by: string;
  added_at: string;
}

export interface CaseObservableDto {
  observable_id: string;
  type: string;
  value: string;
  source?: string;
  added_by: string;
  created_at: string;
}

export interface CaseTaskDto {
  task_id: string;
  title: string;
  description?: string;
  status: string;
  assignee?: string;
  due_at?: string;
  created_by: string;
  completed_by?: string;
  version: number;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

export interface CaseCommentDto {
  comment_id: string;
  body: string;
  author: string;
  created_at: string;
}

export interface CaseHistoryDto {
  history_id: string;
  action: string;
  message: string;
  actor: string;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface CaseDto {
  case_id: string;
  tenant_id?: string;
  title: string;
  description?: string;
  status: string;
  severity: Severity;
  owner: string;
  closure_summary?: string;
  incident_ids: string[];
  evidence_ids: string[];
  participants: CaseParticipantDto[];
  observables: CaseObservableDto[];
  tasks: CaseTaskDto[];
  comments: CaseCommentDto[];
  history: CaseHistoryDto[];
  sla: { due_at: string; breached: boolean };
  allowed_transitions: string[];
  version: number;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
}

export interface EntityDto {
  entity_id: string;
  tenant_id?: string;
  entity_type: string;
  natural_key: string;
  display_name: string;
  label?: string;
  risk_score: number;
  criticality?: string;
  attributes?: Record<string, string>;
  first_seen: string;
  last_seen: string;
  observation_count: number;
  last_event_id?: string;
  version: number;
}

export interface EntityRelationDto {
  relation_id: string;
  tenant_id?: string;
  relation_type: string;
  source_entity_id: string;
  target_entity_id: string;
  attributes?: Record<string, string>;
  first_seen: string;
  last_seen: string;
  observation_count: number;
  last_event_id?: string;
  version: number;
}

export interface EntityGraphDto {
  root: EntityDto;
  entities: EntityDto[];
  relations: EntityRelationDto[];
  event_ids: string[];
  depth: number;
  total_observations: number;
}

export interface ParserTestCaseDto {
  name: string;
  payload: string;
  expected: Record<string, string>;
}

export interface ParserSpecDto {
  format: string;
  input_kind: "JSON" | "KV";
  mappings: Record<string, string>;
  defaults: Record<string, string>;
  tests: ParserTestCaseDto[];
}

export interface ParserValidationDto {
  valid: boolean;
  spec_hash?: string;
  mapped_fields?: number;
  tests_passed?: number;
  tests_total?: number;
  errors?: string[];
  warnings?: string[];
  test_results?: Array<{ name: string; passed: boolean; errors?: string[]; event_id?: string }>;
  validated_at?: string;
  compiler?: string;
  ocsf_compatible?: string;
}

export interface ParserContentDto {
  parser_id: string;
  tenant_id?: string;
  version: number;
  name: string;
  state: string;
  spec: ParserSpecDto;
  validation: ParserValidationDto;
  created_by: string;
  request_id?: string;
  created_at: string;
  updated_at: string;
  published_at?: string;
}

export interface ParserDescriptorDto {
  parser_id: string;
  vendor: string;
  product: string;
  version: string;
  schema_compatibility: string[];
  formats: string[];
  release_state: string;
}

export interface ParserSimulationDto {
  parser_id: string;
  version: number;
  event: EventDto;
  fields: Record<string, string>;
}

export interface MITRETechniqueDto {
  technique_id: string;
  name: string;
  tactics: string[];
  status: "COVERED" | "PARTIAL" | "GAP";
  rules: Array<{ rule_id: string; title: string; version: string; severity: Severity; confidence: number }>;
  data_sources: Array<{ name: string; available: boolean; collectors: string[] }>;
  missing_data_sources: string[];
  incident_count: number;
  average_risk: number;
  maximum_risk: number;
}

export interface MITRECoverageDto {
  framework: string;
  catalog_version: string;
  techniques: MITRETechniqueDto[];
  tactics: Array<{ tactic_id: string; name: string; techniques: number; covered: number; partial: number; gaps: number; coverage_percent: number }>;
  total_techniques: number;
  covered_techniques: number;
  partial_techniques: number;
  coverage_gaps: number;
  coverage_percent: number;
  published_rules: number;
  active_collectors: number;
  incident_count: number;
  generated_at: string;
}
