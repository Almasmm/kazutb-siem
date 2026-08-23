import type {
	EntityDto,
	EntityGraphDto,
	ParserContentDto,
	ParserDescriptorDto,
	ParserSimulationDto,
  AlertDto,
  AISOCDecisionDto,
  AISOCPolicyDto,
  AISOCRequestDetailsDto,
  AISOCRequestDto,
  ApiProblem,
  AuditDto,
  CaseDto,
  CollectorDto,
  EventDto,
  EvidenceCustodyResponse,
  EvidenceDto,
  EvidenceVerificationDto,
  FindingDto,
  HealthDto,
  IncidentDto,
  ListResponse,
  OverviewDto,
  RetentionPolicyDto,
  RuleDto,
  SOARApprovalDto,
  SOARConnectorDto,
  SOARExecutionDto,
  SOARPlaybookDto,
  ThreatIndicatorDto,
  ThreatIntelFeedDto,
  ThreatIntelMatchDto,
  ThreatRetrosearchDto,
  UEBAAnomalyDto,
  UEBABaselineDto,
} from "./types";
import { getAccessToken, getTenantId } from "../auth/session";
import { runtimeConfig } from "../config/runtime";

const API_BASE = runtimeConfig.apiBaseUrl.replace(/\/$/, "");
const HEALTH_BASE = API_BASE.endsWith("/api/v1") ? API_BASE.slice(0, -7) : API_BASE;

export class ApiError extends Error {
  readonly status: number;
  readonly problem?: ApiProblem;

  constructor(status: number, problem?: ApiProblem) {
    super(problem?.detail || problem?.message || problem?.title || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }
}

type QueryValue = string | number | boolean | null | undefined;

function queryString(params?: Record<string, QueryValue>): string {
  if (!params) return "";
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  });
  const serialized = search.toString();
  return serialized ? `?${serialized}` : "";
}

async function parseProblem(response: Response): Promise<ApiProblem | undefined> {
  try {
    return (await response.json()) as ApiProblem;
  } catch {
    return undefined;
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  params?: Record<string, QueryValue>,
): Promise<T> {
  const headers = new Headers(init.headers);
	const accessToken = getAccessToken();
	if (!accessToken) throw new ApiError(401, { title: "Authentication required", detail: "No active KCSP session." });
  headers.set("Accept", "application/json");
  headers.set("Authorization", `Bearer ${accessToken}`);
  headers.set("X-KCSP-Tenant-ID", getTenantId());
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}${queryString(params)}`, { ...init, headers });
  } catch (cause) {
    throw new ApiError(0, {
      title: "Network error",
      detail: cause instanceof Error ? cause.message : "Unable to reach the API",
    });
  }
  if (!response.ok) throw new ApiError(response.status, await parseProblem(response));
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

async function requestDownload(path: string, reason: string): Promise<{ blob: Blob; filename: string; sha256: string }> {
  const headers = new Headers({ "X-KCSP-Access-Reason": reason, Accept: "application/octet-stream" });
  const accessToken = getAccessToken();
  if (!accessToken) throw new ApiError(401, { title: "Authentication required", detail: "No active KCSP session." });
  headers.set("Authorization", `Bearer ${accessToken}`);
  headers.set("X-KCSP-Tenant-ID", getTenantId());
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { headers });
  } catch (cause) {
    throw new ApiError(0, { title: "Network error", detail: cause instanceof Error ? cause.message : "Unable to reach the API" });
  }
  if (!response.ok) throw new ApiError(response.status, await parseProblem(response));
  const disposition = response.headers.get("Content-Disposition") || "";
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const plain = disposition.match(/filename="?([^";]+)"?/i)?.[1];
  let filename = encoded || plain || "kcsp-evidence.bin";
  try { filename = decodeURIComponent(filename); } catch { /* retain server-provided filename */ }
  return { blob: await response.blob(), filename, sha256: response.headers.get("X-KCSP-SHA256") || "" };
}

async function publicRequest<T>(path: string, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${HEALTH_BASE}${path}`, { signal, headers: { Accept: "application/json" } });
  } catch (cause) {
    throw new ApiError(0, { title: "Network error", detail: cause instanceof Error ? cause.message : "Unable to reach the API" });
  }
  if (!response.ok) throw new ApiError(response.status, await parseProblem(response));
  return (await response.json()) as T;
}

function getList<T>(
  path: string,
  params?: Record<string, QueryValue>,
  signal?: AbortSignal,
): Promise<ListResponse<T>> {
  return request<ListResponse<T>>(path, { signal }, params);
}

function normalizeOverview(value: OverviewDto): OverviewDto {
  const metrics = value.metrics || {};
  const platform = value.platform || {};
  const totalSources = Number(platform.sources_total || 0);
  const healthySources = Number(platform.sources_healthy || 0);
  return {
    ...value,
    events_total: Number(metrics.events_24h || 0),
    alerts_total: Number(metrics.open_alerts || 0),
    alerts_open: Number(metrics.open_alerts || 0),
    critical_alerts: Number(metrics.critical_alerts || 0),
    incidents_total: Number(metrics.active_incidents || 0),
    incidents_open: Number(metrics.active_incidents || 0),
    ingest_eps: Number(platform.ingest_eps || 0),
    offline_sources: Math.max(0, totalSources - healthySources),
    parser_errors: Number(platform.parser_errors_24h || 0),
    rules_enabled: value.top_rules?.length || 0,
    alerts_by_severity: value.severity_distribution || [],
  };
}

function normalizeEvent(value: EventDto): EventDto {
  return {
    ...value,
    id: value.id || value.event_id,
    user_name: value.user_name || value.user?.name,
    device_name: value.device_name || value.device?.hostname,
    src_ip: value.src_ip || value.src_endpoint?.ip,
    dst_ip: value.dst_ip || value.dst_endpoint?.ip,
  };
}

function normalizeFinding(value: FindingDto): FindingDto {
  return {
    ...value,
    id: value.id || value.finding_id || "",
    rule_id: value.rule_id || value.rule?.id,
    rule_title: value.rule_title || value.rule?.title,
    mitre_techniques: value.mitre_techniques || value.mitre,
  };
}

function normalizeAlert(value: AlertDto): AlertDto {
  return {
    ...value,
    id: value.id || value.alert_id || "",
    rule_id: value.rule_id || value.rule?.id,
    rule_title: value.rule_title || value.rule?.title,
    asset_id: value.asset_id || value.entity?.id,
    asset_name: value.asset_name || value.entity?.name || value.entity?.label,
    user_name: value.user_name || (value.entity?.type?.toLowerCase().includes("user") ? value.entity.name : undefined),
    mitre_techniques: value.mitre_techniques || value.mitre,
    first_seen_at: value.first_seen_at || value.first_seen,
    last_seen_at: value.last_seen_at || value.last_seen,
  };
}

function normalizeIncident(value: IncidentDto): IncidentDto {
  return {
    ...value,
    id: value.id || value.incident_id || "",
    description: value.description || value.summary,
    mitre_techniques: value.mitre_techniques || value.mitre,
  };
}

function normalizeRule(value: RuleDto): RuleDto {
  const state = value.state || value.status;
  return {
    ...value,
    id: value.id || value.rule_id || "",
    status: value.status || state,
    enabled: value.enabled ?? !["DISABLED", "DRAFT", "INACTIVE"].includes(state?.toUpperCase() || ""),
    mitre_techniques: value.mitre_techniques || value.mitre,
    required_sources: value.required_sources || value.required_data_sources,
  };
}

function normalizeAudit(value: AuditDto): AuditDto {
  return {
    ...value,
    id: value.id || value.audit_id || "",
    trace_id: value.trace_id || value.request_id,
    details: value.details ?? value.metadata,
  };
}

export const api = {
  overview: (signal?: AbortSignal) => request<OverviewDto>("/overview", { signal }).then(normalizeOverview),
  events: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<EventDto>("/events", params, signal).then((page) => ({ ...page, items: page.items.map(normalizeEvent) })),
  findings: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<FindingDto>("/findings", params, signal).then((page) => ({ ...page, items: page.items.map(normalizeFinding) })),
  alerts: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<AlertDto>("/alerts", params, signal).then((page) => ({ ...page, items: page.items.map(normalizeAlert) })),
  updateAlert: (id: string, patch: Record<string, unknown>) =>
    request<AlertDto>(`/alerts/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }).then(normalizeAlert),
  incidents: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<IncidentDto>("/incidents", params, signal).then((page) => ({ ...page, items: page.items.map(normalizeIncident) })),
  createIncident: (payload: Record<string, unknown>) =>
    request<IncidentDto>("/incidents", {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "Idempotency-Key": crypto.randomUUID() },
    }).then(normalizeIncident),
  updateIncident: (id: string, patch: Record<string, unknown>) =>
    request<IncidentDto>(`/incidents/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }).then(normalizeIncident),
  rules: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<RuleDto>("/rules", params, signal).then((page) => ({ ...page, items: page.items.map(normalizeRule) })),
  audit: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<AuditDto>("/audit", params, signal).then((page) => ({ ...page, items: page.items.map(normalizeAudit) })),
  collectors: (signal?: AbortSignal) => getList<CollectorDto>("/collectors", undefined, signal),
  evidence: (params?: Record<string, QueryValue>, signal?: AbortSignal) => getList<EvidenceDto>("/evidence", params, signal),
  evidenceCustody: (id: string, signal?: AbortSignal) =>
    request<EvidenceCustodyResponse>(`/evidence/${encodeURIComponent(id)}/custody`, { signal }),
  verifyEvidence: (id: string, reason: string) =>
    request<EvidenceVerificationDto>(`/evidence/${encodeURIComponent(id)}/verify`, {
      method: "POST",
      headers: { "X-KCSP-Access-Reason": reason },
    }),
  downloadEvidence: (id: string, reason: string) => requestDownload(`/evidence/${encodeURIComponent(id)}/content`, reason),
  threatFeeds: (signal?: AbortSignal) => getList<ThreatIntelFeedDto>("/threat-intel/feeds", undefined, signal),
  threatIndicators: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<ThreatIndicatorDto>("/threat-intel/indicators", params, signal),
  threatMatches: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<ThreatIntelMatchDto>("/threat-intel/matches", params, signal),
  retrosearchThreatIndicator: (id: string, payload: { lookback_seconds: number; limit: number }) =>
    request<ThreatRetrosearchDto>(`/threat-intel/indicators/${encodeURIComponent(id)}/retrosearch`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  uebaAnomalies: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<UEBAAnomalyDto>("/ueba/anomalies", params, signal),
  uebaBaseline: (entityType: string, entityID: string, signal?: AbortSignal) =>
    request<UEBABaselineDto>(`/ueba/entities/${encodeURIComponent(entityType)}/${encodeURIComponent(entityID)}`, { signal }),
  entities: (params?: Record<string, QueryValue>, signal?: AbortSignal) => getList<EntityDto>("/entities", params, signal),
  entity: (id: string, signal?: AbortSignal) => request<EntityDto>(`/entities/${encodeURIComponent(id)}`, { signal }),
  entityGraph: (id: string, depth = 2, signal?: AbortSignal) => request<EntityGraphDto>(`/entities/${encodeURIComponent(id)}/graph?depth=${depth}&limit=500`, { signal }),
  assets: (params?: Record<string, QueryValue>, signal?: AbortSignal) => getList<EntityDto>("/assets", params, signal),
  parsers: (signal?: AbortSignal) => getList<ParserContentDto>("/parsers", undefined, signal),
  builtInParsers: (signal?: AbortSignal) => getList<ParserDescriptorDto>("/parsers/built-in", undefined, signal),
  parser: (id: string, version: number, signal?: AbortSignal) => request<ParserContentDto>(`/parsers/${encodeURIComponent(id)}/versions/${version}`, { signal }),
  createParser: (payload: Record<string, unknown>) => request<ParserContentDto>("/parsers", { method: "POST", body: JSON.stringify(payload), headers: { "Idempotency-Key": crypto.randomUUID() } }),
  createParserVersion: (id: string, payload: Record<string, unknown>) => request<ParserContentDto>(`/parsers/${encodeURIComponent(id)}/versions`, { method: "POST", body: JSON.stringify(payload), headers: { "Idempotency-Key": crypto.randomUUID() } }),
  validateParser: (id: string, version: number) => request<ParserContentDto>(`/parsers/${encodeURIComponent(id)}/versions/${version}/validate`, { method: "POST" }),
  publishParser: (id: string, version: number) => request<ParserContentDto>(`/parsers/${encodeURIComponent(id)}/versions/${version}/publish`, { method: "POST" }),
  disableParser: (id: string) => request<ParserContentDto>(`/parsers/${encodeURIComponent(id)}/disable`, { method: "POST" }),
  simulateParser: (id: string, version: number, payload: string) => request<ParserSimulationDto>(`/parsers/${encodeURIComponent(id)}/versions/${version}/simulate`, { method: "POST", body: JSON.stringify({ payload }) }),
  updateUEBAFeedback: (id: string, payload: { status: string; reason: string; version: number }) =>
    request<UEBAAnomalyDto>(`/ueba/anomalies/${encodeURIComponent(id)}/feedback`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  soarPlaybooks: (signal?: AbortSignal) => getList<SOARPlaybookDto>("/soar/playbooks", undefined, signal),
  soarExecutions: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<SOARExecutionDto>("/soar/executions", params, signal),
  soarApprovals: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<SOARApprovalDto>("/soar/approvals", params, signal),
  decideSOARApproval: (id: string, payload: { decision: string; reason: string }) =>
    request<SOARApprovalDto>(`/soar/approvals/${encodeURIComponent(id)}/decisions`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  soarConnectors: (signal?: AbortSignal) => getList<SOARConnectorDto>("/soar/connectors", undefined, signal),
  aiSOCPolicy: (signal?: AbortSignal) => request<AISOCPolicyDto>("/ai-soc/policy", { signal }),
  aiSOCRequests: (params?: Record<string, QueryValue>, signal?: AbortSignal) =>
    getList<AISOCRequestDto>("/ai-soc/requests", params, signal),
  aiSOCRequest: (id: string, signal?: AbortSignal) =>
    request<AISOCRequestDetailsDto>(`/ai-soc/requests/${encodeURIComponent(id)}`, { signal }),
  decideAISOCRequest: (id: string, payload: { decision: string; reason: string }) =>
    request<AISOCDecisionDto>(`/ai-soc/requests/${encodeURIComponent(id)}/decisions`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  retention: (signal?: AbortSignal) => request<RetentionPolicyDto>("/retention", { signal }),
  updateRetention: (payload: Pick<RetentionPolicyDto, "raw_days" | "normalized_days" | "findings_days" | "evidence_days" | "version">) =>
    request<RetentionPolicyDto>("/retention", { method: "PATCH", body: JSON.stringify(payload) }),
  healthReady: (signal?: AbortSignal) => publicRequest<HealthDto>("/health/ready", signal),
  cases: (params?: Record<string, QueryValue>, signal?: AbortSignal) => getList<CaseDto>("/cases", params, signal),
  case: (id: string, signal?: AbortSignal) => request<CaseDto>(`/cases/${encodeURIComponent(id)}`, { signal }),
  createCase: (payload: Record<string, unknown>) => request<CaseDto>("/cases", { method: "POST", body: JSON.stringify(payload), headers: { "Idempotency-Key": crypto.randomUUID() } }),
  updateCase: (id: string, payload: Record<string, unknown>) => request<CaseDto>(`/cases/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) }),
  addCaseComment: (id: string, body: string, version: number) => request<CaseDto>(`/cases/${encodeURIComponent(id)}/comments`, { method: "POST", body: JSON.stringify({ body, version }) }),
  addCaseTask: (id: string, payload: Record<string, unknown>) => request<CaseDto>(`/cases/${encodeURIComponent(id)}/tasks`, { method: "POST", body: JSON.stringify(payload) }),
  updateCaseTask: (id: string, taskID: string, payload: Record<string, unknown>) => request<CaseDto>(`/cases/${encodeURIComponent(id)}/tasks/${encodeURIComponent(taskID)}`, { method: "PATCH", body: JSON.stringify(payload) }),
  addCaseParticipant: (id: string, payload: Record<string, unknown>) => request<CaseDto>(`/cases/${encodeURIComponent(id)}/participants`, { method: "POST", body: JSON.stringify(payload) }),
  addCaseObservable: (id: string, payload: Record<string, unknown>) => request<CaseDto>(`/cases/${encodeURIComponent(id)}/observables`, { method: "POST", body: JSON.stringify(payload) }),
  linkCaseIncident: (id: string, incidentID: string, version: number) => request<CaseDto>(`/cases/${encodeURIComponent(id)}/incidents`, { method: "POST", body: JSON.stringify({ incident_id: incidentID, version }) }),
  uploadCaseEvidence: (caseID: string, file: File, description: string) => {
    const filename = file.name.normalize("NFKD").replace(/[^\x20-\x7E]/g, "_").slice(0, 255) || "evidence.bin";
    return request<EvidenceDto>("/evidence", {
      method: "POST",
      body: file,
      headers: {
        "Content-Type": file.type || "application/octet-stream",
        "X-KCSP-Filename": filename,
        "X-KCSP-Description": description.slice(0, 4000),
        "X-KCSP-Case-ID": caseID,
        "Idempotency-Key": crypto.randomUUID(),
      },
    });
  },
};

export const apiConfig = { base: API_BASE, get tenantId() { return getTenantId(); } };
