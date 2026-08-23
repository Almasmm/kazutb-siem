import type {
  AlertDto,
  ApiProblem,
  AuditDto,
  CollectorDto,
  EventDto,
  FindingDto,
  IncidentDto,
  ListResponse,
  OverviewDto,
  RuleDto,
} from "./types";
import { getAccessToken, getTenantId } from "../auth/session";
import { runtimeConfig } from "../config/runtime";

const API_BASE = runtimeConfig.apiBaseUrl.replace(/\/$/, "");

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
  if (init.body) headers.set("Content-Type", "application/json");

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
};

export const apiConfig = { base: API_BASE, get tenantId() { return getTenantId(); } };
