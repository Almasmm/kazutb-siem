// Per-source telemetry health reported by the agent in collector heartbeat
// metadata. Agent connectivity and source acquisition are separate concerns: an
// agent can be ONLINE while every one of its channels is failing to read, so the
// Collectors page surfaces both instead of only the heartbeat state.

export type SourceState = "HEALTHY" | "DEGRADED" | "STARTING" | "UNSUPPORTED";

export interface SourceHealth {
  name: string;
  channel?: string;
  state: SourceState;
  last_success_at?: string;
  last_error_at?: string;
  last_error?: string;
  error_count: number;
  consecutive_errors: number;
  events_read: number;
  checkpoint: number;
  quarantined?: number;
  encoding?: string;
  next_attempt_at?: string;
  backoff_seconds?: number;
}

const SOURCE_STATES: SourceState[] = ["HEALTHY", "DEGRADED", "STARTING", "UNSUPPORTED"];

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/**
 * Reads the source health array out of free-form collector health metadata.
 * Metadata is agent-supplied, so every field is validated and anything
 * unrecognised is dropped rather than rendered.
 */
export function parseSourceHealth(metadata: Record<string, unknown> | null | undefined): SourceHealth[] {
  const entries = metadata?.source_health;
  if (!Array.isArray(entries)) return [];
  const parsed: SourceHealth[] = [];
  for (const entry of entries) {
    const record = asRecord(entry);
    if (!record) continue;
    const name = asString(record.name);
    if (!name) continue;
    const rawState = asString(record.state)?.toUpperCase();
    const state = SOURCE_STATES.includes(rawState as SourceState) ? (rawState as SourceState) : "STARTING";
    parsed.push({
      name,
      channel: asString(record.channel),
      state,
      last_success_at: asString(record.last_success_at),
      last_error_at: asString(record.last_error_at),
      last_error: asString(record.last_error),
      error_count: asNumber(record.error_count),
      consecutive_errors: asNumber(record.consecutive_errors),
      events_read: asNumber(record.events_read),
      checkpoint: asNumber(record.checkpoint),
      quarantined: asNumber(record.quarantined),
      encoding: asString(record.encoding),
      next_attempt_at: asString(record.next_attempt_at),
      backoff_seconds: asNumber(record.backoff_seconds),
    });
  }
  return parsed;
}

/**
 * Summarises acquisition health independently of the heartbeat. Any degraded
 * source degrades the whole collector, because a heartbeat alone does not mean
 * telemetry is arriving.
 */
export function summarizeSourceState(sources: SourceHealth[]): SourceState | null {
  if (!sources.length) return null;
  if (sources.some((source) => source.state === "DEGRADED")) return "DEGRADED";
  if (sources.some((source) => source.state === "HEALTHY")) {
    return sources.every((source) => source.state === "HEALTHY" || source.state === "UNSUPPORTED") ? "HEALTHY" : "STARTING";
  }
  if (sources.every((source) => source.state === "UNSUPPORTED")) return "UNSUPPORTED";
  return "STARTING";
}

/**
 * Ingestion lag for a source: how long ago it last read successfully. Returns
 * null when the source has never had a successful read.
 */
export function sourceLagSeconds(source: SourceHealth, now: Date = new Date()): number | null {
  if (!source.last_success_at) return null;
  const lastSuccess = Date.parse(source.last_success_at);
  if (Number.isNaN(lastSuccess)) return null;
  return Math.max(0, Math.round((now.getTime() - lastSuccess) / 1000));
}
