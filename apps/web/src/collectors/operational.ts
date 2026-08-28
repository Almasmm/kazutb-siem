import type { CollectorDto, CollectorOperationalDto, FleetSummaryDto } from "../api/types";
import { parseSourceHealth, type SourceHealth } from "./sourceHealth";

// The console shows connectivity and telemetry as separate facts. An agent
// whose heartbeat lands is reachable; whether its channels read and whether its
// backlog drains are different questions, and collapsing them into one ONLINE
// badge is what hid a 51k-event backlog on the pilot host.

export type OperationalState = "HEALTHY" | "DEGRADED" | "OFFLINE" | "NEVER_SEEN" | "REVOKED" | "UNKNOWN";

const OPERATIONAL_STATES: OperationalState[] = ["HEALTHY", "DEGRADED", "OFFLINE", "NEVER_SEEN", "REVOKED", "UNKNOWN"];

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/**
 * Reads the server-derived operational view. Older agents and collectors that
 * predate the operational block fall back to whatever the heartbeat metadata
 * carries, so the page degrades gracefully instead of rendering blanks.
 */
export function collectorOperational(collector: CollectorDto | null | undefined): CollectorOperationalDto | null {
  if (!collector) return null;
  if (collector.operational) return collector.operational;
  const metadata = collector.health_metadata;
  if (!metadata) return null;
  return {
    connectivity: collector.health || "UNKNOWN",
    telemetry: "UNKNOWN",
    overall: collector.health === "ONLINE" ? "HEALTHY" : collector.health || "UNKNOWN",
    queue_depth: asNumber(metadata.queue_depth),
    queue_bytes: asNumber(metadata.queue_bytes),
    source_total: parseSourceHealth(metadata).length,
    source_healthy: 0,
    source_degraded: 0,
    collection_rate_eps: 0,
    delivery_rate_eps: 0,
    net_backlog_rate_eps: 0,
    events_collected_total: 0,
    events_delivered_total: 0,
    send_failures_total: 0,
    backlog_draining: false,
  };
}

export function operationalState(collector: CollectorDto | null | undefined): OperationalState {
  const operational = collectorOperational(collector);
  const raw = (operational?.overall || collector?.health || "UNKNOWN").toUpperCase();
  return OPERATIONAL_STATES.includes(raw as OperationalState) ? (raw as OperationalState) : "UNKNOWN";
}

/** Sources reported by the agent, ordered so failing channels surface first. */
export function collectorSources(collector: CollectorDto | null | undefined): SourceHealth[] {
  const sources = parseSourceHealth(collector?.health_metadata);
  const rank: Record<string, number> = { DEGRADED: 0, STARTING: 1, HEALTHY: 2, UNSUPPORTED: 3 };
  return [...sources].sort((a, b) => {
    const byState = (rank[a.state] ?? 9) - (rank[b.state] ?? 9);
    return byState !== 0 ? byState : (a.channel || a.name).localeCompare(b.channel || b.name);
  });
}

export interface BacklogView {
  depth: number;
  bytes: number;
  collectionRate: number;
  deliveryRate: number;
  netRate: number;
  draining: boolean;
  growing: boolean;
  oldestAgeSeconds: number | null;
  drainEtaSeconds: number | null;
}

/**
 * Backlog as a first-class operational fact: how deep, how old, and whether it
 * is growing or draining. Net rate is collection minus delivery, so a positive
 * value means the endpoint is falling behind.
 */
export function backlogView(collector: CollectorDto | null | undefined): BacklogView | null {
  const operational = collectorOperational(collector);
  if (!operational) return null;
  const netRate = operational.net_backlog_rate_eps;
  return {
    depth: operational.queue_depth,
    bytes: operational.queue_bytes,
    collectionRate: operational.collection_rate_eps,
    deliveryRate: operational.delivery_rate_eps,
    netRate,
    draining: operational.backlog_draining || netRate < 0,
    growing: operational.queue_depth > 0 && netRate > 0,
    oldestAgeSeconds: operational.queue_oldest_age_seconds ?? null,
    drainEtaSeconds: operational.queue_drain_eta_seconds ?? null,
  };
}

/**
 * Fleet counters for the dashboard. The server supplies them; when an older
 * server does not, they are recomputed from the collector list so the cards
 * still show real numbers rather than zeros.
 */
export function fleetSummary(
  fleet: FleetSummaryDto | undefined,
  collectors: CollectorDto[] | undefined,
): FleetSummaryDto {
  if (fleet) return fleet;
  const summary: FleetSummaryDto = {
    total: 0, online: 0, healthy: 0, degraded: 0, offline: 0, never_seen: 0, revoked: 0,
    backlog_events: 0, backlog_bytes: 0, collection_rate_eps: 0, delivery_rate_eps: 0,
  };
  for (const collector of collectors || []) {
    summary.total += 1;
    const operational = collectorOperational(collector);
    if (operational) {
      summary.backlog_events += operational.queue_depth;
      summary.backlog_bytes += operational.queue_bytes;
      summary.collection_rate_eps += operational.collection_rate_eps;
      summary.delivery_rate_eps += operational.delivery_rate_eps;
      if (operational.connectivity === "ONLINE") summary.online += 1;
    }
    switch (operationalState(collector)) {
      case "HEALTHY": summary.healthy += 1; break;
      case "DEGRADED": summary.degraded += 1; break;
      case "OFFLINE": summary.offline += 1; break;
      case "NEVER_SEEN": summary.never_seen += 1; break;
      case "REVOKED": summary.revoked += 1; break;
    }
  }
  return summary;
}

/** Endpoints that are not delivering telemetry: offline, degraded or revoked. */
export function endpointsNotDelivering(summary: FleetSummaryDto): number {
  return summary.offline + summary.degraded + summary.revoked + summary.never_seen;
}

/** Compact byte rendering; the exact value is shown on hover in the UI. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

/** Compact duration for lag, uptime and backlog age. */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return "—";
  const whole = Math.round(seconds);
  if (whole < 60) return `${whole}s`;
  if (whole < 3600) return `${Math.floor(whole / 60)}m ${whole % 60}s`;
  if (whole < 86400) return `${Math.floor(whole / 3600)}h ${Math.floor((whole % 3600) / 60)}m`;
  return `${Math.floor(whole / 86400)}d ${Math.floor((whole % 86400) / 3600)}h`;
}

/** Rounds an events-per-second figure for display without hiding small rates. */
export function formatRate(eps: number): string {
  if (!Number.isFinite(eps) || eps === 0) return "0";
  if (Math.abs(eps) >= 100) return Math.round(eps).toString();
  if (Math.abs(eps) >= 1) return eps.toFixed(1);
  return eps.toFixed(2);
}
