import { describe, expect, it } from "vitest";
import type { CollectorDto } from "../api/types";
import {
  backlogView,
  collectorOperational,
  collectorSources,
  endpointsNotDelivering,
  fleetSummary,
  formatBytes,
  formatDuration,
  formatRate,
  operationalState,
} from "./operational";

// Modelled on the real pilot endpoint: heartbeat lands, so the collector is
// ONLINE, while 51k events sit in the local queue and the backlog is growing.
const kaztbu: CollectorDto = {
  collector_id: "agt_70e3bbd15031e64b333fa27e",
  name: "kaztbu",
  type: "lightweight-agent",
  state: "ACTIVE",
  health: "ONLINE",
  version: "0.5.2",
  last_seen_at: "2026-08-28T10:22:16.197308Z",
  operational: {
    connectivity: "ONLINE",
    telemetry: "DEGRADED",
    overall: "DEGRADED",
    reasons: ["BACKLOG_GROWING", "BACKLOG_HIGH"],
    queue_depth: 51598,
    queue_bytes: 106549242,
    source_total: 5,
    source_healthy: 5,
    source_degraded: 0,
    collection_rate_eps: 8,
    delivery_rate_eps: 4,
    net_backlog_rate_eps: 4,
    events_collected_total: 60000,
    events_delivered_total: 8402,
    send_failures_total: 0,
    backlog_draining: false,
  },
  health_metadata: {
    queue_depth: 51598,
    queue_bytes: 106549242,
    source_health: [
      { name: "windows-event:Security", channel: "Security", state: "HEALTHY", checkpoint: 44473, events_read: 900, error_count: 0 },
      { name: "windows-event:Microsoft-Windows-Sysmon/Operational", channel: "Microsoft-Windows-Sysmon/Operational", state: "DEGRADED", error_count: 3, last_error: "read failed", events_read: 0, checkpoint: 0 },
    ],
  },
};

const healthyHost: CollectorDto = {
  collector_id: "agt_healthy",
  name: "lab-01",
  type: "lightweight-agent",
  state: "ACTIVE",
  health: "ONLINE",
  operational: {
    connectivity: "ONLINE", telemetry: "HEALTHY", overall: "HEALTHY",
    queue_depth: 0, queue_bytes: 0, source_total: 3, source_healthy: 3, source_degraded: 0,
    collection_rate_eps: 10, delivery_rate_eps: 10, net_backlog_rate_eps: 0,
    events_collected_total: 100, events_delivered_total: 100, send_failures_total: 0,
    backlog_draining: false,
  },
};

const offlineHost: CollectorDto = {
  collector_id: "agt_offline", name: "old-pc", type: "lightweight-agent", state: "ACTIVE", health: "OFFLINE",
  operational: {
    connectivity: "OFFLINE", telemetry: "UNKNOWN", overall: "OFFLINE",
    queue_depth: 0, queue_bytes: 0, source_total: 0, source_healthy: 0, source_degraded: 0,
    collection_rate_eps: 0, delivery_rate_eps: 0, net_backlog_rate_eps: 0,
    events_collected_total: 0, events_delivered_total: 0, send_failures_total: 0,
    backlog_draining: false,
  },
};

describe("operationalState", () => {
  it("separates connectivity from telemetry: ONLINE is not HEALTHY", () => {
    expect(kaztbu.health).toBe("ONLINE");
    expect(collectorOperational(kaztbu)?.connectivity).toBe("ONLINE");
    expect(operationalState(kaztbu)).toBe("DEGRADED");
  });

  it("reports a genuinely healthy endpoint as healthy", () => {
    expect(operationalState(healthyHost)).toBe("HEALTHY");
  });

  it("reports a stale endpoint as offline", () => {
    expect(operationalState(offlineHost)).toBe("OFFLINE");
  });

  it("falls back to heartbeat metadata when the server sends no operational block", () => {
    const legacy: CollectorDto = { collector_id: "a", name: "a", type: "t", state: "ACTIVE", health: "ONLINE", health_metadata: { queue_depth: 7 } };
    const operational = collectorOperational(legacy);
    expect(operational?.queue_depth).toBe(7);
    expect(operationalState(legacy)).toBe("HEALTHY");
  });

  it("is UNKNOWN when nothing has been reported", () => {
    expect(operationalState({ collector_id: "a", name: "a", type: "t", state: "ACTIVE", health: "" })).toBe("UNKNOWN");
  });
});

describe("backlogView", () => {
  it("exposes the backlog as a first-class metric and flags growth", () => {
    const backlog = backlogView(kaztbu)!;
    expect(backlog.depth).toBe(51598);
    expect(backlog.bytes).toBe(106549242);
    expect(backlog.collectionRate).toBe(8);
    expect(backlog.deliveryRate).toBe(4);
    expect(backlog.netRate).toBe(4);
    expect(backlog.growing).toBe(true);
    expect(backlog.draining).toBe(false);
  });

  it("flags a draining backlog when delivery outpaces collection", () => {
    const draining: CollectorDto = {
      ...kaztbu,
      operational: { ...kaztbu.operational!, delivery_rate_eps: 400, net_backlog_rate_eps: -392, backlog_draining: true, queue_drain_eta_seconds: 131 },
    };
    const backlog = backlogView(draining)!;
    expect(backlog.draining).toBe(true);
    expect(backlog.growing).toBe(false);
    expect(backlog.drainEtaSeconds).toBe(131);
  });
});

describe("collectorSources", () => {
  it("lists every source with failing channels first", () => {
    const sources = collectorSources(kaztbu);
    expect(sources).toHaveLength(2);
    expect(sources[0]!.state).toBe("DEGRADED");
    expect(sources[0]!.channel).toBe("Microsoft-Windows-Sysmon/Operational");
    expect(sources[1]!.state).toBe("HEALTHY");
    expect(sources[1]!.checkpoint).toBe(44473);
  });
});

describe("fleetSummary", () => {
  it("counts the fleet from collector records when the server sends none", () => {
    const summary = fleetSummary(undefined, [kaztbu, healthyHost, offlineHost]);
    expect(summary.total).toBe(3);
    expect(summary.online).toBe(2);
    expect(summary.healthy).toBe(1);
    expect(summary.degraded).toBe(1);
    expect(summary.offline).toBe(1);
    expect(summary.backlog_events).toBe(51598);
    expect(summary.backlog_bytes).toBe(106549242);
    expect(summary.collection_rate_eps).toBe(18);
    expect(summary.delivery_rate_eps).toBe(14);
  });

  it("prefers the server-provided summary", () => {
    const provided = {
      total: 9, online: 9, healthy: 9, degraded: 0, offline: 0, never_seen: 0, revoked: 0,
      backlog_events: 0, backlog_bytes: 0, collection_rate_eps: 1, delivery_rate_eps: 1,
    };
    expect(fleetSummary(provided, [kaztbu])).toBe(provided);
  });

  it("counts degraded endpoints as not delivering, not only offline ones", () => {
    const summary = fleetSummary(undefined, [kaztbu, healthyHost, offlineHost]);
    // The pre-fix dashboard reported 0 here while a 51k backlog was stuck.
    expect(endpointsNotDelivering(summary)).toBe(2);
  });
});

describe("formatting", () => {
  it("renders bytes compactly", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(106549242)).toBe("102 MB");
  });

  it("renders durations compactly", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(150)).toBe("2m 30s");
    expect(formatDuration(7500)).toBe("2h 5m");
    expect(formatDuration(180000)).toBe("2d 2h");
  });

  it("keeps small event rates visible instead of rounding them to zero", () => {
    expect(formatRate(0)).toBe("0");
    expect(formatRate(0.42)).toBe("0.42");
    expect(formatRate(3.33)).toBe("3.3");
    expect(formatRate(412.7)).toBe("413");
  });
});
