import { describe, expect, it } from "vitest";
import { parseSourceHealth, sourceLagSeconds, summarizeSourceState } from "./sourceHealth";

const heartbeat = {
  queue_depth: 12,
  source_state: "DEGRADED",
  source_health: [
    {
      name: "windows-event:Security",
      channel: "Security",
      state: "HEALTHY",
      last_success_at: "2026-08-27T10:15:00Z",
      error_count: 0,
      consecutive_errors: 0,
      events_read: 340,
      checkpoint: 44473,
      encoding: "utf-16le",
    },
    {
      name: "windows-event:Microsoft-Windows-Sysmon/Operational",
      channel: "Microsoft-Windows-Sysmon/Operational",
      state: "DEGRADED",
      last_error_at: "2026-08-27T10:16:00Z",
      last_error: "decode Windows Event Log channel: invalid UTF-8",
      error_count: 9,
      consecutive_errors: 9,
      events_read: 0,
      checkpoint: 0,
      backoff_seconds: 60,
    },
  ],
};

describe("parseSourceHealth", () => {
  it("reads per-source health from collector metadata", () => {
    const sources = parseSourceHealth(heartbeat);
    expect(sources).toHaveLength(2);
    expect(sources[0]).toMatchObject({ name: "windows-event:Security", state: "HEALTHY", checkpoint: 44473, events_read: 340 });
    expect(sources[1]).toMatchObject({ state: "DEGRADED", error_count: 9, backoff_seconds: 60 });
    expect(sources[1]!.last_error).toContain("invalid UTF-8");
  });

  it("returns nothing for metadata without source health", () => {
    expect(parseSourceHealth(null)).toEqual([]);
    expect(parseSourceHealth(undefined)).toEqual([]);
    expect(parseSourceHealth({ queue_depth: 1 })).toEqual([]);
    expect(parseSourceHealth({ source_health: "not-an-array" })).toEqual([]);
  });

  it("drops malformed entries and defaults unknown states", () => {
    const sources = parseSourceHealth({
      source_health: [null, 42, { channel: "Security" }, { name: "ok", state: "WEIRD" }],
    });
    expect(sources).toHaveLength(1);
    expect(sources[0]).toMatchObject({ name: "ok", state: "STARTING", error_count: 0, checkpoint: 0 });
  });
});

describe("summarizeSourceState", () => {
  it("degrades the collector when any source is failing", () => {
    expect(summarizeSourceState(parseSourceHealth(heartbeat))).toBe("DEGRADED");
  });

  it("is healthy only when every supported source reads", () => {
    expect(summarizeSourceState(parseSourceHealth({
      source_health: [{ name: "a", state: "HEALTHY" }, { name: "b", state: "HEALTHY" }],
    }))).toBe("HEALTHY");
    expect(summarizeSourceState(parseSourceHealth({
      source_health: [{ name: "a", state: "HEALTHY" }, { name: "b", state: "STARTING" }],
    }))).toBe("STARTING");
  });

  it("returns null when the agent reports no sources", () => {
    expect(summarizeSourceState([])).toBeNull();
  });
});

describe("sourceLagSeconds", () => {
  it("measures how long ago a source last read", () => {
    const security = parseSourceHealth(heartbeat)[0]!;
    expect(sourceLagSeconds(security, new Date("2026-08-27T10:16:30Z"))).toBe(90);
  });

  it("has no lag for a source that never read successfully", () => {
    const sysmon = parseSourceHealth(heartbeat)[1]!;
    expect(sourceLagSeconds(sysmon)).toBeNull();
  });
});
