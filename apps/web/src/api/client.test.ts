import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("KCSP API client", () => {
  it("sends the demo identity and tenant context", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({ items: [{
      alert_id: "alt-1",
      title: "Suspicious PowerShell",
      rule: { id: "rule-1", title: "PowerShell rule", version: "1" },
      entity: { type: "device", id: "asset-1", name: "dc-01" },
      mitre: ["T1059.001"],
      first_seen: "2026-08-17T10:00:00Z",
    }], total: 1 }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const page = await api.alerts({ limit: 25, status: "NEW" });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toContain("/api/v1/alerts?limit=25&status=NEW");
    const headers = new Headers((init as RequestInit).headers);
    expect(headers.get("Authorization")).toBe("Bearer kcsp-demo-l2");
    expect(headers.get("X-KCSP-Tenant-ID")).toBe("university-kulazhanov");
    expect(page.items[0]).toMatchObject({
      id: "alt-1",
      rule_id: "rule-1",
      rule_title: "PowerShell rule",
      asset_name: "dc-01",
      mitre_techniques: ["T1059.001"],
      first_seen_at: "2026-08-17T10:00:00Z",
    });
  });

  it("preserves problem details for actionable errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      title: "Forbidden",
      detail: "scope soc.alerts.triage is required",
      trace_id: "trace-123",
    }), { status: 403, headers: { "Content-Type": "application/problem+json" } })));

    await expect(api.updateAlert("alert-1", { status: "TRIAGE" })).rejects.toMatchObject({
      status: 403,
      message: "scope soc.alerts.triage is required",
      problem: { trace_id: "trace-123" },
    });
  });
});
