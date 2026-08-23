import { describe, expect, it } from "vitest";
import { safeReturnPath, selectTenant } from "./session";

describe("OIDC tenant session", () => {
  it("selects only a claimed tenant for a tenant-scoped user", () => {
    expect(selectTenant({ remembered: "tenant-b", configured: "tenant-a", memberships: ["tenant-a", "tenant-b"], platformScope: false })).toBe("tenant-b");
    expect(() => selectTenant({ remembered: "tenant-x", configured: "tenant-x", memberships: [], platformScope: false })).toThrow(/tenant membership/);
  });

  it("allows an explicit tenant context for platform-scoped operators", () => {
    expect(selectTenant({ remembered: "tenant-b", configured: "tenant-a", memberships: [], platformScope: true })).toBe("tenant-b");
  });

  it("accepts only same-origin callback return paths", () => {
    expect(safeReturnPath("/alerts?status=OPEN#queue", "https://soc.example.edu")).toBe("/alerts?status=OPEN#queue");
    expect(safeReturnPath("//evil.example/path", "https://soc.example.edu")).toBe("/soc");
    expect(safeReturnPath("https://evil.example/path", "https://soc.example.edu")).toBe("/soc");
  });
});
