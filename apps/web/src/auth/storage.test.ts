import { describe, expect, it } from "vitest";
import { createSafeSessionStorage } from "./storage";

describe("OIDC session storage", () => {
  it("falls back to a complete in-memory Storage when browser storage is denied", () => {
    const storage = createSafeSessionStorage(() => { throw new Error("denied"); });
    storage.setItem("oidc.state", "pending");
    storage.setItem("kcsp.tenant", "tenant-a");
    expect(storage.length).toBe(2);
    expect(storage.getItem("oidc.state")).toBe("pending");
    expect([storage.key(0), storage.key(1)]).toContain("kcsp.tenant");
    storage.removeItem("oidc.state");
    expect(storage.getItem("oidc.state")).toBeNull();
    storage.clear();
    expect(storage.length).toBe(0);
  });
});
