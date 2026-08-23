import { describe, expect, it } from "vitest";
import { resolveRuntimeConfig, type BuildConfigSource } from "./runtime";

describe("runtime configuration", () => {
  it("prefers public runtime values over build-time fallbacks", () => {
    const build: BuildConfigSource = {
      MODE: "production",
      VITE_API_BASE_URL: "/compiled/api",
      VITE_AUTH_MODE: "demo",
      VITE_OIDC_AUTHORITY: "https://compiled.example/",
      VITE_OIDC_CLIENT_ID: "compiled-client",
      VITE_TENANT_ID: "compiled-tenant",
      VITE_TIME_ZONE: "UTC",
    };

    const resolved = resolveRuntimeConfig(
      {
        apiBaseUrl: "/api/v1",
        authMode: "oidc",
        oidcAuthority: "https://identity.example.edu/realms/kcsp/",
        oidcClientId: "kcsp",
        oidcScope: "openid profile email",
        tenantId: "tenant-production",
        timeZone: "Asia/Almaty",
      },
      build,
      "https://soc.example.edu",
    );

    expect(resolved).toMatchObject({
      apiBaseUrl: "/api/v1",
      authMode: "oidc",
      oidcAuthority: "https://identity.example.edu/realms/kcsp",
      oidcClientId: "kcsp",
      oidcScope: "openid profile email",
      oidcRedirectUri: "https://soc.example.edu/auth/callback",
      oidcPostLogoutRedirectUri: "https://soc.example.edu",
      tenantId: "tenant-production",
      timeZone: "Asia/Almaty",
    });
    expect(Object.isFrozen(resolved)).toBe(true);
  });

  it("keeps the deterministic demo fallback in test mode", () => {
    const resolved = resolveRuntimeConfig(undefined, { MODE: "test" }, "http://localhost");
    expect(resolved.authMode).toBe("demo");
    expect(resolved.apiBaseUrl).toBe("/api/v1");
    expect(resolved.apiToken).toBe("kcsp-demo-l2");
    expect(resolved.oidcRedirectUri).toBe("http://localhost/auth/callback");
  });
});
