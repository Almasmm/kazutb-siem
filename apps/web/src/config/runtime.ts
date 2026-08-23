export type RuntimeAuthMode = "demo" | "oidc";

export interface RuntimeConfigSource {
  apiBaseUrl?: string;
  apiToken?: string;
  authMode?: RuntimeAuthMode;
  oidcAuthority?: string;
  oidcClientId?: string;
  oidcScope?: string;
  oidcRedirectUri?: string;
  oidcPostLogoutRedirectUri?: string;
  tenantId?: string;
  timeZone?: string;
}

export interface BuildConfigSource {
  MODE?: string;
  VITE_API_BASE_URL?: string;
  VITE_API_TOKEN?: string;
  VITE_AUTH_MODE?: string;
  VITE_OIDC_AUTHORITY?: string;
  VITE_OIDC_CLIENT_ID?: string;
  VITE_OIDC_SCOPE?: string;
  VITE_OIDC_REDIRECT_URI?: string;
  VITE_OIDC_POST_LOGOUT_REDIRECT_URI?: string;
  VITE_TENANT_ID?: string;
  VITE_TIME_ZONE?: string;
}

export interface ResolvedRuntimeConfig {
  apiBaseUrl: string;
  apiToken: string;
  authMode: RuntimeAuthMode;
  oidcAuthority: string;
  oidcClientId: string;
  oidcScope: string;
  oidcRedirectUri: string;
  oidcPostLogoutRedirectUri: string;
  tenantId: string;
  timeZone: string;
}

function firstNonEmpty(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim() !== "") return value.trim();
  }
  return undefined;
}

function authMode(...values: unknown[]): RuntimeAuthMode {
  for (const value of values) {
    if (value === "demo" || value === "oidc") return value;
  }
  return "oidc";
}

export function resolveRuntimeConfig(
  runtime: RuntimeConfigSource | undefined,
  build: BuildConfigSource,
  browserOrigin: string,
): Readonly<ResolvedRuntimeConfig> {
  const inferredMode: RuntimeAuthMode = build.MODE === "test" ? "demo" : "oidc";
  return Object.freeze({
    apiBaseUrl: firstNonEmpty(runtime?.apiBaseUrl, build.VITE_API_BASE_URL) || "/api/v1",
    apiToken: firstNonEmpty(runtime?.apiToken, build.VITE_API_TOKEN) || "kcsp-demo-l2",
    authMode: authMode(runtime?.authMode, build.VITE_AUTH_MODE, inferredMode),
    oidcAuthority: (firstNonEmpty(runtime?.oidcAuthority, build.VITE_OIDC_AUTHORITY) || "").replace(/\/$/, ""),
    oidcClientId: firstNonEmpty(runtime?.oidcClientId, build.VITE_OIDC_CLIENT_ID) || "",
    oidcScope: firstNonEmpty(runtime?.oidcScope, build.VITE_OIDC_SCOPE) || "openid profile email offline_access",
    oidcRedirectUri:
      firstNonEmpty(runtime?.oidcRedirectUri, build.VITE_OIDC_REDIRECT_URI) || `${browserOrigin}/auth/callback`,
    oidcPostLogoutRedirectUri:
      firstNonEmpty(runtime?.oidcPostLogoutRedirectUri, build.VITE_OIDC_POST_LOGOUT_REDIRECT_URI) || browserOrigin,
    tenantId: firstNonEmpty(runtime?.tenantId, build.VITE_TENANT_ID) || "university-kulazhanov",
    timeZone: firstNonEmpty(runtime?.timeZone, build.VITE_TIME_ZONE) || "Asia/Almaty",
  });
}

const browserOrigin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
const runtimeSource = typeof window === "undefined" ? undefined : window.__KCSP_CONFIG__;

export const runtimeConfig = resolveRuntimeConfig(runtimeSource, import.meta.env, browserOrigin);
