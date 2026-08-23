import { runtimeConfig } from "../config/runtime";

export type AuthMode = "demo" | "oidc";

export interface SessionUser {
  id: string;
  displayName: string;
  role: string;
}

interface OIDCUserLike {
  access_token: string;
  profile: Record<string, unknown>;
}

export const authConfig = {
  mode: runtimeConfig.authMode as AuthMode,
  authority: runtimeConfig.oidcAuthority,
  clientId: runtimeConfig.oidcClientId,
  scope: runtimeConfig.oidcScope,
  redirectUri: runtimeConfig.oidcRedirectUri,
  postLogoutRedirectUri: runtimeConfig.oidcPostLogoutRedirectUri,
  configuredTenant: runtimeConfig.tenantId,
};

let accessToken = authConfig.mode === "demo" ? runtimeConfig.apiToken : "";
let tenantId = authConfig.configuredTenant;
let currentUser: SessionUser | null = authConfig.mode === "demo"
  ? { id: "user-soc-l2", displayName: "Development SOC L2", role: "SOC L2" }
  : null;

export function setOIDCSession(user: OIDCUserLike): SessionUser {
  const tokenClaims = decodeJWTClaims(user.access_token);
  const claims = { ...tokenClaims, ...user.profile };
  const tenants = stringArray(claims.kcsp_tenants);
  const singleTenant = typeof claims.tenant_id === "string" ? claims.tenant_id : "";
  if (singleTenant && !tenants.includes(singleTenant)) tenants.push(singleTenant);
  const rememberedTenant = sessionStorage.getItem("kcsp.tenant") || "";
  if (rememberedTenant && tenants.includes(rememberedTenant)) {
    tenantId = rememberedTenant;
  } else if (tenants.includes(authConfig.configuredTenant)) {
    tenantId = authConfig.configuredTenant;
  } else if (tenants.length > 0) {
		tenantId = tenants[0] ?? authConfig.configuredTenant;
  } else if (authConfig.configuredTenant) {
    tenantId = authConfig.configuredTenant;
  } else {
    throw new Error("The identity token does not contain a KCSP tenant membership.");
  }
  sessionStorage.setItem("kcsp.tenant", tenantId);
  const roles = collectRoles(claims);
  currentUser = {
    id: String(claims.sub || ""),
    displayName: String(claims.name || claims.preferred_username || claims.email || claims.sub || "KCSP user"),
    role: roleLabel(roles[0]),
  };
  accessToken = user.access_token;
  return currentUser;
}

export function clearOIDCSession(): void {
  if (authConfig.mode !== "demo") {
    accessToken = "";
    currentUser = null;
  }
}

export function getAccessToken(): string {
  return accessToken;
}

export function getTenantId(): string {
  return tenantId;
}

export function getSessionUser(): SessionUser | null {
  return currentUser;
}

function decodeJWTClaims(token: string): Record<string, unknown> {
  try {
    const payload = token.split(".")[1];
    if (!payload) return {};
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = decodeURIComponent(Array.from(atob(normalized), (character) =>
      `%${character.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""));
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function stringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  if (typeof value === "string") return value.split(/[ ,]+/).filter(Boolean);
  return [];
}

function collectRoles(claims: Record<string, unknown>): string[] {
  const roles = stringArray(claims.kcsp_roles);
  const realmAccess = claims.realm_access as { roles?: unknown } | undefined;
  roles.push(...stringArray(realmAccess?.roles));
  return Array.from(new Set(roles.map((role) => role.toLowerCase().replace(/^kcsp-/, "").replace(/[- .]/g, "_"))));
}

function roleLabel(role = ""): string {
  const labels: Record<string, string> = {
    platform_super_admin: "Platform Super Admin", tenant_admin: "Tenant Admin", soc_manager: "SOC Manager",
    soc_l1: "SOC L1", soc_l2: "SOC L2", soc_l3: "SOC L3", threat_hunter: "Threat Hunter",
    detection_engineer: "Detection Engineer", threat_intelligence_analyst: "Threat Intelligence Analyst", auditor: "Auditor",
  };
  return labels[role] || "Authenticated user";
}
