import { runtimeConfig } from "../config/runtime";
import { authSessionStorage } from "./storage";

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
let tenantId = normalizeTenantId(authConfig.configuredTenant) || authConfig.configuredTenant;
let allowedTenantIds = new Set(authConfig.mode === "demo" && tenantId ? [tenantId] : []);
let platformScoped = false;
let currentUser: SessionUser | null = authConfig.mode === "demo"
  ? { id: "user-soc-l2", displayName: "Development SOC L2", role: "SOC L2" }
  : null;

export function setOIDCSession(user: OIDCUserLike): SessionUser {
  const tokenClaims = decodeJWTClaims(user.access_token);
  const claims = { ...tokenClaims, ...user.profile };
  const roles = collectRoles(claims);
  platformScoped = roles.some((role) => ["platform_super_admin", "platform_administrator", "mssp_manager"].includes(role));
  const tenants = stringArray(claims.kcsp_tenants).map(normalizeTenantId).filter((value): value is string => Boolean(value));
  const singleTenant = typeof claims.tenant_id === "string" ? claims.tenant_id : "";
  const normalizedSingleTenant = normalizeTenantId(singleTenant);
  if (normalizedSingleTenant && !tenants.includes(normalizedSingleTenant)) tenants.push(normalizedSingleTenant);
  allowedTenantIds = new Set(tenants);
  tenantId = selectTenant({
    remembered: authSessionStorage.getItem("kcsp.tenant"),
    configured: authConfig.configuredTenant,
    memberships: tenants,
    platformScope: platformScoped,
  });
  authSessionStorage.setItem("kcsp.tenant", tenantId);
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
    allowedTenantIds = new Set();
    platformScoped = false;
    authSessionStorage.removeItem("kcsp.tenant");
  }
}

export function getAccessToken(): string {
  return accessToken;
}

export function getTenantId(): string {
  return tenantId;
}

export function setTenantId(value: string): void {
  const normalized = normalizeTenantId(value);
  if (!normalized) throw new Error("Invalid KCSP tenant identifier.");
  if (!platformScoped && !allowedTenantIds.has(normalized)) throw new Error("The authenticated user is not a member of this KCSP tenant.");
  tenantId = normalized;
  authSessionStorage.setItem("kcsp.tenant", tenantId);
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

export function selectTenant(input: {
  remembered?: string | null;
  configured?: string | null;
  memberships: readonly string[];
  platformScope: boolean;
}): string {
  const memberships = new Set(input.memberships.map(normalizeTenantId).filter((value): value is string => Boolean(value)));
  const remembered = normalizeTenantId(input.remembered);
  const configured = normalizeTenantId(input.configured);
  if (remembered && (input.platformScope || memberships.has(remembered))) return remembered;
  if (configured && (input.platformScope || memberships.has(configured))) return configured;
  const firstMembership = memberships.values().next().value as string | undefined;
  if (firstMembership) return firstMembership;
  throw new Error("The identity token does not contain a KCSP tenant membership.");
}

export function safeReturnPath(value: unknown, origin: string): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) return "/soc";
  try {
    const resolved = new URL(value, origin);
    if (resolved.origin !== origin) return "/soc";
    return `${resolved.pathname}${resolved.search}${resolved.hash}`;
  } catch {
    return "/soc";
  }
}

function normalizeTenantId(value?: string | null): string | null {
  const normalized = value?.trim().toLowerCase() || "";
  return /^[a-z0-9][a-z0-9-]{1,62}$/.test(normalized) ? normalized : null;
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
