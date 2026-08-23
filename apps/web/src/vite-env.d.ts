/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_API_TOKEN?: string;
  readonly VITE_AUTH_MODE?: string;
  readonly VITE_OIDC_AUTHORITY?: string;
  readonly VITE_OIDC_CLIENT_ID?: string;
  readonly VITE_OIDC_SCOPE?: string;
  readonly VITE_OIDC_REDIRECT_URI?: string;
  readonly VITE_OIDC_POST_LOGOUT_REDIRECT_URI?: string;
  readonly VITE_TENANT_ID?: string;
  readonly VITE_TIME_ZONE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

interface Window {
  __KCSP_CONFIG__?: {
    apiBaseUrl?: string;
    apiToken?: string;
    authMode?: "demo" | "oidc";
    oidcAuthority?: string;
    oidcClientId?: string;
    oidcScope?: string;
    oidcRedirectUri?: string;
    oidcPostLogoutRedirectUri?: string;
    tenantId?: string;
    timeZone?: string;
  };
}
