import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";
import { AlertTriangle, LoaderCircle, LogIn, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { UserManager, type User } from "oidc-client-ts";
import {
  authConfig,
  clearOIDCSession,
  getSessionUser,
  type SessionUser,
  setOIDCSession,
} from "./session";

interface AuthContextValue {
  mode: "demo" | "oidc";
  user: SessionUser | null;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);
const oidcConfigured = authConfig.mode === "oidc" && Boolean(authConfig.authority && authConfig.clientId);
const manager = oidcConfigured ? new UserManager({
  authority: authConfig.authority,
  client_id: authConfig.clientId,
  redirect_uri: authConfig.redirectUri,
  post_logout_redirect_uri: authConfig.postLogoutRedirectUri,
  response_type: "code",
  scope: authConfig.scope,
  automaticSilentRenew: true,
  monitorSession: true,
}) : null;

let initialization: Promise<User | null> | null = null;

async function initializeOIDC(): Promise<User | null> {
  if (!manager) return null;
  if (!initialization) {
    initialization = (async () => {
      const params = new URLSearchParams(window.location.search);
      if (params.has("code") && params.has("state")) {
        const user = await manager.signinRedirectCallback();
        const state = user.state as { returnUrl?: string } | undefined;
        window.history.replaceState({}, document.title, state?.returnUrl || "/soc");
        return user;
      }
      const user = await manager.getUser();
      if (user?.expired) {
        await manager.removeUser();
        return null;
      }
      return user;
    })();
  }
  return initialization;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(authConfig.mode === "oidc");
  const [user, setUser] = useState<SessionUser | null>(getSessionUser());
  const [error, setError] = useState("");

  useEffect(() => {
    if (authConfig.mode === "demo") return;
    if (!manager) {
      setError(t("auth.notConfigured"));
      setLoading(false);
      return;
    }
    let active = true;
    const acceptUser = (oidcUser: User) => {
      if (!active) return;
      try {
        setUser(setOIDCSession(oidcUser));
        setError("");
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : t("auth.failed"));
      }
    };
    const removeUser = () => {
      clearOIDCSession();
      if (active) setUser(null);
    };
    manager.events.addUserLoaded(acceptUser);
    manager.events.addUserUnloaded(removeUser);
    void initializeOIDC()
      .then((oidcUser) => { if (oidcUser) acceptUser(oidcUser); })
      .catch((cause: unknown) => { if (active) setError(cause instanceof Error ? cause.message : t("auth.failed")); })
      .finally(() => { if (active) setLoading(false); });
    return () => {
      active = false;
      manager.events.removeUserLoaded(acceptUser);
      manager.events.removeUserUnloaded(removeUser);
    };
  }, [t]);

  const value = useMemo<AuthContextValue>(() => ({
    mode: authConfig.mode,
    user,
    signIn: async () => {
      if (!manager) return;
      setError("");
      await manager.signinRedirect({ state: { returnUrl: window.location.pathname + window.location.search } });
    },
    signOut: async () => {
      if (authConfig.mode === "demo" || !manager) return;
      clearOIDCSession();
      await manager.signoutRedirect();
    },
  }), [user]);

  if (loading) return <AuthScreen icon={<LoaderCircle className="auth-spinner" />} title={t("auth.loading")} text={t("auth.loadingHint")} />;
  if (authConfig.mode === "oidc" && !user) {
    return (
      <AuthScreen
        icon={error ? <AlertTriangle /> : <ShieldCheck />}
        title={error ? t("auth.errorTitle") : t("auth.signInTitle")}
        text={error || t("auth.signInHint")}
        action={manager ? <button className="auth-button" type="button" onClick={() => void value.signIn()}><LogIn size={17} />{t("auth.signIn")}</button> : undefined}
      />
    );
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function AuthScreen({ icon, title, text, action }: { icon: ReactNode; title: string; text: string; action?: ReactNode }) {
  return (
    <main className="auth-gate">
      <section className="auth-panel">
        <div className="auth-brand"><span>{icon}</span><div><strong>KCSP</strong><small>IDENTITY GATEWAY</small></div></div>
        <div className="auth-signal"><span /><span /><span /></div>
        <p className="auth-kicker">KULAZHANOV CYBER SECURITY PLATFORM</p>
        <h1>{title}</h1>
        <p className="auth-copy">{text}</p>
        {action}
        <footer><ShieldCheck size={14} />OIDC · PKCE · TENANT RBAC</footer>
      </section>
    </main>
  );
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
