import { useState } from "react";
import {
  Activity,
  Archive,
  BarChart3,
  BellRing,
  Briefcase,
  BrainCircuit,
  ChevronDown,
  ClipboardList,
  Crosshair,
  Globe2,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  RadioTower,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UsersRound,
  Network,
  Braces,
  Workflow,
  X,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { apiConfig } from "../api/client";
import { TENANT_TIME_ZONE } from "../utils/format";
import { useAuth } from "../auth/AuthProvider";

const navGroups = [
  {
    label: "nav.operations",
    items: [
      { to: "/soc", label: "nav.soc", icon: LayoutDashboard },
      { to: "/alerts", label: "nav.alerts", icon: ShieldAlert },
      { to: "/incidents", label: "nav.incidents", icon: BellRing },
      { to: "/cases", label: "nav.cases", icon: Briefcase },
      { to: "/soar", label: "nav.soar", icon: Workflow },
    ],
  },
  {
    label: "nav.intelligence",
    items: [
      { to: "/hunt", label: "nav.hunt", icon: Search },
      { to: "/assets", label: "nav.assets", icon: Network },
      { to: "/threat-intel", label: "nav.threatIntel", icon: Crosshair },
      { to: "/ueba", label: "nav.ueba", icon: UsersRound },
      { to: "/ai-soc", label: "nav.aiSoc", icon: BrainCircuit },
      { to: "/rules", label: "nav.rules", icon: Radar },
      { to: "/mitre", label: "nav.mitre", icon: Crosshair },
      { to: "/parsers", label: "nav.parsers", icon: Braces },
    ],
  },
  {
    label: "nav.governance",
    items: [
      { to: "/evidence", label: "nav.evidence", icon: Archive },
      { to: "/reports", label: "nav.reports", icon: BarChart3 },
      { to: "/collectors", label: "nav.collectors", icon: RadioTower },
      { to: "/system", label: "nav.system", icon: Settings2 },
      { to: "/audit", label: "nav.audit", icon: ClipboardList },
    ],
  },
];

const pageKeys: Record<string, string> = {
  "/soc": "nav.soc",
  "/alerts": "nav.alerts",
  "/hunt": "nav.hunt",
  "/incidents": "nav.incidents",
  "/rules": "nav.rules",
  "/audit": "nav.audit",
  "/collectors": "nav.collectors",
  "/threat-intel": "nav.threatIntel",
  "/ueba": "nav.ueba",
  "/evidence": "nav.evidence",
  "/soar": "nav.soar",
  "/ai-soc": "nav.aiSoc",
  "/system": "nav.system",
  "/cases": "nav.cases",
  "/assets": "nav.assets",
  "/parsers": "nav.parsers",
  "/mitre": "nav.mitre",
  "/reports": "nav.reports",
};

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [languageOpen, setLanguageOpen] = useState(false);
  const { t, i18n } = useTranslation();
  const location = useLocation();
	const { mode, user, signOut } = useAuth();
  const route = Object.keys(pageKeys).find((key) => location.pathname.startsWith(key)) || "/soc";
  const currentPageKey = pageKeys[route] || "nav.soc";
  const language = i18n.resolvedLanguage?.slice(0, 2).toUpperCase() || "RU";

  const changeLanguage = (next: "ru" | "kk" | "en") => {
    void i18n.changeLanguage(next);
    setLanguageOpen(false);
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <span className="brand-mark"><Shield size={23} fill="currentColor" /></span>
          <span><strong>{t("app.name")}</strong><small>{t("app.tagline")}</small></span>
          <button className="icon-button sidebar-close" onClick={() => setMobileOpen(false)} type="button"><X size={19} /></button>
        </div>

        <div className="tenant-card">
          <span className="tenant-icon"><ShieldCheck size={18} /></span>
          <span><small>{t("app.environment")}</small><strong>{t("app.tenant")}</strong></span>
        </div>

        <nav className="primary-nav" aria-label="Primary navigation">
          {navGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <span className="nav-label">{t(group.label)}</span>
              {group.items.map(({ to, label, icon: Icon }) => (
                <NavLink key={to} to={to} onClick={() => setMobileOpen(false)} className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}>
                  <Icon size={18} /><span>{t(label)}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="secure-indicator"><span /><div><strong>{t("app.protected")}</strong><small>{apiConfig.tenantId}</small></div></div>
        </div>
      </aside>

      {mobileOpen && <button className="sidebar-backdrop" type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation" />}

      <div className="workspace">
        <header className="topbar">
          <div className="topbar-title">
            <button className="icon-button menu-button" type="button" onClick={() => setMobileOpen(true)}><Menu size={20} /></button>
            <Activity size={17} className="topbar-route-icon" />
            <strong>{t(currentPageKey)}</strong>
          </div>
          <div className="topbar-actions">
            <span className="timezone-chip">UTC+5 · {TENANT_TIME_ZONE}</span>
            <span className="connection-chip"><span />{t("common.live")}</span>
            <div className="language-picker">
              <button className="language-button" type="button" onClick={() => setLanguageOpen((value) => !value)} aria-expanded={languageOpen}>
                <Globe2 size={16} /> {language} <ChevronDown size={14} />
              </button>
              {languageOpen && (
                <div className="language-menu">
                  <button type="button" onClick={() => changeLanguage("ru")}>Русский <span>RU</span></button>
                  <button type="button" onClick={() => changeLanguage("kk")}>Қазақша <span>KK</span></button>
                  <button type="button" onClick={() => changeLanguage("en")}>English <span>EN</span></button>
                </div>
              )}
            </div>
            {mode === "oidc" && <button className="icon-button" type="button" onClick={() => void signOut()} title={t("auth.signOut")}><LogOut size={17} /></button>}
            <div className="analyst-avatar" title={`${user?.displayName || "KCSP"} · ${user?.role || ""}`}>{initials(user?.displayName)}</div>
          </div>
        </header>
        <main className="main-content"><Outlet /></main>
      </div>
    </div>
  );
}

function initials(name = "KCSP"): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const first = parts[0] || "KC";
  const last = parts.at(-1) || first;
  return (parts.length > 1 ? first.slice(0, 1) + last.slice(0, 1) : first.slice(0, 2)).toUpperCase();
}
