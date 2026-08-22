import type { ReactNode } from "react";
import { useEffect } from "react";
import {
  AlertTriangle,
  ChevronRight,
  CircleAlert,
  Inbox,
  LoaderCircle,
  RefreshCw,
  X,
  type LucideIcon,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { ApiError } from "../api/client";
import { formatNumber, titleCaseCode } from "../utils/format";

export function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
}: {
  eyebrow: string;
  title: string;
  subtitle: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function PanelHeader({
  title,
  meta,
  action,
}: {
  title: string;
  meta?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="panel-header">
      <div>
        <h2>{title}</h2>
        {meta && <div className="panel-meta">{meta}</div>}
      </div>
      {action}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
  tone = "default",
}: {
  label: string;
  value: number | string;
  detail?: ReactNode;
  icon: LucideIcon;
  tone?: "default" | "critical" | "warning" | "good";
}) {
  return (
    <article className={`metric-card metric-${tone}`}>
      <div className="metric-topline">
        <span>{label}</span>
        <span className="metric-icon"><Icon size={18} aria-hidden="true" /></span>
      </div>
      <strong>{typeof value === "number" ? formatNumber(value) : value}</strong>
      {detail && <div className="metric-detail">{detail}</div>}
    </article>
  );
}

export function LoadingState({ rows = 5, compact = false }: { rows?: number; compact?: boolean }) {
  const { t } = useTranslation();
  return (
    <div className={`loading-state ${compact ? "compact" : ""}`} role="status" aria-live="polite">
      <div className="loading-label"><LoaderCircle size={17} className="spin" /> {t("common.loading")}</div>
      {Array.from({ length: rows }).map((_, index) => (
        <div className="skeleton-row" key={index} style={{ opacity: 1 - index * 0.11 }}>
          <span /><span /><span /><span />
        </div>
      ))}
    </div>
  );
}

export function ErrorState({ error, onRetry, compact = false }: { error: unknown; onRetry?: () => void; compact?: boolean }) {
  const { t } = useTranslation();
  const apiError = error instanceof ApiError ? error : undefined;
  const detail = error instanceof Error ? error.message : t("errors.default");
  return (
    <div className={`error-state ${compact ? "compact" : ""}`} role="alert">
      <span className="state-icon error"><AlertTriangle size={23} /></span>
      <div>
        <strong>{t("errors.title")}</strong>
        <p>{detail || t("errors.default")}</p>
        {apiError?.problem?.trace_id && <code>{t("errors.trace")}: {apiError.problem.trace_id}</code>}
      </div>
      {onRetry && (
        <button className="button ghost" onClick={onRetry} type="button">
          <RefreshCw size={15} /> {t("common.retry")}
        </button>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  action,
}: {
  title: string;
  description?: string;
  icon?: LucideIcon;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="state-icon"><Icon size={26} /></span>
      <strong>{title}</strong>
      {description && <p>{description}</p>}
      {action}
    </div>
  );
}

function normalizedCode(value?: string): string {
  return (value || "unknown").trim().toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
}

export function SeverityBadge({ value }: { value?: string | number }) {
  const { t, i18n } = useTranslation();
  const numericMap: Record<number, string> = { 0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical", 5: "critical" };
  const code = typeof value === "number" ? numericMap[value] || "unknown" : normalizedCode(value);
  const key = `severity.${code}`;
  const label = i18n.exists(key) ? t(key) : titleCaseCode(String(value || "unknown"));
  return <span className={`badge severity-${code}`}><span className="badge-dot" />{label}</span>;
}

export function StatusBadge({ value }: { value?: string }) {
  const { t, i18n } = useTranslation();
  const code = normalizedCode(value);
  const key = `status.${code}`;
  const label = i18n.exists(key) ? t(key) : titleCaseCode(value);
  return <span className={`badge status-${code}`}><span className="badge-dot" />{label}</span>;
}

export function RiskScore({ value = 0, compact = false }: { value?: number; compact?: boolean }) {
  const normalized = Math.min(100, Math.max(0, Math.round(value)));
  const tone = normalized >= 80 ? "critical" : normalized >= 60 ? "high" : normalized >= 35 ? "medium" : "low";
  if (compact) return <span className={`risk-number risk-${tone}`}>{normalized}</span>;
  return (
    <div className="risk-score" aria-label={`Risk score ${normalized} out of 100`}>
      <div className="risk-ring" style={{ "--risk": normalized } as React.CSSProperties}>
        <strong>{normalized}</strong><span>/100</span>
      </div>
      <div className="risk-track"><span className={`risk-fill risk-${tone}`} style={{ width: `${normalized}%` }} /></div>
    </div>
  );
}

export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "accent" | "warning" }) {
  return <span className={`tag tag-${tone}`}>{children}</span>;
}

export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return <div className="detail-row"><dt>{label}</dt><dd>{children || "—"}</dd></div>;
}

export function JsonBlock({ value }: { value: unknown }) {
  const serialized = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return <pre className="json-block"><code>{serialized || "{}"}</code></pre>;
}

export function Drawer({
  open,
  onClose,
  title,
  eyebrow,
  children,
  footer,
  wide = false,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  eyebrow?: string;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const { t } = useTranslation();
  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    document.addEventListener("keydown", handler);
    document.body.classList.add("overlay-open");
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.classList.remove("overlay-open");
    };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="overlay" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside className={`drawer ${wide ? "drawer-wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <header className="drawer-header">
          <div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2></div>
          <button className="icon-button" type="button" onClick={onClose} aria-label={t("common.close")}><X size={20} /></button>
        </header>
        <div className="drawer-content">{children}</div>
        {footer && <footer className="drawer-footer">{footer}</footer>}
      </aside>
    </div>
  );
}

export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer: ReactNode;
}) {
  const { t } = useTranslation();
  useEffect(() => {
    if (!open) return;
    const handler = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="overlay modal-overlay" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <header className="drawer-header"><h2>{title}</h2><button className="icon-button" onClick={onClose} type="button" aria-label={t("common.close")}><X size={20} /></button></header>
        <div className="modal-content">{children}</div>
        <footer className="drawer-footer">{footer}</footer>
      </section>
    </div>
  );
}

export function InlineNotice({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "success" | "warning" }) {
  return <div className={`inline-notice notice-${tone}`}><CircleAlert size={17} />{children}</div>;
}

export function TableAction() {
  return <ChevronRight className="table-chevron" size={17} aria-hidden="true" />;
}
