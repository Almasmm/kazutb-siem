import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowRight,
  BellRing,
  DatabaseZap,
  RadioTower,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Siren,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { OverviewBreakdown, OverviewDto, OverviewMetricPoint } from "../api/types";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  MetricCard,
  PageHeader,
  PanelHeader,
  SeverityBadge,
} from "../components/ui";
import { formatDateTime, formatNumber } from "../utils/format";

function metric(data: OverviewDto | undefined, ...keys: string[]): number {
  for (const key of keys) {
    const direct = data?.[key];
    if (typeof direct === "number") return direct;
    const nested = data?.counts?.[key];
    if (typeof nested === "number") return nested;
  }
  return 0;
}

function Sparkline({ points }: { points: OverviewMetricPoint[] }) {
  if (points.length < 2) return null;
  const width = 640;
  const height = 190;
  const values = points.map((point) => point.count);
  const max = Math.max(...values, 1);
  const coordinates = points.map((point, index) => {
    const x = (index / Math.max(points.length - 1, 1)) * width;
    const y = height - (point.count / max) * (height - 25) - 10;
    return `${x},${y}`;
  });
  const area = `0,${height} ${coordinates.join(" ")} ${width},${height}`;
  return (
    <div className="sparkline-wrap">
      <svg className="sparkline" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Alert activity chart">
        <defs>
          <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#44d3b6" stopOpacity="0.28" />
            <stop offset="1" stopColor="#44d3b6" stopOpacity="0" />
          </linearGradient>
        </defs>
        <line x1="0" y1="45" x2={width} y2="45" className="chart-grid" />
        <line x1="0" y1="100" x2={width} y2="100" className="chart-grid" />
        <line x1="0" y1="155" x2={width} y2="155" className="chart-grid" />
        <polygon points={area} fill="url(#sparkFill)" />
        <polyline points={coordinates.join(" ")} fill="none" stroke="#53dfc1" strokeWidth="3" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="chart-axis"><span>{formatDateTime(points[0]?.timestamp || points[0]?.time)}</span><span>{formatDateTime(points.at(-1)?.timestamp || points.at(-1)?.time)}</span></div>
    </div>
  );
}

function SeverityDistribution({ items, fallback }: { items?: OverviewBreakdown[]; fallback: OverviewBreakdown[] }) {
  const { t } = useTranslation();
  const values = items?.length ? items : fallback;
  const total = Math.max(values.reduce((sum, item) => sum + item.count, 0), 1);
  return (
    <div className="severity-distribution">
      <div className="severity-stack" aria-hidden="true">
        {values.filter((item) => item.count > 0).map((item) => {
          const code = (item.severity || item.name || "unknown").toLowerCase();
          return <span key={code} className={`severity-segment segment-${code}`} style={{ width: `${(item.count / total) * 100}%` }} />;
        })}
      </div>
      <div className="severity-list">
        {values.map((item) => {
          const severity = item.severity || item.name || "unknown";
          return (
            <div key={severity}>
              <SeverityBadge value={severity} />
              <strong>{formatNumber(item.count)}</strong>
              <span>{Math.round((item.count / total) * 100)}%</span>
            </div>
          );
        })}
      </div>
      {!values.some((item) => item.count > 0) && <p className="muted centered">{t("common.noData")}</p>}
    </div>
  );
}

export default function SocPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const overview = useQuery({
    queryKey: ["overview"],
    queryFn: ({ signal }) => api.overview(signal),
    refetchInterval: 30_000,
  });

  const data = overview.data;
  const openAlerts = metric(data, "alerts_open", "open_alerts");
  const criticalAlerts = metric(data, "critical_alerts", "alerts_critical");
  const highAlerts = metric(data, "high_alerts", "alerts_high");
  const incidents = metric(data, "incidents_open", "open_incidents");
  const ingestEps = metric(data, "ingest_eps", "eps");
  const offlineSources = metric(data, "offline_sources", "sources_offline");
  const parserErrors = metric(data, "parser_errors", "parser_errors_total");
  const trend = data?.alert_trend?.length ? data.alert_trend : data?.event_trend || [];
  const severityFallback: OverviewBreakdown[] = [
    { severity: "CRITICAL", count: criticalAlerts },
    { severity: "HIGH", count: highAlerts },
    { severity: "MEDIUM", count: metric(data, "medium_alerts", "alerts_medium") },
    { severity: "LOW", count: metric(data, "low_alerts", "alerts_low") },
  ];

  return (
    <div className="page">
      <PageHeader
        eyebrow={t("soc.eyebrow")}
        title={t("soc.title")}
        subtitle={t("soc.subtitle")}
        actions={
          <button className="button ghost" type="button" onClick={() => void overview.refetch()} disabled={overview.isFetching}>
            <RefreshCw size={16} className={overview.isFetching ? "spin" : ""} />{t("common.refresh")}
          </button>
        }
      />

      {overview.isPending ? <LoadingState rows={7} /> : overview.isError ? (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      ) : (
        <>
          <div className="snapshot-line"><span className="pulse-dot" />{t("soc.generatedAt", { time: formatDateTime(data?.generated_at) })}</div>
          <section className="metrics-grid">
            <MetricCard label={t("soc.openAlerts")} value={openAlerts} icon={ShieldAlert} tone={openAlerts ? "warning" : "good"} detail={`${formatNumber(metric(data, "alerts_total"))} ${t("common.total").toLowerCase()}`} />
            <MetricCard label={t("soc.criticalAlerts")} value={criticalAlerts} icon={Siren} tone={criticalAlerts ? "critical" : "good"} detail={`${formatNumber(highAlerts)} High`} />
            <MetricCard label={t("soc.openIncidents")} value={incidents} icon={BellRing} tone={incidents ? "warning" : "good"} detail={`${formatNumber(metric(data, "incidents_total"))} ${t("common.total").toLowerCase()}`} />
            <MetricCard label={t("soc.ingestRate")} value={ingestEps} icon={DatabaseZap} tone="default" detail={t("soc.eventsPerSecond")} />
          </section>

          <section className="dashboard-grid">
            <article className="panel chart-panel">
              <PanelHeader title={t("soc.alertActivity")} meta={`${formatNumber(metric(data, "findings_total"))} ${t("soc.findingsDetected").toLowerCase()}`} />
              {trend.length > 1 ? <Sparkline points={trend} /> : <EmptyState title={t("soc.noTrend")} icon={Activity} />}
            </article>
            <article className="panel severity-panel">
              <PanelHeader title={t("soc.severityDistribution")} meta={`${formatNumber(openAlerts)} ${t("soc.openAlerts").toLowerCase()}`} />
              <SeverityDistribution items={data?.alerts_by_severity} fallback={severityFallback} />
            </article>
          </section>

          <section className="dashboard-grid lower-grid">
            <article className="panel health-panel">
              <PanelHeader title={t("soc.operationalHealth")} />
              <div className="health-list">
                <div><span className={`health-icon ${offlineSources ? "warning" : "good"}`}><RadioTower size={18} /></span><div><strong>{t("soc.offlineSources")}</strong><small>{offlineSources ? t("soc.attention") : t("soc.healthy")}</small></div><b>{formatNumber(offlineSources)}</b></div>
                <div><span className={`health-icon ${parserErrors ? "warning" : "good"}`}><DatabaseZap size={18} /></span><div><strong>{t("soc.parserErrors")}</strong><small>{parserErrors ? t("soc.attention") : t("soc.healthy")}</small></div><b>{formatNumber(parserErrors)}</b></div>
                <div><span className="health-icon good"><ShieldCheck size={18} /></span><div><strong>{t("soc.activeRules")}</strong><small>{t("soc.healthy")}</small></div><b>{formatNumber(metric(data, "rules_enabled", "active_rules"))}</b></div>
              </div>
            </article>

            <article className="panel recent-panel">
              <PanelHeader title={t("soc.topRules")} action={<button className="text-button" type="button" onClick={() => navigate("/rules")}>{t("nav.rules")} <ArrowRight size={15} /></button>} />
              {data?.top_rules?.length ? (
                <div className="compact-table-wrap">
                  <table className="data-table compact-table">
                    <tbody>
                      {data.top_rules.slice(0, 5).map((rule, index) => (
                        <tr key={`${rule.title || rule.name || rule.label}-${index}`}>
                          <td><ShieldCheck size={17} className="accent-icon" /></td>
                          <td><strong>{rule.title || rule.name || rule.label || t("common.unknown")}</strong><small>{t("soc.openAlerts")}</small></td>
                          <td><strong>{formatNumber(rule.count)}</strong></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : <EmptyState title={t("soc.noRulesActive")} icon={ShieldCheck} />}
            </article>
          </section>
        </>
      )}
    </div>
  );
}
