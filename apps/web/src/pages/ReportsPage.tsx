import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, BarChart3, Clock3, Download, FileJson, FileText, Plus, ShieldCheck, Table2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { ReportRunDto } from "../api/types";
import { Drawer, EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, StatusBadge } from "../components/ui";
import { formatFullDateTime } from "../utils/format";
import "./reports.css";

const reportTypes = ["EXECUTIVE_SECURITY", "SOC_OPERATIONS", "INCIDENT", "CASE_CLOSURE"] as const;
type ReportType = (typeof reportTypes)[number];
type SnapshotMetric = { key?: string; label?: string; value?: number; unit?: string };

export default function ReportsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [type, setType] = useState<ReportType>("EXECUTIVE_SECURITY");
  const [filter, setFilter] = useState("");
  const [composerOpen, setComposerOpen] = useState(false);
  const [selected, setSelected] = useState<ReportRunDto | null>(null);
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [incidentId, setIncidentId] = useState("");
  const [caseId, setCaseId] = useState("");
  const [downloadError, setDownloadError] = useState<unknown>(null);

  const reports = useQuery({
    queryKey: ["reports", filter],
    queryFn: ({ signal }) => api.reports(filter ? { type: filter } : undefined, signal),
    refetchInterval: 30_000,
  });
  const items = reports.data?.items || [];
  const latest = items[0];
  const latestMetrics = metricsFrom(latest?.snapshot);
  const create = useMutation({
    mutationFn: () => api.generateReport({
      report_type: type,
      parameters: {
        ...(start ? { start: new Date(start).toISOString() } : {}),
        ...(end ? { end: new Date(end).toISOString() } : {}),
        ...(type === "INCIDENT" ? { incident_id: incidentId.trim() } : {}),
        ...(type === "CASE_CLOSURE" ? { case_id: caseId.trim() } : {}),
      },
    }),
    onSuccess: (run) => {
      setSelected(run);
      setComposerOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
  });

  const operationalCards = useMemo(() => latestMetrics.slice(0, 4), [latestMetrics]);

  const download = async (run: ReportRunDto, format: "json" | "csv" | "html") => {
    setDownloadError(null);
    try {
      const file = await api.downloadReport(run.report_id, format);
      const href = URL.createObjectURL(file.blob);
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = file.filename;
      anchor.click();
      URL.revokeObjectURL(href);
    } catch (error) {
      setDownloadError(error);
    }
  };

  return <div className="page reports-page">
    <PageHeader eyebrow={t("reportsPage.eyebrow")} title={t("reportsPage.title")} subtitle={t("reportsPage.subtitle")} actions={<button type="button" className="report-button primary" onClick={() => setComposerOpen((value) => !value)}><Plus size={17} />{t("reportsPage.generate")}</button>} />

    <section className="report-command panel">
      <div className="report-command-copy"><span>{t("reportsPage.assurance")}</span><strong>{latest ? latest.title : t("reportsPage.noRuns")}</strong><small>{latest ? `${latest.report_id} · ${formatFullDateTime(latest.completed_at || latest.created_at)}` : t("reportsPage.createFirst")}</small></div>
      <div className="report-integrity"><ShieldCheck size={22} /><div><span>{t("reportsPage.integrity")}</span><strong>{latest?.checksum_sha256 || t("reportsPage.awaitingSnapshot")}</strong></div></div>
    </section>

    {composerOpen && <form className="report-composer panel" onSubmit={(event) => { event.preventDefault(); create.mutate(); }}>
      <div className="report-composer-heading"><div><span>{t("reportsPage.generator")}</span><h2>{t("reportsPage.newSnapshot")}</h2></div><small>{t("reportsPage.immutableHint")}</small></div>
      <div className="report-form-grid">
        <label><span>{t("reportsPage.reportType")}</span><select value={type} onChange={(event) => setType(event.target.value as ReportType)}>{reportTypes.map((value) => <option key={value} value={value}>{t(`reportsPage.types.${value}`)}</option>)}</select></label>
        <label><span>{t("reportsPage.periodStart")}</span><input type="datetime-local" value={start} onChange={(event) => setStart(event.target.value)} /></label>
        <label><span>{t("reportsPage.periodEnd")}</span><input type="datetime-local" value={end} onChange={(event) => setEnd(event.target.value)} /></label>
        {type === "INCIDENT" && <label><span>{t("reportsPage.incidentId")}</span><input required value={incidentId} onChange={(event) => setIncidentId(event.target.value)} placeholder="inc_..." /></label>}
        {type === "CASE_CLOSURE" && <label><span>{t("reportsPage.caseId")}</span><input required value={caseId} onChange={(event) => setCaseId(event.target.value)} placeholder="case_..." /></label>}
      </div>
      {create.isError && <ErrorState error={create.error} compact />}
      <div className="report-form-actions"><button type="button" className="report-button" onClick={() => setComposerOpen(false)}>{t("common.cancel")}</button><button type="submit" disabled={create.isPending} className="report-button primary"><BarChart3 size={17} />{create.isPending ? t("reportsPage.generating") : t("reportsPage.generateSnapshot")}</button></div>
    </form>}

    <section className="metrics-grid compact-metrics report-metrics">
      {operationalCards.length ? operationalCards.map((metric, index) => <MetricCard key={metric.key || index} label={metricLabel(metric)} value={`${metric.value ?? 0}${metric.unit ? ` ${metric.unit}` : ""}`} icon={[Activity, Clock3, ShieldCheck, BarChart3][index] || Activity} />) : <><MetricCard label={t("reportsPage.totalRuns")} value={items.length} icon={FileText} /><MetricCard label={t("reportsPage.completed")} value={items.filter((item) => item.status === "COMPLETED").length} icon={ShieldCheck} tone="good" /><MetricCard label={t("reportsPage.formats")} value="JSON · CSV · HTML" icon={Table2} /><MetricCard label={t("reportsPage.retention")} value={t("reportsPage.immutable")} icon={Clock3} /></>}
    </section>

    <section className="panel report-ledger">
      <div className="report-ledger-head"><div><span>{t("reportsPage.ledger")}</span><h2>{t("reportsPage.history")}</h2></div><label><select value={filter} onChange={(event) => setFilter(event.target.value)}><option value="">{t("common.all")}</option>{reportTypes.map((value) => <option key={value} value={value}>{t(`reportsPage.types.${value}`)}</option>)}</select></label></div>
      {reports.isPending ? <LoadingState rows={7} /> : reports.isError ? <ErrorState error={reports.error} onRetry={() => void reports.refetch()} /> : !items.length ? <EmptyState title={t("reportsPage.noReports")} icon={FileText} /> : <div className="table-scroll"><table className="data-table report-table"><thead><tr><th>{t("common.status")}</th><th>{t("reportsPage.report")}</th><th>{t("reportsPage.reportType")}</th><th>{t("common.actor")}</th><th>{t("common.created")}</th><th>{t("reportsPage.checksum")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.report_id} className="clickable-row" onClick={() => setSelected(item)}><td><StatusBadge value={item.status} /></td><td className="primary-cell"><strong>{item.title}</strong><small>{item.report_id}</small></td><td><span className="report-type-code">{t(`reportsPage.types.${item.report_type}`)}</span></td><td>{item.created_by}</td><td>{formatFullDateTime(item.created_at)}</td><td><code>{item.checksum_sha256.slice(0, 20)}...</code></td><td><FileText size={17} /></td></tr>)}</tbody></table></div>}
    </section>

    {downloadError !== null && <section className="panel"><ErrorState error={downloadError} compact /></section>}
    <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} wide title={selected?.title || ""} eyebrow={selected ? `${selected.report_type} · ${selected.report_id}` : ""} footer={selected && <div className="report-downloads"><button className="report-button" type="button" onClick={() => void download(selected, "json")}><FileJson size={16} />JSON</button><button className="report-button" type="button" onClick={() => void download(selected, "csv")}><Table2 size={16} />CSV</button><button className="report-button primary" type="button" onClick={() => void download(selected, "html")}><Download size={16} />HTML</button></div>}>
      {selected && <ReportDetails report={selected} />}
    </Drawer>
  </div>;
}

function ReportDetails({ report }: { report: ReportRunDto }) {
  const { t } = useTranslation();
  const metrics = metricsFrom(report.snapshot);
  return <div className="detail-stack report-detail">
    <div className="report-detail-seal"><ShieldCheck size={28} /><div><span>{t("reportsPage.integrityVerified")}</span><strong>{report.checksum_sha256}</strong></div><StatusBadge value={report.status} /></div>
    <dl className="report-detail-grid"><div><dt>{t("reportsPage.reportType")}</dt><dd>{t(`reportsPage.types.${report.report_type}`)}</dd></div><div><dt>{t("common.actor")}</dt><dd>{report.created_by}</dd></div><div><dt>{t("reportsPage.completedAt")}</dt><dd>{formatFullDateTime(report.completed_at || report.created_at)}</dd></div><div><dt>{t("reportsPage.period")}</dt><dd>{periodLabel(report)}</dd></div></dl>
    {metrics.length > 0 && <section className="detail-section"><h3>{t("reportsPage.keyMetrics")}</h3><div className="snapshot-metric-grid">{metrics.map((metric, index) => <div key={metric.key || index}><span>{metricLabel(metric)}</span><strong>{metric.value ?? 0}</strong><small>{metric.unit || ""}</small></div>)}</div></section>}
    <section className="detail-section"><h3>{t("reportsPage.snapshot")}</h3><pre className="report-json">{JSON.stringify(report.snapshot, null, 2)}</pre></section>
  </div>;
}

function metricsFrom(snapshot?: Record<string, unknown>): SnapshotMetric[] {
  const metrics = snapshot?.metrics;
  if (!Array.isArray(metrics)) return [];
  return metrics.filter((item): item is SnapshotMetric => Boolean(item) && typeof item === "object");
}

function metricLabel(metric: SnapshotMetric): string {
  return metric.label || (metric.key || "metric").replaceAll("_", " ").replace(/\b\w/g, (value) => value.toUpperCase());
}

function periodLabel(report: ReportRunDto): string {
  const start = report.parameters.start;
  const end = report.parameters.end;
  if (!start && !end) return "—";
  return `${start ? formatFullDateTime(start) : "—"} — ${end ? formatFullDateTime(end) : "—"}`;
}
