import { useDeferredValue, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BellPlus,
  CheckCircle2,
  Clock3,
  Filter,
  Search,
  ShieldAlert,
  ShieldCheck,
  Siren,
  UserRoundCheck,
  XCircle,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { AlertDto } from "../api/types";
import {
  DetailRow,
  Drawer,
  EmptyState,
  ErrorState,
  InlineNotice,
  JsonBlock,
  LoadingState,
  Modal,
  PageHeader,
  RiskScore,
  SeverityBadge,
  StatusBadge,
  TableAction,
  Tag,
} from "../components/ui";
import { formatDateTime, formatFullDateTime, formatNumber } from "../utils/format";

function matchesAlert(alert: AlertDto, query: string): boolean {
  if (!query) return true;
  const haystack = [alert.id, alert.title, alert.name, alert.description, alert.user_name, alert.asset_name, alert.src_ip, alert.dst_ip, alert.rule_title]
    .filter(Boolean).join(" ").toLowerCase();
  return haystack.includes(query.toLowerCase());
}

function alertTitle(alert: AlertDto): string {
  return alert.title || alert.name || alert.rule_title || alert.id;
}

export default function AlertsPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") || "");
  const [severity, setSeverity] = useState(params.get("severity") || "");
  const [status, setStatus] = useState(params.get("status") || "");
  const [incidentOpen, setIncidentOpen] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const deferredSearch = useDeferredValue(search);

  const alerts = useQuery({
    queryKey: ["alerts", deferredSearch, severity, status],
    queryFn: ({ signal }) => api.alerts({ q: deferredSearch, severity, status, limit: 100, offset: 0 }, signal),
    refetchInterval: 15_000,
  });

  const selectedId = params.get("alert");
  const filtered = useMemo(() => (alerts.data?.items || []).filter((alert) => {
    const severityMatches = !severity || alert.severity?.toUpperCase() === severity;
    const statusMatches = !status || alert.status?.toUpperCase() === status;
    return severityMatches && statusMatches && matchesAlert(alert, deferredSearch);
  }), [alerts.data?.items, deferredSearch, severity, status]);
  const selected = filtered.find((alert) => alert.id === selectedId) || alerts.data?.items.find((alert) => alert.id === selectedId);

  useEffect(() => {
    if (!selected) return;
    setIncidentTitle(`${t("incidentsPage.title")}: ${alertTitle(selected)}`);
    setIncidentDescription(selected.description || "");
  }, [selected, t]);

  const syncParams = (next: { q?: string; severity?: string; status?: string; alert?: string | null }) => {
    const updated = new URLSearchParams(params);
    Object.entries(next).forEach(([key, value]) => value ? updated.set(key, value) : updated.delete(key));
    setParams(updated, { replace: true });
  };

  const updateAlert = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Record<string, unknown> }) => api.updateAlert(id, patch),
    onSuccess: () => {
      setNotice(t("alertsPage.statusUpdated"));
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  const createIncident = useMutation({
    mutationFn: (alert: AlertDto) => api.createIncident({
      title: incidentTitle.trim() || alertTitle(alert),
      summary: incidentDescription.trim(),
      alert_ids: [alert.id],
      assignee: "Данияр Нұрлан",
    }),
    onSuccess: (incident) => {
      setIncidentOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["overview"] });
      navigate(`/incidents?focus=${encodeURIComponent(incident.id)}&created=1`);
    },
  });

  const acknowledge = (alert: AlertDto) => updateAlert.mutate({
    id: alert.id,
    patch: { status: "ACKNOWLEDGED", assignee: "Данияр Нұрлан", version: alert.version },
  });
  const falsePositive = (alert: AlertDto) => updateAlert.mutate({
    id: alert.id,
    patch: { status: "CLOSED", disposition: "FALSE_POSITIVE", version: alert.version },
  });

  return (
    <div className="page">
      <PageHeader eyebrow={t("alertsPage.eyebrow")} title={t("alertsPage.title")} subtitle={t("alertsPage.subtitle")} />

      <section className="filter-bar panel">
        <label className="search-field grow"><Search size={17} /><input value={search} onChange={(event) => { setSearch(event.target.value); syncParams({ q: event.target.value }); }} placeholder={t("alertsPage.searchPlaceholder")} /></label>
        <label className="select-field"><Filter size={16} /><select value={severity} onChange={(event) => { setSeverity(event.target.value); syncParams({ severity: event.target.value }); }} aria-label={t("common.severity")}>
          <option value="">{t("common.severity")}: {t("common.all")}</option>
          <option value="CRITICAL">{t("severity.critical")}</option><option value="HIGH">{t("severity.high")}</option>
          <option value="MEDIUM">{t("severity.medium")}</option><option value="LOW">{t("severity.low")}</option>
        </select></label>
        <label className="select-field"><select value={status} onChange={(event) => { setStatus(event.target.value); syncParams({ status: event.target.value }); }} aria-label={t("common.status")}>
          <option value="">{t("common.status")}: {t("common.all")}</option>
          <option value="NEW">{t("status.new")}</option><option value="TRIAGE">{t("status.triage")}</option>
          <option value="IN_PROGRESS">{t("status.in_progress")}</option><option value="CLOSED">{t("status.closed")}</option>
        </select></label>
        <span className="result-count"><strong>{formatNumber(alerts.data?.total)}</strong> {t("common.total").toLowerCase()}</span>
      </section>

      {notice && <InlineNotice tone="success"><span>{notice}</span><button className="notice-close" type="button" onClick={() => setNotice(null)}>×</button></InlineNotice>}
      {updateAlert.isError && <ErrorState error={updateAlert.error} compact />}

      <section className="panel table-panel">
        {alerts.isPending ? <LoadingState rows={8} /> : alerts.isError ? <ErrorState error={alerts.error} onRetry={() => void alerts.refetch()} /> : filtered.length === 0 ? (
          <EmptyState title={deferredSearch || severity || status ? t("common.noResults") : t("alertsPage.noAlerts")} description={t("alertsPage.noAlertsHint")} icon={ShieldCheck} />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>{t("common.severity")}</th><th>{t("common.title")}</th><th>{t("common.risk")}</th><th>{t("common.status")}</th><th>{t("alertsPage.entity")}</th><th>{t("common.time")}</th><th aria-label={t("common.details")} /></tr></thead>
              <tbody>{filtered.map((alert) => (
                <tr key={alert.id} className={`clickable-row ${selectedId === alert.id ? "selected" : ""}`} onClick={() => syncParams({ alert: alert.id })} onKeyDown={(event) => event.key === "Enter" && syncParams({ alert: alert.id })} tabIndex={0}>
                  <td><SeverityBadge value={alert.severity} /></td>
                  <td className="primary-cell"><strong>{alertTitle(alert)}</strong><small>{alert.rule_title || alert.rule_id || alert.source || alert.id}</small></td>
                  <td><RiskScore value={alert.risk_score} compact /></td>
                  <td><StatusBadge value={alert.status} /></td>
                  <td><div className="entity-cell"><strong>{alert.asset_name || alert.user_name || alert.src_ip || "—"}</strong><small>{alert.user_name || alert.src_ip || alert.source_type || ""}</small></div></td>
                  <td className="nowrap"><span>{formatDateTime(alert.last_seen_at || alert.created_at)}</span><small>{formatNumber(alert.event_count)} {t("common.events").toLowerCase()}</small></td>
                  <td><TableAction /></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </section>

      <Drawer
        open={Boolean(selected)}
        onClose={() => syncParams({ alert: null })}
        title={selected ? alertTitle(selected) : ""}
        eyebrow={selected ? `${t("common.id")}: ${selected.id}` : undefined}
        wide
        footer={selected && (
          <div className="action-row">
            <button className="button ghost danger-text" type="button" disabled={updateAlert.isPending || selected.status?.toUpperCase() === "CLOSED"} onClick={() => falsePositive(selected)}><XCircle size={16} />{t("alertsPage.falsePositive")}</button>
            <button className="button secondary" type="button" disabled={updateAlert.isPending || ["TRIAGE", "ACKNOWLEDGED", "IN_PROGRESS", "CLOSED"].includes(selected.status?.toUpperCase() || "")} onClick={() => acknowledge(selected)}>{updateAlert.isPending ? <span className="button-spinner" /> : <UserRoundCheck size={16} />}{t(updateAlert.isPending ? "alertsPage.acknowledging" : "alertsPage.acknowledge")}</button>
            <button className="button primary" type="button" disabled={Boolean(selected.incident_id)} onClick={() => setIncidentOpen(true)}><BellPlus size={16} />{t("alertsPage.createIncident")}</button>
          </div>
        )}
      >
        {selected && (
          <div className="detail-stack">
            <div className="alert-summary-grid">
              <div className="risk-panel"><span>{t("common.risk")}</span><RiskScore value={selected.risk_score} /></div>
              <div className="summary-status"><SeverityBadge value={selected.severity} /><StatusBadge value={selected.status} /><p>{selected.description || t("common.notAvailable")}</p></div>
            </div>
            {selected.incident_id && <InlineNotice tone="info"><Siren size={17} />{t("alertsPage.linkedIncident")}: <button className="link-inline" onClick={() => navigate(`/incidents?focus=${encodeURIComponent(selected.incident_id!)}`)}>{selected.incident_id}</button></InlineNotice>}
            <section className="detail-section"><h3>{t("alertsPage.observed")}</h3><dl className="detail-grid">
              <DetailRow label={t("alertsPage.firstSeen")}>{formatFullDateTime(selected.first_seen_at || selected.created_at)}</DetailRow>
              <DetailRow label={t("alertsPage.lastSeen")}>{formatFullDateTime(selected.last_seen_at || selected.updated_at)}</DetailRow>
              <DetailRow label={t("alertsPage.eventCount")}>{formatNumber(selected.event_count)}</DetailRow>
              <DetailRow label={t("common.analyst")}>{selected.assignee || t("common.unassigned")}</DetailRow>
              <DetailRow label={t("common.asset")}>{selected.asset_name || selected.asset_id || "—"}</DetailRow>
              <DetailRow label={t("common.user")}>{selected.user_name || "—"}</DetailRow>
              <DetailRow label="Source IP">{selected.src_ip || "—"}</DetailRow>
              <DetailRow label="Destination IP">{selected.dst_ip || "—"}</DetailRow>
            </dl></section>
            <section className="detail-section"><h3>{t("alertsPage.detection")}</h3><dl className="detail-grid">
              <DetailRow label="Rule ID">{selected.rule_id || "—"}</DetailRow><DetailRow label={t("common.title")}>{selected.rule_title || "—"}</DetailRow>
              <DetailRow label={t("common.source")}>{selected.source || selected.source_type || "—"}</DetailRow><DetailRow label={t("common.confidence")}>{selected.confidence != null ? `${selected.confidence}%` : "—"}</DetailRow>
            </dl>
            <div className="tag-list">{selected.mitre_techniques?.length ? selected.mitre_techniques.map((technique) => <Tag key={technique} tone="accent">{technique}</Tag>) : <span className="muted">{t("common.noData")}</span>}</div></section>
            <section className="detail-section"><h3>{t("alertsPage.riskBreakdown")}</h3>
              {selected.risk_breakdown?.length ? <div className="risk-breakdown">{selected.risk_breakdown.map((item, index) => <div key={`${item.label}-${index}`}><span>{item.label || item.reason || item.source || t("common.unknown")}</span><strong className={(item.delta || item.score || 0) >= 0 ? "risk-positive" : "risk-negative"}>{(item.delta ?? item.score ?? 0) > 0 ? "+" : ""}{item.delta ?? item.score ?? 0}</strong></div>)}</div> : <span className="muted">{t("common.noData")}</span>}
            </section>
            <details className="raw-details"><summary>{t("common.rawData")}</summary><JsonBlock value={selected} /></details>
          </div>
        )}
      </Drawer>

      <Modal open={incidentOpen && Boolean(selected)} onClose={() => setIncidentOpen(false)} title={t("alertsPage.createIncidentTitle")} footer={<><button className="button ghost" type="button" onClick={() => setIncidentOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={!incidentTitle.trim() || createIncident.isPending} onClick={() => selected && createIncident.mutate(selected)}>{createIncident.isPending ? <span className="button-spinner" /> : <BellPlus size={16} />}{t("alertsPage.createIncident")}</button></>}>
        <p className="modal-intro">{t("alertsPage.createIncidentHint")}</p>
        <label className="form-field"><span>{t("alertsPage.incidentTitle")}</span><input value={incidentTitle} onChange={(event) => setIncidentTitle(event.target.value)} autoFocus /></label>
        <label className="form-field"><span>{t("alertsPage.incidentDescription")}</span><textarea rows={4} value={incidentDescription} onChange={(event) => setIncidentDescription(event.target.value)} /></label>
        {createIncident.isError && <ErrorState error={createIncident.error} compact />}
        {selected && <div className="linked-object"><ShieldAlert size={18} /><div><strong>{alertTitle(selected)}</strong><small>{selected.id}</small></div><SeverityBadge value={selected.severity} /></div>}
      </Modal>
    </div>
  );
}
