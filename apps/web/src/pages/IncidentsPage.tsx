import { useDeferredValue, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, BellRing, CheckCircle2, Filter, Search, ShieldAlert, UsersRound } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { IncidentDto } from "../api/types";
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
  SeverityBadge,
  StatusBadge,
  TableAction,
  Tag,
} from "../components/ui";
import { formatDateTime, formatFullDateTime, formatNumber, titleCaseCode } from "../utils/format";

const lifecycle = ["NEW", "TRIAGE", "INVESTIGATION", "CONTAINMENT", "ERADICATION", "RECOVERY", "CLOSED"];

function incidentTitle(incident: IncidentDto): string {
  return incident.title || incident.description || incident.id;
}

function entityLabel(entity: Record<string, unknown> | string): string {
  if (typeof entity === "string") return entity;
  return String(entity.name || entity.value || entity.id || entity.type || "Entity");
}

export default function IncidentsPage() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [notice, setNotice] = useState(params.get("created") ? t("incidentsPage.createdFromAlert") : "");
  const [closureOpen, setClosureOpen] = useState(false);
  const [closureDisposition, setClosureDisposition] = useState("BENIGN_TRUE_POSITIVE");
  const [closureReason, setClosureReason] = useState("");
  const deferredSearch = useDeferredValue(search);

  const incidents = useQuery({
    queryKey: ["incidents", deferredSearch, status, severity],
    queryFn: ({ signal }) => api.incidents({ q: deferredSearch, status, severity, limit: 100, offset: 0 }, signal),
    refetchInterval: 20_000,
  });
  const focusId = params.get("focus");
  const visible = useMemo(() => (incidents.data?.items || []).filter((incident) => {
    const haystack = [incident.id, incident.title, incident.description, incident.assignee].filter(Boolean).join(" ").toLowerCase();
    return (!deferredSearch || haystack.includes(deferredSearch.toLowerCase())) && (!status || incident.status?.toUpperCase() === status) && (!severity || incident.severity?.toUpperCase() === severity);
  }), [deferredSearch, incidents.data?.items, severity, status]);
  const selected = incidents.data?.items.find((incident) => incident.id === focusId);

  const updateIncident = useMutation({
    mutationFn: ({ incident, patch }: { incident: IncidentDto; patch: Record<string, unknown> }) => api.updateIncident(incident.id, { ...patch, version: incident.version }),
    onSuccess: () => {
      setNotice(t("incidentsPage.statusUpdated"));
      setClosureOpen(false);
      setClosureReason("");
      void queryClient.invalidateQueries({ queryKey: ["incidents"] });
      void queryClient.invalidateQueries({ queryKey: ["overview"] });
    },
  });

  const updateFocus = (id?: string) => {
    const next = new URLSearchParams(params);
    if (id) next.set("focus", id); else next.delete("focus");
    next.delete("created");
    setParams(next, { replace: true });
  };

  const currentIndex = selected ? lifecycle.indexOf(selected.status?.toUpperCase() || "NEW") : -1;
  const nextStatus = currentIndex >= 0 && currentIndex < lifecycle.length - 1 ? lifecycle[currentIndex + 1] : undefined;
  const statusLabel = (value: string) => {
    const key = `status.${value.toLowerCase()}`;
    return i18n.exists(key) ? t(key) : titleCaseCode(value);
  };

  return (
    <div className="page">
      <PageHeader eyebrow={t("incidentsPage.eyebrow")} title={t("incidentsPage.title")} subtitle={t("incidentsPage.subtitle")} />
      {notice && <InlineNotice tone="success"><CheckCircle2 size={17} /><span>{notice}</span><button className="notice-close" type="button" onClick={() => setNotice("")}>×</button></InlineNotice>}
      {updateIncident.isError && <ErrorState error={updateIncident.error} compact />}

      <section className="filter-bar panel">
        <label className="search-field grow"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("incidentsPage.searchPlaceholder")} /></label>
        <label className="select-field"><Filter size={16} /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">{t("common.severity")}: {t("common.all")}</option><option value="CRITICAL">{t("severity.critical")}</option><option value="HIGH">{t("severity.high")}</option><option value="MEDIUM">{t("severity.medium")}</option><option value="LOW">{t("severity.low")}</option></select></label>
        <label className="select-field"><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">{t("common.status")}: {t("common.all")}</option>{lifecycle.map((item) => <option value={item} key={item}>{statusLabel(item)}</option>)}</select></label>
        <span className="result-count"><strong>{formatNumber(incidents.data?.total)}</strong> {t("common.total").toLowerCase()}</span>
      </section>

      <section className="panel table-panel">
        {incidents.isPending ? <LoadingState rows={7} /> : incidents.isError ? <ErrorState error={incidents.error} onRetry={() => void incidents.refetch()} /> : visible.length === 0 ? (
          <EmptyState title={deferredSearch || status || severity ? t("common.noResults") : t("incidentsPage.noIncidents")} description={t("incidentsPage.noIncidentsHint")} icon={BellRing} />
        ) : <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.severity")}</th><th>{t("common.title")}</th><th>{t("common.status")}</th><th>{t("common.analyst")}</th><th>{t("common.alerts")}</th><th>{t("common.updated")}</th><th /></tr></thead><tbody>
          {visible.map((incident) => <tr key={incident.id} className={`clickable-row ${focusId === incident.id ? "selected" : ""}`} tabIndex={0} onClick={() => updateFocus(incident.id)} onKeyDown={(event) => event.key === "Enter" && updateFocus(incident.id)}>
            <td><SeverityBadge value={incident.severity} /></td><td className="primary-cell"><strong>{incidentTitle(incident)}</strong><small>{incident.id}</small></td><td><StatusBadge value={incident.status} /></td>
            <td>{incident.assignee || t("common.unassigned")}</td><td><span className="count-chip"><ShieldAlert size={14} />{formatNumber(incident.alert_ids?.length)}</span></td><td className="nowrap">{formatDateTime(incident.updated_at || incident.created_at)}</td><td><TableAction /></td>
          </tr>)}
        </tbody></table></div>}
      </section>

      <Drawer open={Boolean(selected)} onClose={() => updateFocus()} title={selected ? incidentTitle(selected) : ""} eyebrow={selected ? `${t("common.id")}: ${selected.id}` : undefined} wide footer={selected && nextStatus ? <div className="action-row align-right"><button className="button primary" type="button" disabled={updateIncident.isPending} onClick={() => nextStatus === "CLOSED" ? setClosureOpen(true) : updateIncident.mutate({ incident: selected, patch: { status: nextStatus } })}>{updateIncident.isPending ? <span className="button-spinner" /> : <ArrowRight size={16} />}{t("incidentsPage.advance", { status: statusLabel(nextStatus) })}</button></div> : undefined}>
        {selected && <div className="detail-stack">
          <div className="incident-lead"><div><SeverityBadge value={selected.severity} /><StatusBadge value={selected.status} /></div><p>{selected.description || t("common.notAvailable")}</p></div>
          <section className="detail-section"><h3>{t("incidentsPage.lifecycle")}</h3><div className="lifecycle-stepper">{lifecycle.map((step, index) => <div key={step} className={`${index < currentIndex ? "complete" : ""} ${index === currentIndex ? "current" : ""}`}><span>{index < currentIndex ? "✓" : index + 1}</span><small>{statusLabel(step)}</small></div>)}</div></section>
          <dl className="detail-grid"><DetailRow label={t("common.created")}>{formatFullDateTime(selected.created_at)}</DetailRow><DetailRow label={t("common.updated")}>{formatFullDateTime(selected.updated_at)}</DetailRow><DetailRow label={t("common.analyst")}>{selected.assignee || t("common.unassigned")}</DetailRow><DetailRow label={t("common.version")}>{selected.version ?? "—"}</DetailRow></dl>
          <section className="detail-section"><h3>{t("incidentsPage.relatedAlerts")}</h3><div className="tag-list">{selected.alert_ids?.length ? selected.alert_ids.map((id) => <Tag key={id} tone="warning">{id}</Tag>) : <span className="muted">{t("common.noData")}</span>}</div></section>
          <section className="detail-section"><h3>{t("incidentsPage.entities")}</h3><div className="tag-list">{selected.entities?.length ? selected.entities.map((entity, index) => <Tag key={`${entityLabel(entity)}-${index}`}><UsersRound size={13} />{entityLabel(entity)}</Tag>) : <span className="muted">{t("common.noData")}</span>}</div><div className="tag-list top-gap">{selected.mitre_techniques?.map((technique) => <Tag key={technique} tone="accent">{technique}</Tag>)}</div></section>
          <section className="detail-section"><h3>{t("incidentsPage.timeline")}</h3>{selected.timeline?.length ? <div className="timeline">{selected.timeline.map((entry, index) => <div key={entry.id || index}><span className="timeline-dot" /><div><strong>{entry.action || entry.type || t("common.action")}</strong><p>{entry.message || "—"}</p><small>{formatFullDateTime(entry.timestamp || entry.created_at)} · {entry.actor || t("common.unknown")}</small></div></div>)}</div> : <EmptyState title={t("common.noData")} icon={BellRing} />}</section>
          {selected.closure_reason && <InlineNotice tone="info">{t("incidentsPage.closureReason")}: {selected.closure_reason}</InlineNotice>}
          <details className="raw-details"><summary>{t("common.rawData")}</summary><JsonBlock value={selected} /></details>
        </div>}
      </Drawer>

      <Modal
        open={closureOpen && Boolean(selected)}
        onClose={() => setClosureOpen(false)}
        title={t("incidentsPage.closeTitle")}
        footer={<>
          <button className="button ghost" type="button" onClick={() => setClosureOpen(false)}>{t("common.cancel")}</button>
          <button className="button primary" type="button" disabled={!selected || !closureReason.trim() || updateIncident.isPending} onClick={() => selected && updateIncident.mutate({ incident: selected, patch: { status: "CLOSED", disposition: closureDisposition, closure_reason: closureReason.trim() } })}>{updateIncident.isPending ? <span className="button-spinner" /> : <CheckCircle2 size={16} />}{t("common.close")}</button>
        </>}
      >
        <p className="modal-intro">{t("incidentsPage.closeHint")}</p>
        <label className="form-field"><span>{t("incidentsPage.disposition")}</span><select value={closureDisposition} onChange={(event) => setClosureDisposition(event.target.value)}>
          <option value="BENIGN_TRUE_POSITIVE">{t("incidentsPage.benignTruePositive")}</option>
          <option value="FALSE_POSITIVE">{t("incidentsPage.falsePositive")}</option>
          <option value="ACCEPTED_RISK">{t("incidentsPage.acceptedRisk")}</option>
        </select></label>
        <label className="form-field"><span>{t("incidentsPage.closureReason")}</span><textarea rows={4} value={closureReason} onChange={(event) => setClosureReason(event.target.value)} placeholder={t("incidentsPage.closurePlaceholder")} /></label>
        {updateIncident.isError && <ErrorState error={updateIncident.error} compact />}
      </Modal>
    </div>
  );
}
