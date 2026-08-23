import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BrainCircuit, CheckCircle2, Search, ShieldAlert, UsersRound, XCircle } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { UEBAAnomalyDto } from "../api/types";
import { DetailRow, Drawer, EmptyState, ErrorState, LoadingState, MetricCard, Modal, PageHeader, RiskScore, SeverityBadge, StatusBadge, TableAction } from "../components/ui";
import { formatDateTime, formatFullDateTime } from "../utils/format";

export default function UebaPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState("");
  const [entityType, setEntityType] = useState("");
  const [minimumRisk, setMinimumRisk] = useState("0");
  const [selected, setSelected] = useState<UEBAAnomalyDto | null>(null);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [feedbackStatus, setFeedbackStatus] = useState("CONFIRMED");
  const [reason, setReason] = useState("");
  const anomalies = useQuery({ queryKey: ["ueba-anomalies", status, entityType, minimumRisk], queryFn: ({ signal }) => api.uebaAnomalies({ status, entity_type: entityType, minimum_risk: Number(minimumRisk), limit: 500 }, signal) });
  const baseline = useQuery({ queryKey: ["ueba-baseline", selected?.entity_type, selected?.entity_id], queryFn: ({ signal }) => api.uebaBaseline(selected!.entity_type, selected!.entity_id, signal), enabled: Boolean(selected) });
  const feedback = useMutation({
    mutationFn: () => api.updateUEBAFeedback(selected!.anomaly_id, { status: feedbackStatus, reason: reason.trim(), version: selected!.version }),
    onSuccess: (item) => { setSelected(item); setFeedbackOpen(false); setReason(""); void queryClient.invalidateQueries({ queryKey: ["ueba-anomalies"] }); },
  });
  const items = anomalies.data?.items || [];
  const highRisk = items.filter((item) => item.risk_score >= 70).length;
  const confirmed = items.filter((item) => item.status === "CONFIRMED").length;

  return <div className="page">
    <PageHeader eyebrow={t("uebaPage.eyebrow")} title={t("uebaPage.title")} subtitle={t("uebaPage.subtitle")} />
    <section className="metrics-grid compact-metrics"><MetricCard label={t("uebaPage.anomalies")} value={anomalies.data?.total || 0} icon={UsersRound} /><MetricCard label={t("uebaPage.highRisk")} value={highRisk} icon={ShieldAlert} tone={highRisk ? "critical" : "good"} /><MetricCard label={t("uebaPage.confirmed")} value={confirmed} icon={CheckCircle2} tone="good" /><MetricCard label={t("uebaPage.model") } value={items[0]?.model_version || "—"} icon={BrainCircuit} /></section>
    <section className="filter-bar panel"><label className="search-field grow"><Search size={17} /><select value={entityType} onChange={(event) => setEntityType(event.target.value)}><option value="">{t("uebaPage.entityType")}: {t("common.all")}</option><option value="USER">USER</option><option value="DEVICE">DEVICE</option></select></label><label className="select-field"><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">{t("common.status")}: {t("common.all")}</option><option>NEW</option><option>CONFIRMED</option><option>FALSE_POSITIVE</option></select></label><label className="select-field"><select value={minimumRisk} onChange={(event) => setMinimumRisk(event.target.value)}><option value="0">{t("uebaPage.minimumRisk")}: 0</option><option value="40">40+</option><option value="70">70+</option><option value="90">90+</option></select></label></section>
    <section className="panel table-panel">{anomalies.isPending ? <LoadingState rows={8} /> : anomalies.isError ? <ErrorState error={anomalies.error} onRetry={() => void anomalies.refetch()} /> : !items.length ? <EmptyState title={t("uebaPage.noAnomalies")} icon={UsersRound} /> : <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("common.risk")}</th><th>{t("common.title")}</th><th>{t("uebaPage.entity")}</th><th>{t("common.confidence")}</th><th>{t("common.created")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.anomaly_id} className="clickable-row" onClick={() => setSelected(item)}><td><StatusBadge value={item.status} /></td><td><RiskScore value={item.risk_score} compact /></td><td className="primary-cell"><strong>{item.title}</strong><small>{item.anomaly_id} · {item.peer_group || "—"}</small></td><td><strong>{item.entity_name || item.entity_id}</strong><small className="block-small">{item.entity_type}</small></td><td>{item.confidence}%</td><td>{formatDateTime(item.created_at)}</td><td><TableAction /></td></tr>)}</tbody></table></div>}</section>
    <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} wide title={selected?.title || ""} eyebrow={selected?.anomaly_id} footer={selected && <button className="button primary" type="button" onClick={() => setFeedbackOpen(true)}>{t("uebaPage.recordFeedback")}</button>}>
      {selected && <div className="detail-stack"><div className="drawer-lead"><SeverityBadge value={selected.severity} /><StatusBadge value={selected.status} /><strong>{selected.entity_name || selected.entity_id}</strong></div><div className="alert-summary-grid"><div className="risk-panel"><span>{t("common.risk")}</span><RiskScore value={selected.risk_score} /></div><p className="lead-description">{String(selected.explanation?.summary || selected.title)}</p></div><dl className="detail-grid"><DetailRow label={t("uebaPage.entity")}>{selected.entity_type} / {selected.entity_id}</DetailRow><DetailRow label={t("common.confidence")}>{selected.confidence}%</DetailRow><DetailRow label={t("uebaPage.model")}>{selected.model_version}</DetailRow><DetailRow label={t("uebaPage.observations")}>{selected.baseline_observations ?? "—"}</DetailRow><DetailRow label={t("common.created")}>{formatFullDateTime(selected.created_at)}</DetailRow><DetailRow label={t("common.updated")}>{formatFullDateTime(selected.updated_at)}</DetailRow></dl>
        <section className="detail-section"><h3>{t("uebaPage.behaviorSignals")}</h3><div className="feature-list">{selected.features?.map((feature) => <div key={`${feature.code}-${feature.field}`}><span className="feature-score">+{feature.score}</span><div><strong>{feature.code}</strong><p>{feature.explanation}</p><small>{feature.field}{feature.value ? ` = ${feature.value}` : ""} · baseline {(feature.baseline_frequency * 100).toFixed(1)}%</small></div></div>)}</div></section>
        <section className="detail-section"><h3>{t("uebaPage.baseline")}</h3>{baseline.isPending ? <LoadingState rows={3} compact /> : baseline.isError ? <ErrorState error={baseline.error} compact /> : baseline.data && <dl className="detail-grid"><DetailRow label={t("uebaPage.peerGroup")}>{baseline.data.peer_group || "—"}</DetailRow><DetailRow label={t("uebaPage.observations")}>{baseline.data.observation_count}</DetailRow><DetailRow label={t("uebaPage.drift")}>{baseline.data.drift_status} / {baseline.data.drift_score.toFixed(2)}</DetailRow><DetailRow label={t("uebaPage.trainingWindow")}>{baseline.data.training_window_days} {t("systemPage.days")}</DetailRow></dl>}</section>
      </div>}
    </Drawer>
    <Modal open={feedbackOpen && Boolean(selected)} onClose={() => setFeedbackOpen(false)} title={t("uebaPage.feedbackTitle")} footer={<><button className="button ghost" type="button" onClick={() => setFeedbackOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={!reason.trim() || feedback.isPending} onClick={() => feedback.mutate()}>{feedbackStatus === "CONFIRMED" ? <CheckCircle2 size={16} /> : <XCircle size={16} />}{t("common.save")}</button></>}><label className="form-field"><span>{t("common.status")}</span><select value={feedbackStatus} onChange={(event) => setFeedbackStatus(event.target.value)}><option value="CONFIRMED">{t("uebaPage.confirmed")}</option><option value="FALSE_POSITIVE">{t("uebaPage.falsePositive")}</option></select></label><label className="form-field"><span>{t("common.reason")}</span><textarea rows={4} value={reason} onChange={(event) => setReason(event.target.value)} /></label>{feedback.isError && <ErrorState error={feedback.error} compact />}</Modal>
  </div>;
}
