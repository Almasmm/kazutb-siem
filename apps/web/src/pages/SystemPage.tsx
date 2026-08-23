import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive, Database, FileSearch, HeartPulse, Save, ServerCog } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { RetentionPolicyDto } from "../api/types";
import { ErrorState, InlineNotice, JsonBlock, LoadingState, MetricCard, PageHeader, PanelHeader, StatusBadge } from "../components/ui";
import { formatFullDateTime } from "../utils/format";

type RetentionDraft = Pick<RetentionPolicyDto, "raw_days" | "normalized_days" | "findings_days" | "evidence_days" | "version">;
const emptyDraft: RetentionDraft = { raw_days: 0, normalized_days: 0, findings_days: 0, evidence_days: 0, version: 0 };

export default function SystemPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<RetentionDraft>(emptyDraft);
  const health = useQuery({ queryKey: ["system-readiness"], queryFn: ({ signal }) => api.healthReady(signal), refetchInterval: 15_000 });
  const retention = useQuery({ queryKey: ["retention"], queryFn: ({ signal }) => api.retention(signal) });
  useEffect(() => { if (retention.data) setDraft({ raw_days: retention.data.raw_days, normalized_days: retention.data.normalized_days, findings_days: retention.data.findings_days, evidence_days: retention.data.evidence_days, version: retention.data.version }); }, [retention.data]);
  const update = useMutation({ mutationFn: () => api.updateRetention(draft), onSuccess: (policy) => { setDraft({ raw_days: policy.raw_days, normalized_days: policy.normalized_days, findings_days: policy.findings_days, evidence_days: policy.evidence_days, version: policy.version }); void queryClient.invalidateQueries({ queryKey: ["retention"] }); } });
  const readiness = String(health.data?.status || (health.data?.ready === true ? "READY" : "UNKNOWN")).toUpperCase();
  const setDays = (field: keyof Omit<RetentionDraft, "version">, value: string) => setDraft((current) => ({ ...current, [field]: Math.max(1, Number(value) || 1) }));

  return <div className="page"><PageHeader eyebrow={t("systemPage.eyebrow")} title={t("systemPage.title")} subtitle={t("systemPage.subtitle")} actions={<button className="button ghost" type="button" onClick={() => void health.refetch()}><HeartPulse size={16} />{t("common.refresh")}</button>} />
    {retention.isPending ? <LoadingState rows={6} /> : retention.isError ? <ErrorState error={retention.error} onRetry={() => void retention.refetch()} /> : <><section className="metrics-grid"><MetricCard label={t("systemPage.rawEvents")} value={`${draft.raw_days} ${t("systemPage.days")}`} icon={Archive} /><MetricCard label={t("systemPage.normalizedEvents")} value={`${draft.normalized_days} ${t("systemPage.days")}`} icon={Database} /><MetricCard label={t("systemPage.findings")} value={`${draft.findings_days} ${t("systemPage.days")}`} icon={FileSearch} /><MetricCard label={t("systemPage.evidence")} value={`${draft.evidence_days} ${t("systemPage.days")}`} icon={ServerCog} /></section>
      <section className="system-grid"><article className="panel"><PanelHeader title={t("systemPage.readiness")} meta={t("systemPage.readinessHint")} action={<StatusBadge value={readiness} />} />{health.isPending ? <LoadingState rows={5} compact /> : health.isError ? <ErrorState error={health.error} onRetry={() => void health.refetch()} compact /> : <div className="system-health"><div className={`health-orbit ${["READY", "OK", "HEALTHY"].includes(readiness) ? "ready" : "warning"}`}><HeartPulse size={28} /><span>{readiness}</span></div><details className="raw-details"><summary>{t("systemPage.healthDetails")}</summary><JsonBlock value={health.data} /></details></div>}</article>
      <article className="panel"><PanelHeader title={t("systemPage.retentionPolicy")} meta={`${t("common.version")} ${retention.data?.version || 0}`} /><form className="retention-form" onSubmit={(event) => { event.preventDefault(); update.mutate(); }}>{(["raw_days", "normalized_days", "findings_days", "evidence_days"] as const).map((field) => <label className="form-field" key={field}><span>{t(`systemPage.${field}`)}</span><div className="number-field"><input type="number" min="1" max="3650" value={draft[field]} onChange={(event) => setDays(field, event.target.value)} /><small>{t("systemPage.days")}</small></div></label>)}<div className="retention-actions"><span>{t("systemPage.updatedBy")}: {retention.data?.updated_by || "—"}<br />{formatFullDateTime(retention.data?.updated_at)}</span><button className="button primary" type="submit" disabled={update.isPending}><Save size={16} />{t("common.save")}</button></div>{update.isError && <ErrorState error={update.error} compact />}{update.isSuccess && <InlineNotice tone="success">{t("systemPage.saved")}</InlineNotice>}</form></article></section></>}
  </div>;
}
