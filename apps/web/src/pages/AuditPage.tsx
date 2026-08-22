import { useDeferredValue, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ClipboardCheck, Fingerprint, Search } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { AuditDto } from "../api/types";
import {
  DetailRow,
  Drawer,
  EmptyState,
  ErrorState,
  JsonBlock,
  LoadingState,
  PageHeader,
  StatusBadge,
  TableAction,
  Tag,
} from "../components/ui";
import { formatDateTime, formatFullDateTime, formatNumber } from "../utils/format";

export default function AuditPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [outcome, setOutcome] = useState("");
  const [selected, setSelected] = useState<AuditDto | null>(null);
  const deferredSearch = useDeferredValue(search);
  const audit = useQuery({
    queryKey: ["audit", deferredSearch, outcome],
    queryFn: ({ signal }) => api.audit({ q: deferredSearch, outcome, limit: 200, offset: 0 }, signal),
    refetchInterval: 30_000,
  });
  const visible = useMemo(() => (audit.data?.items || []).filter((record) => {
    const text = [record.id, record.actor, record.actor_id, record.action, record.resource_type, record.resource_id, record.trace_id, record.ip_address].filter(Boolean).join(" ").toLowerCase();
    return (!deferredSearch || text.includes(deferredSearch.toLowerCase())) && (!outcome || record.outcome?.toUpperCase() === outcome);
  }), [audit.data?.items, deferredSearch, outcome]);

  return (
    <div className="page">
      <PageHeader eyebrow={t("auditPage.eyebrow")} title={t("auditPage.title")} subtitle={t("auditPage.subtitle")} />
      <section className="filter-bar panel">
        <label className="search-field grow"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("auditPage.searchPlaceholder")} /></label>
        <label className="select-field"><select value={outcome} onChange={(event) => setOutcome(event.target.value)}><option value="">{t("common.outcome")}: {t("common.all")}</option><option value="SUCCESS">{t("status.success")}</option><option value="FAILURE">{t("status.failure")}</option><option value="DENIED">{t("status.denied")}</option></select></label>
        <span className="result-count"><strong>{formatNumber(audit.data?.total)}</strong> {t("common.total").toLowerCase()}</span>
      </section>
      <section className="panel table-panel">
        {audit.isPending ? <LoadingState rows={8} /> : audit.isError ? <ErrorState error={audit.error} onRetry={() => void audit.refetch()} /> : !visible.length ? <EmptyState title={t("auditPage.noAudit")} icon={ClipboardCheck} /> : (
          <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.time")}</th><th>{t("common.actor")}</th><th>{t("common.action")}</th><th>{t("auditPage.resource")}</th><th>{t("common.outcome")}</th><th>{t("auditPage.ipAddress")}</th><th /></tr></thead><tbody>
            {visible.map((record) => <tr key={record.id} className="clickable-row" tabIndex={0} onClick={() => setSelected(record)} onKeyDown={(event) => event.key === "Enter" && setSelected(record)}>
              <td className="nowrap"><strong>{formatDateTime(record.timestamp || record.created_at)}</strong><small>{record.id}</small></td>
              <td className="primary-cell"><strong>{record.actor || record.actor_id || t("common.unknown")}</strong><small>{record.actor_id || ""}</small></td>
              <td><Tag tone="accent">{record.action || t("common.unknown")}</Tag></td><td><strong>{record.resource_type || "—"}</strong><small className="block-small">{record.resource_id || ""}</small></td><td><StatusBadge value={record.outcome} /></td><td className="mono-small">{record.ip_address || "—"}</td><td><TableAction /></td>
            </tr>)}
          </tbody></table></div>
        )}
      </section>
      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.action || t("auditPage.title")} eyebrow={selected?.id} wide>
        {selected && <div className="detail-stack">
          <div className="drawer-lead"><StatusBadge value={selected.outcome} /><strong>{selected.action || t("common.unknown")}</strong></div>
          <dl className="detail-grid"><DetailRow label={t("common.time")}>{formatFullDateTime(selected.timestamp || selected.created_at)}</DetailRow><DetailRow label={t("common.actor")}>{selected.actor || selected.actor_id || "—"}</DetailRow><DetailRow label={t("auditPage.resource")}>{[selected.resource_type, selected.resource_id].filter(Boolean).join(" / ") || "—"}</DetailRow><DetailRow label={t("auditPage.ipAddress")}>{selected.ip_address || "—"}</DetailRow><DetailRow label={t("auditPage.traceId")}>{selected.trace_id ? <code>{selected.trace_id}</code> : "—"}</DetailRow><DetailRow label="Tenant">{selected.tenant_id || "—"}</DetailRow></dl>
          <section className="detail-section"><h3>{t("auditPage.payload")}</h3><JsonBlock value={selected.details ?? selected} /></section>
          <div className="integrity-note"><Fingerprint size={20} /><div><strong>{t("auditPage.eyebrow")}</strong><span>{selected.id}</span></div></div>
        </div>}
      </Drawer>
    </div>
  );
}
