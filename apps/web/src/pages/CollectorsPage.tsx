import { useDeferredValue, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { RadioTower, Search } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { CollectorDto } from "../api/types";
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

export default function CollectorsPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [health, setHealth] = useState("");
  const [selected, setSelected] = useState<CollectorDto | null>(null);
  const deferredSearch = useDeferredValue(search);
  const collectors = useQuery({ queryKey: ["collectors"], queryFn: ({ signal }) => api.collectors(signal), refetchInterval: 30_000 });
  const visible = useMemo(() => (collectors.data?.items || []).filter((collector) => {
    const text = [collector.collector_id, collector.name, collector.type, collector.auth_subject, collector.version, collector.observed_ip, ...(collector.capabilities || [])]
      .filter(Boolean).join(" ").toLowerCase();
    return (!health || collector.health === health) && (!deferredSearch || text.includes(deferredSearch.toLowerCase()));
  }), [collectors.data?.items, deferredSearch, health]);

  return (
    <div className="page">
      <PageHeader eyebrow={t("collectorsPage.eyebrow")} title={t("collectorsPage.title")} subtitle={t("collectorsPage.subtitle")} />
      <section className="filter-bar panel">
        <label className="search-field grow"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("collectorsPage.searchPlaceholder")} /></label>
        <label className="select-field"><select value={health} onChange={(event) => setHealth(event.target.value)}><option value="">{t("collectorsPage.health")}: {t("common.all")}</option><option value="ONLINE">ONLINE</option><option value="OFFLINE">OFFLINE</option><option value="NEVER_SEEN">NEVER SEEN</option><option value="REVOKED">REVOKED</option></select></label>
        <span className="result-count"><strong>{formatNumber(collectors.data?.total)}</strong> {t("common.total").toLowerCase()}</span>
      </section>
      <section className="panel table-panel">
        {collectors.isPending ? <LoadingState rows={6} /> : collectors.isError ? <ErrorState error={collectors.error} onRetry={() => void collectors.refetch()} /> : !visible.length ? <EmptyState title={t("collectorsPage.noCollectors")} icon={RadioTower} /> : (
          <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("collectorsPage.health")}</th><th>{t("common.source")}</th><th>{t("collectorsPage.type")}</th><th>{t("common.version")}</th><th>{t("collectorsPage.lastSeen")}</th><th>{t("collectorsPage.queue")}</th><th /></tr></thead><tbody>
            {visible.map((collector) => <tr key={collector.collector_id} className="clickable-row" tabIndex={0} onClick={() => setSelected(collector)} onKeyDown={(event) => event.key === "Enter" && setSelected(collector)}>
              <td><StatusBadge value={collector.health} /></td>
              <td className="primary-cell"><strong>{collector.name}</strong><small>{collector.collector_id} · {collector.observed_ip || t("common.notAvailable")}</small></td>
              <td><Tag tone="accent">{collector.type}</Tag></td><td>{collector.version || "—"}</td><td className="nowrap">{collector.last_seen_at ? formatDateTime(collector.last_seen_at) : t("collectorsPage.neverSeen")}</td>
              <td><strong>{formatNumber(Number(collector.health_metadata?.queue_depth || 0))}</strong></td><td><TableAction /></td>
            </tr>)}
          </tbody></table></div>
        )}
      </section>
      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.name || ""} eyebrow={selected?.collector_id}>
        {selected && <div className="detail-stack">
          <div className="drawer-lead"><StatusBadge value={selected.health} /><StatusBadge value={selected.state} /><strong>{selected.type}</strong></div>
          <dl className="detail-grid"><DetailRow label={t("collectorsPage.subject")}>{selected.auth_subject || "—"}</DetailRow><DetailRow label={t("common.version")}>{selected.version || "—"}</DetailRow><DetailRow label={t("collectorsPage.observedIp")}>{selected.observed_ip || "—"}</DetailRow><DetailRow label={t("collectorsPage.lastSeen")}>{selected.last_seen_at ? formatFullDateTime(selected.last_seen_at) : t("collectorsPage.neverSeen")}</DetailRow><DetailRow label={t("common.created")}>{formatFullDateTime(selected.created_at)}</DetailRow><DetailRow label={t("common.updated")}>{formatFullDateTime(selected.updated_at)}</DetailRow></dl>
          <section className="detail-section"><h3>{t("collectorsPage.capabilities")}</h3><div className="tag-list">{selected.capabilities?.length ? selected.capabilities.map((capability) => <Tag key={capability}>{capability}</Tag>) : <span className="muted">{t("common.noData")}</span>}</div></section>
          <details className="raw-details"><summary>{t("collectorsPage.healthMetadata")}</summary><JsonBlock value={selected.health_metadata || {}} /></details>
        </div>}
      </Drawer>
    </div>
  );
}
