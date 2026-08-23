import { useDeferredValue, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, History, Radio, Search, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { ThreatIndicatorDto } from "../api/types";
import { DetailRow, Drawer, EmptyState, ErrorState, InlineNotice, LoadingState, MetricCard, PageHeader, StatusBadge, TableAction, Tag } from "../components/ui";
import { formatDateTime, formatFullDateTime, formatNumber } from "../utils/format";

export default function ThreatIntelPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [type, setType] = useState("");
  const [state, setState] = useState("");
  const [selected, setSelected] = useState<ThreatIndicatorDto | null>(null);
  const deferredSearch = useDeferredValue(search);
  const feeds = useQuery({ queryKey: ["threat-feeds"], queryFn: ({ signal }) => api.threatFeeds(signal) });
  const indicators = useQuery({
    queryKey: ["threat-indicators", deferredSearch, type, state],
    queryFn: ({ signal }) => api.threatIndicators({ q: deferredSearch, type, state, limit: 500 }, signal),
  });
  const matches = useQuery({ queryKey: ["threat-matches"], queryFn: ({ signal }) => api.threatMatches({ limit: 500 }, signal), refetchInterval: 30_000 });
  const retrosearch = useMutation({
    mutationFn: (id: string) => api.retrosearchThreatIndicator(id, { lookback_seconds: 7 * 24 * 60 * 60, limit: 500 }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["threat-matches"] }),
  });
  const feedNames = useMemo(() => new Map((feeds.data?.items || []).map((feed) => [feed.feed_id, feed.name])), [feeds.data?.items]);
  const selectedMatches = (matches.data?.items || []).filter((match) => match.indicator_id === selected?.indicator_id);
  const activeCount = (indicators.data?.items || []).filter((item) => item.state === "ACTIVE").length;

  return <div className="page">
    <PageHeader eyebrow={t("threatIntelPage.eyebrow")} title={t("threatIntelPage.title")} subtitle={t("threatIntelPage.subtitle")} />
    <section className="metrics-grid compact-metrics">
      <MetricCard label={t("threatIntelPage.indicators")} value={indicators.data?.total || 0} icon={Crosshair} />
      <MetricCard label={t("threatIntelPage.active")} value={activeCount} icon={ShieldCheck} tone="good" />
      <MetricCard label={t("threatIntelPage.matches")} value={matches.data?.total || 0} icon={History} tone={(matches.data?.total || 0) > 0 ? "warning" : "good"} />
      <MetricCard label={t("threatIntelPage.feeds")} value={feeds.data?.total || 0} icon={Radio} />
    </section>
    <section className="filter-bar panel">
      <label className="search-field grow"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("threatIntelPage.searchPlaceholder")} /></label>
      <label className="select-field"><select value={type} onChange={(event) => setType(event.target.value)}><option value="">{t("threatIntelPage.type")}: {t("common.all")}</option><option>IPV4</option><option>DOMAIN</option><option>URL</option><option>HASH</option><option>EMAIL</option></select></label>
      <label className="select-field"><select value={state} onChange={(event) => setState(event.target.value)}><option value="">{t("common.status")}: {t("common.all")}</option><option>ACTIVE</option><option>DISABLED</option><option>REVOKED</option><option>EXPIRED</option></select></label>
    </section>
    <section className="panel table-panel">
      {indicators.isPending ? <LoadingState rows={8} /> : indicators.isError ? <ErrorState error={indicators.error} onRetry={() => void indicators.refetch()} /> : !indicators.data.items.length ? <EmptyState title={t("threatIntelPage.noIndicators")} icon={Crosshair} /> :
        <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("threatIntelPage.indicator")}</th><th>{t("common.source")}</th><th>{t("common.confidence")}</th><th>{t("threatIntelPage.reputation")}</th><th>{t("threatIntelPage.lastSeen")}</th><th /></tr></thead><tbody>{indicators.data.items.map((item) => <tr key={item.indicator_id} className="clickable-row" onClick={() => setSelected(item)}><td><StatusBadge value={item.state} /></td><td className="primary-cell"><strong>{item.value}</strong><small>{item.type} · {item.indicator_id}</small></td><td>{feedNames.get(item.feed_id) || item.source || item.feed_id}</td><td><strong>{item.confidence}%</strong></td><td><Tag tone={item.reputation?.toUpperCase().includes("MAL") ? "warning" : "neutral"}>{item.reputation || "—"}</Tag></td><td>{formatDateTime(item.last_seen)}</td><td><TableAction /></td></tr>)}</tbody></table></div>}
    </section>
    <Drawer open={Boolean(selected)} onClose={() => { setSelected(null); retrosearch.reset(); }} wide title={selected?.value || ""} eyebrow={selected?.indicator_id} footer={selected && <button className="button primary" type="button" disabled={retrosearch.isPending} onClick={() => retrosearch.mutate(selected.indicator_id)}><History size={16} />{t("threatIntelPage.retrosearch")}</button>}>
      {selected && <div className="detail-stack"><div className="drawer-lead"><StatusBadge value={selected.state} /><Tag tone="accent">{selected.type}</Tag><strong>{selected.value}</strong></div><p className="lead-description">{selected.description || t("common.notAvailable")}</p>
        <dl className="detail-grid"><DetailRow label={t("common.source")}>{feedNames.get(selected.feed_id) || selected.source || selected.feed_id}</DetailRow><DetailRow label={t("common.confidence")}>{selected.confidence}%</DetailRow><DetailRow label={t("threatIntelPage.reputation")}>{selected.reputation || "—"}</DetailRow><DetailRow label={t("threatIntelPage.campaign")}>{selected.campaign || "—"}</DetailRow><DetailRow label={t("threatIntelPage.lastSeen")}>{formatFullDateTime(selected.last_seen)}</DetailRow><DetailRow label={t("common.updated")}>{formatFullDateTime(selected.updated_at)}</DetailRow></dl>
        <section className="detail-section"><h3>{t("threatIntelPage.context")}</h3><div className="tag-list">{[...(selected.tags || []), ...(selected.threat_actors || []), selected.malware].filter(Boolean).map((value) => <Tag key={value}>{value}</Tag>)}</div></section>
        {retrosearch.isError && <ErrorState error={retrosearch.error} compact />}{retrosearch.data && <InlineNotice tone={retrosearch.data.partial ? "warning" : "success"}>{t("threatIntelPage.retroResult", { matched: formatNumber(retrosearch.data.events_matched), candidates: formatNumber(retrosearch.data.candidate_events) })}</InlineNotice>}
        <section className="detail-section"><h3>{t("threatIntelPage.matches")}</h3>{matches.isPending ? <LoadingState rows={3} compact /> : !selectedMatches.length ? <EmptyState title={t("threatIntelPage.noMatches")} icon={ShieldCheck} /> : <div className="compact-list">{selectedMatches.map((match) => <div key={match.match_id}><div><strong>{match.event_id}</strong><small>{match.matched_field}: {match.matched_value}</small></div><span>{formatDateTime(match.matched_at)}</span></div>)}</div>}</section>
      </div>}
    </Drawer>
  </div>;
}
