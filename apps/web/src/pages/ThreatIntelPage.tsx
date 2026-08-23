import { useDeferredValue, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, FlaskConical, History, Plus, Radio, RefreshCw, Search, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { ThreatIndicatorDto, ThreatIntelFeedDto } from "../api/types";
import { DetailRow, Drawer, EmptyState, ErrorState, InlineNotice, LoadingState, MetricCard, Modal, PageHeader, StatusBadge, TableAction, Tag } from "../components/ui";
import { formatDateTime, formatFullDateTime, formatNumber } from "../utils/format";

export default function ThreatIntelPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [type, setType] = useState("");
  const [state, setState] = useState("");
  const [selected, setSelected] = useState<ThreatIndicatorDto | null>(null);
  const [feedEditorOpen, setFeedEditorOpen] = useState(false);
  const [feedNotice, setFeedNotice] = useState("");
  const [feedForm, setFeedForm] = useState({ name: "", kind: "MISP", description: "", sourceUrl: "", authReference: "", refreshSeconds: 3600, confidence: 70, tags: "" });
  const deferredSearch = useDeferredValue(search);
  const session = useQuery({ queryKey: ["session"], queryFn: ({ signal }) => api.session(signal), staleTime: 5 * 60_000 });
  const feeds = useQuery({ queryKey: ["threat-feeds"], queryFn: ({ signal }) => api.threatFeeds(signal), refetchInterval: 15_000 });
  const indicators = useQuery({
    queryKey: ["threat-indicators", deferredSearch, type, state],
    queryFn: ({ signal }) => api.threatIndicators({ q: deferredSearch, type, state, limit: 500 }, signal),
  });
  const matches = useQuery({ queryKey: ["threat-matches"], queryFn: ({ signal }) => api.threatMatches({ limit: 500 }, signal), refetchInterval: 30_000 });
  const retrosearch = useMutation({
    mutationFn: (id: string) => api.retrosearchThreatIndicator(id, { lookback_seconds: 7 * 24 * 60 * 60, limit: 500 }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["threat-matches"] }),
  });
  const createFeed = useMutation({
    mutationFn: () => api.createThreatFeed({ name: feedForm.name.trim(), kind: feedForm.kind, description: feedForm.description.trim(), source_url: feedForm.sourceUrl.trim(), auth_reference: feedForm.authReference.trim(), refresh_interval_seconds: feedForm.refreshSeconds, default_confidence: feedForm.confidence, tags: feedForm.tags.split(",").map((value) => value.trim()).filter(Boolean) }),
    onSuccess: () => { setFeedEditorOpen(false); setFeedNotice(t("threatIntelPage.feedCreated")); setFeedForm({ name: "", kind: "MISP", description: "", sourceUrl: "", authReference: "", refreshSeconds: 3600, confidence: 70, tags: "" }); void queryClient.invalidateQueries({ queryKey: ["threat-feeds"] }); },
  });
  const syncFeed = useMutation({ mutationFn: (feed: ThreatIntelFeedDto) => api.syncThreatFeed(feed.feed_id), onSuccess: () => { setFeedNotice(t("threatIntelPage.syncQueued")); void queryClient.invalidateQueries({ queryKey: ["threat-feeds"] }); } });
  const testFeed = useMutation({ mutationFn: (feed: ThreatIntelFeedDto) => api.testThreatFeed(feed.feed_id), onSuccess: (result) => { setFeedNotice(result.detail || result.status); void queryClient.invalidateQueries({ queryKey: ["threat-feeds"] }); } });
  const feedNames = useMemo(() => new Map((feeds.data?.items || []).map((feed) => [feed.feed_id, feed.name])), [feeds.data?.items]);
  const selectedMatches = (matches.data?.items || []).filter((match) => match.indicator_id === selected?.indicator_id);
  const activeCount = (indicators.data?.items || []).filter((item) => item.state === "ACTIVE").length;
  const canManageFeeds = Boolean(session.data?.permissions.includes("*") || session.data?.permissions.includes("ti.indicators.manage"));

  return <div className="page">
    <PageHeader eyebrow={t("threatIntelPage.eyebrow")} title={t("threatIntelPage.title")} subtitle={t("threatIntelPage.subtitle")} actions={canManageFeeds ? <button className="button primary" type="button" onClick={() => setFeedEditorOpen(true)}><Plus size={16} />{t("threatIntelPage.newFeed")}</button> : undefined} />
    <section className="metrics-grid compact-metrics">
      <MetricCard label={t("threatIntelPage.indicators")} value={indicators.data?.total || 0} icon={Crosshair} />
      <MetricCard label={t("threatIntelPage.active")} value={activeCount} icon={ShieldCheck} tone="good" />
      <MetricCard label={t("threatIntelPage.matches")} value={matches.data?.total || 0} icon={History} tone={(matches.data?.total || 0) > 0 ? "warning" : "good"} />
      <MetricCard label={t("threatIntelPage.feeds")} value={feeds.data?.total || 0} icon={Radio} />
    </section>
    {feedNotice && <InlineNotice tone="success">{feedNotice}</InlineNotice>}
    <section className="panel table-panel"><div className="panel-header"><div><span className="eyebrow">{t("threatIntelPage.feedControl")}</span><h2>{t("threatIntelPage.feeds")}</h2></div></div>
      {feeds.isPending ? <LoadingState rows={3} /> : feeds.isError ? <ErrorState error={feeds.error} compact /> : !feeds.data?.items.length ? <EmptyState title={t("threatIntelPage.noFeeds")} icon={Radio} /> : <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("common.name")}</th><th>{t("threatIntelPage.provider")}</th><th>{t("threatIntelPage.lastSync")}</th><th>{t("threatIntelPage.syncResult")}</th><th /></tr></thead><tbody>{feeds.data.items.map((feed) => <tr key={feed.feed_id}><td><StatusBadge value={feed.health_status || feed.sync_status} /></td><td className="primary-cell"><strong>{feed.name}</strong><small>{feed.source_url || t("common.notAvailable")}</small></td><td><Tag>{feed.kind}</Tag></td><td>{formatDateTime(feed.last_sync_at)}</td><td><strong>{feed.last_imported || 0}</strong><small>{t("threatIntelPage.syncCounts", { deduplicated: feed.last_deduplicated || 0, rejected: feed.last_rejected || 0 })}</small></td><td>{canManageFeeds && <div className="table-actions"><button className="icon-button" type="button" title={t("threatIntelPage.testFeed")} disabled={testFeed.isPending} onClick={() => testFeed.mutate(feed)}><FlaskConical size={15} /></button><button className="icon-button" type="button" title={t("threatIntelPage.syncNow")} disabled={syncFeed.isPending || feed.state !== "ACTIVE"} onClick={() => syncFeed.mutate(feed)}><RefreshCw size={15} /></button></div>}</td></tr>)}</tbody></table></div>}
      {(createFeed.isError || syncFeed.isError || testFeed.isError) && <ErrorState error={createFeed.error || syncFeed.error || testFeed.error} compact />}
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
    <Modal open={feedEditorOpen} onClose={() => setFeedEditorOpen(false)} title={t("threatIntelPage.createFeedTitle")} footer={<><button className="button ghost" type="button" onClick={() => setFeedEditorOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={!feedForm.name.trim() || !feedForm.sourceUrl.trim() || createFeed.isPending} onClick={() => createFeed.mutate()}><Radio size={16} />{t("common.create")}</button></>}>
      <div className="parser-form-grid"><label className="form-field"><span>{t("common.name")}</span><input value={feedForm.name} onChange={(event) => setFeedForm({ ...feedForm, name: event.target.value })} /></label><label className="form-field"><span>{t("threatIntelPage.provider")}</span><select value={feedForm.kind} onChange={(event) => setFeedForm({ ...feedForm, kind: event.target.value })}><option value="MISP">MISP</option><option value="OPENCTI">OPENCTI</option></select></label></div>
      <label className="form-field"><span>{t("common.description")}</span><textarea rows={3} value={feedForm.description} onChange={(event) => setFeedForm({ ...feedForm, description: event.target.value })} /></label>
      <label className="form-field"><span>{t("threatIntelPage.sourceUrl")}</span><input type="url" placeholder={feedForm.kind === "MISP" ? "https://misp.example.edu" : "https://opencti.example.edu"} value={feedForm.sourceUrl} onChange={(event) => setFeedForm({ ...feedForm, sourceUrl: event.target.value })} /></label>
      <label className="form-field"><span>{t("threatIntelPage.secretRef")}</span><input placeholder="env://KCSP_TI_FEED_SECRET_PROVIDER" value={feedForm.authReference} onChange={(event) => setFeedForm({ ...feedForm, authReference: event.target.value })} /><small>{t("threatIntelPage.secretRefHint")}</small></label>
      <div className="parser-form-grid"><label className="form-field"><span>{t("threatIntelPage.refreshSeconds")}</span><input type="number" min={60} max={604800} value={feedForm.refreshSeconds} onChange={(event) => setFeedForm({ ...feedForm, refreshSeconds: Number(event.target.value) })} /></label><label className="form-field"><span>{t("common.confidence")}</span><input type="number" min={0} max={100} value={feedForm.confidence} onChange={(event) => setFeedForm({ ...feedForm, confidence: Number(event.target.value) })} /></label></div>
      <label className="form-field"><span>{t("common.tags")}</span><input placeholder="university, csirt, tlp:amber" value={feedForm.tags} onChange={(event) => setFeedForm({ ...feedForm, tags: event.target.value })} /></label>
      {createFeed.isError && <ErrorState error={createFeed.error} compact />}
    </Modal>
  </div>;
}
