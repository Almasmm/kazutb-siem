import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Cable, Cpu, Laptop, Network, Search, ShieldAlert, UserRound } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { EntityDto } from "../api/types";
import { DetailRow, Drawer, EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, RiskScore, TableAction } from "../components/ui";
import { formatDateTime, formatFullDateTime } from "../utils/format";

const entityKinds = ["", "DEVICE", "USER", "IP", "PROCESS", "APPLICATION", "SERVICE"];

export default function AssetsPage() {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("");
  const [minimumRisk, setMinimumRisk] = useState("0");
  const [selected, setSelected] = useState<EntityDto | null>(null);
  const entities = useQuery({ queryKey: ["entities", query, kind, minimumRisk], queryFn: ({ signal }) => api.entities({ q: query, type: kind, minimum_risk: Number(minimumRisk), limit: 500 }, signal) });
  const assets = useQuery({ queryKey: ["asset-metrics"], queryFn: ({ signal }) => api.assets({ limit: 500 }, signal) });
  const graph = useQuery({ queryKey: ["entity-graph", selected?.entity_id], queryFn: ({ signal }) => api.entityGraph(selected!.entity_id, 2, signal), enabled: Boolean(selected) });
  const items = entities.data?.items || [];
  const risky = items.filter((item) => item.risk_score >= 70).length;
  const entityByID = useMemo(() => new Map((graph.data?.entities || []).map((entity) => [entity.entity_id, entity])), [graph.data]);

  const selectRelated = (entityID: string) => {
    const entity = entityByID.get(entityID);
    if (entity) setSelected(entity);
  };

  return <div className="page entity-page">
    <PageHeader eyebrow={t("assetsPage.eyebrow")} title={t("assetsPage.title")} subtitle={t("assetsPage.subtitle")} />
    <section className="metrics-grid compact-metrics"><MetricCard label={t("assetsPage.entities")} value={entities.data?.total || 0} icon={Network} /><MetricCard label={t("assetsPage.managedAssets")} value={assets.data?.total || 0} icon={Laptop} /><MetricCard label={t("assetsPage.highRisk")} value={risky} icon={ShieldAlert} tone={risky ? "critical" : "good"} /><MetricCard label={t("assetsPage.observations")} value={items.reduce((total, item) => total + item.observation_count, 0)} icon={Cable} /></section>
    <section className="filter-bar panel"><label className="search-field grow"><Search size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("assetsPage.searchPlaceholder")} /></label><label className="select-field"><select value={kind} onChange={(event) => setKind(event.target.value)}>{entityKinds.map((value) => <option key={value || "all"} value={value}>{value || `${t("assetsPage.entityType")}: ${t("common.all")}`}</option>)}</select></label><label className="select-field"><select value={minimumRisk} onChange={(event) => setMinimumRisk(event.target.value)}><option value="0">{t("assetsPage.minimumRisk")}: 0</option><option value="40">40+</option><option value="70">70+</option><option value="90">90+</option></select></label></section>
    <section className="panel table-panel">{entities.isPending ? <LoadingState rows={9} /> : entities.isError ? <ErrorState error={entities.error} onRetry={() => void entities.refetch()} /> : !items.length ? <EmptyState title={t("assetsPage.noEntities")} icon={Boxes} /> : <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("assetsPage.entityType")}</th><th>{t("common.risk")}</th><th>{t("assetsPage.entity")}</th><th>{t("assetsPage.observations")}</th><th>{t("assetsPage.firstSeen")}</th><th>{t("assetsPage.lastSeen")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.entity_id} className="clickable-row" onClick={() => setSelected(item)}><td><span className={`entity-kind kind-${item.entity_type.toLowerCase()}`}>{entityIcon(item.entity_type)}{item.entity_type}</span></td><td><RiskScore value={item.risk_score} compact /></td><td className="primary-cell"><strong>{item.display_name}</strong><small>{item.label || item.natural_key}</small></td><td>{item.observation_count.toLocaleString()}</td><td>{formatDateTime(item.first_seen)}</td><td>{formatDateTime(item.last_seen)}</td><td><TableAction /></td></tr>)}</tbody></table></div>}</section>
    <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} wide title={selected?.display_name || ""} eyebrow={selected ? `${selected.entity_type} · ${selected.entity_id}` : ""}>
      {selected && <div className="detail-stack"><div className="entity-drawer-lead"><span className={`entity-orb kind-${selected.entity_type.toLowerCase()}`}>{entityIcon(selected.entity_type, 23)}</span><div><span>{t("assetsPage.riskContext")}</span><strong>{selected.label || selected.natural_key}</strong></div><RiskScore value={selected.risk_score} /></div><dl className="detail-grid"><DetailRow label={t("assetsPage.naturalKey")}>{selected.natural_key}</DetailRow><DetailRow label={t("assetsPage.observations")}>{selected.observation_count.toLocaleString()}</DetailRow><DetailRow label={t("assetsPage.firstSeen")}>{formatFullDateTime(selected.first_seen)}</DetailRow><DetailRow label={t("assetsPage.lastSeen")}>{formatFullDateTime(selected.last_seen)}</DetailRow></dl>
        <section className="detail-section"><h3>{t("assetsPage.relationshipGraph")}</h3>{graph.isPending ? <LoadingState rows={5} compact /> : graph.isError ? <ErrorState error={graph.error} compact /> : graph.data && <><div className="entity-graph-summary"><div className="graph-root"><span>{entityIcon(graph.data.root.entity_type, 22)}</span><strong>{graph.data.root.display_name}</strong><small>{graph.data.root.entity_type}</small></div><div className="graph-stats"><strong>{graph.data.entities.length}</strong><span>{t("assetsPage.nodes")}</span><strong>{graph.data.relations.length}</strong><span>{t("assetsPage.relations")}</span></div></div><div className="relation-list">{graph.data.relations.map((relation) => { const source = entityByID.get(relation.source_entity_id); const target = entityByID.get(relation.target_entity_id); const related = relation.source_entity_id === selected.entity_id ? target : source; return <button type="button" key={relation.relation_id} onClick={() => related && selectRelated(related.entity_id)}><span className="relation-direction">{relation.relation_type}</span><div><strong>{source?.display_name || relation.source_entity_id}</strong><small>→ {target?.display_name || relation.target_entity_id}</small></div><em>{relation.observation_count}×</em></button>; })}</div></>}</section>
        {Object.keys(selected.attributes || {}).length > 0 && <section className="detail-section"><h3>{t("assetsPage.attributes")}</h3><dl className="detail-grid">{Object.entries(selected.attributes || {}).map(([key, value]) => <DetailRow key={key} label={key}>{value}</DetailRow>)}</dl></section>}
        <section className="detail-section"><h3>{t("assetsPage.eventPivots")}</h3><div className="event-pivots">{(graph.data?.event_ids || [selected.last_event_id]).filter(Boolean).map((eventID) => <Link key={eventID} to={`/hunt?q=${encodeURIComponent(eventID || "")}`}><Cpu size={15} /><span>{eventID}</span></Link>)}</div></section>
      </div>}
    </Drawer>
  </div>;
}

function entityIcon(kind: string, size = 14) {
  if (kind === "DEVICE" || kind === "SERVER") return <Laptop size={size} />;
  if (kind === "USER" || kind === "ACCOUNT") return <UserRound size={size} />;
  if (kind === "PROCESS") return <Cpu size={size} />;
  return <Network size={size} />;
}
