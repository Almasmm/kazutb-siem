import { useDeferredValue, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, RadioTower, Search } from "lucide-react";
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
import { sourceLagSeconds } from "../collectors/sourceHealth";
import {
  backlogView,
  collectorOperational,
  collectorSources,
  fleetSummary,
  formatBytes,
  formatDuration,
  formatRate,
  operationalState,
} from "../collectors/operational";

// Operational telemetry moves continuously, so the page polls rather than
// waiting for a manual refresh. Ten seconds keeps a draining backlog visibly
// counting down without hammering the API.
const OPERATIONAL_REFRESH_MS = 10_000;

export default function CollectorsPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [state, setState] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const deferredSearch = useDeferredValue(search);

  const collectors = useQuery({
    queryKey: ["collectors"],
    queryFn: ({ signal }) => api.collectors(signal),
    refetchInterval: OPERATIONAL_REFRESH_MS,
  });

  const items = useMemo(() => collectors.data?.items || [], [collectors.data?.items]);
  const summary = useMemo(() => fleetSummary(undefined, items), [items]);

  const visible = useMemo(() => items.filter((collector) => {
    const text = [collector.collector_id, collector.name, collector.type, collector.auth_subject,
      collector.version, collector.observed_ip, ...(collector.capabilities || [])]
      .filter(Boolean).join(" ").toLowerCase();
    return (!state || operationalState(collector) === state)
      && (!deferredSearch || text.includes(deferredSearch.toLowerCase()));
  }), [items, deferredSearch, state]);

  // Keeping the selection by id rather than by object means the drawer keeps
  // updating from each poll instead of freezing on the row that was clicked.
  const selected = useMemo(
    () => items.find((collector) => collector.collector_id === selectedId) || null,
    [items, selectedId],
  );

  return (
    <div className="page">
      <PageHeader eyebrow={t("collectorsPage.eyebrow")} title={t("collectorsPage.title")} subtitle={t("collectorsPage.subtitle")} />

      <section className="metrics-grid compact">
        <FleetTile label={t("collectorsPage.endpoints")} value={formatNumber(summary.total)} tone="default" />
        <FleetTile label={t("collectorsPage.healthy")} value={formatNumber(summary.healthy)} tone={summary.healthy ? "good" : "default"} />
        <FleetTile label={t("collectorsPage.degraded")} value={formatNumber(summary.degraded)} tone={summary.degraded ? "warning" : "good"} />
        <FleetTile label={t("collectorsPage.offline")} value={formatNumber(summary.offline)} tone={summary.offline ? "critical" : "good"} />
        <FleetTile
          label={t("collectorsPage.backlog")}
          value={formatNumber(summary.backlog_events)}
          detail={formatBytes(summary.backlog_bytes)}
          tone={summary.backlog_events > 0 ? "warning" : "good"}
        />
        <FleetTile
          label={t("collectorsPage.throughput")}
          value={`${formatRate(summary.delivery_rate_eps)} ${t("collectorsPage.epsShort")}`}
          detail={t("collectorsPage.collectedVsDelivered", {
            collected: formatRate(summary.collection_rate_eps),
            delivered: formatRate(summary.delivery_rate_eps),
          })}
          tone="default"
        />
      </section>

      <section className="filter-bar panel">
        <label className="search-field grow"><Search size={17} />
          <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("collectorsPage.searchPlaceholder")} />
        </label>
        <label className="select-field">
          <select value={state} onChange={(event) => setState(event.target.value)}>
            <option value="">{t("collectorsPage.status")}: {t("common.all")}</option>
            <option value="HEALTHY">HEALTHY</option>
            <option value="DEGRADED">DEGRADED</option>
            <option value="OFFLINE">OFFLINE</option>
            <option value="NEVER_SEEN">NEVER SEEN</option>
            <option value="REVOKED">REVOKED</option>
          </select>
        </label>
        <span className="result-count"><strong>{formatNumber(collectors.data?.total)}</strong> {t("common.total").toLowerCase()}</span>
        <span className="result-count muted">{t("collectorsPage.autoRefresh", { seconds: OPERATIONAL_REFRESH_MS / 1000 })}</span>
      </section>

      <section className="panel table-panel">
        {collectors.isPending ? <LoadingState rows={6} />
          : collectors.isError ? <ErrorState error={collectors.error} onRetry={() => void collectors.refetch()} />
          : !visible.length ? <EmptyState title={t("collectorsPage.noCollectors")} icon={RadioTower} />
          : (
            <div className="table-scroll"><table className="data-table"><thead><tr>
              <th>{t("collectorsPage.status")}</th>
              <th>{t("common.source")}</th>
              <th>{t("collectorsPage.osVersion")}</th>
              <th>{t("collectorsPage.sources")}</th>
              <th>{t("collectorsPage.eps")}</th>
              <th>{t("collectorsPage.queue")}</th>
              <th>{t("collectorsPage.lastSeen")}</th>
              <th />
            </tr></thead><tbody>
              {visible.map((collector) => <CollectorRow key={collector.collector_id} collector={collector} onOpen={() => setSelectedId(collector.collector_id)} />)}
            </tbody></table></div>
          )}
      </section>

      <Drawer open={Boolean(selected)} onClose={() => setSelectedId(null)} title={selected?.name || ""} eyebrow={selected?.collector_id}>
        {selected && <CollectorDetail collector={selected} />}
      </Drawer>
    </div>
  );
}

function FleetTile({ label, value, detail, tone }: { label: string; value: string; detail?: string; tone: string }) {
  return (
    <article className={`metric-card tone-${tone}`}>
      <span className="metric-label">{label}</span>
      <strong className="metric-value">{value}</strong>
      {detail && <small className="metric-detail">{detail}</small>}
    </article>
  );
}

function CollectorRow({ collector, onOpen }: { collector: CollectorDto; onOpen: () => void }) {
  const { t } = useTranslation();
  const operational = collectorOperational(collector);
  const backlog = backlogView(collector);
  const state = operationalState(collector);
  const sources = collectorSources(collector);
  const degraded = sources.filter((source) => source.state === "DEGRADED").length;

  return (
    <tr className="clickable-row" tabIndex={0} onClick={onOpen} onKeyDown={(event) => event.key === "Enter" && onOpen()}>
      <td>
        <StatusBadge value={state} />
        {/* Connectivity is shown next to telemetry state so ONLINE is never
            mistaken for "working". */}
        {operational && operational.connectivity !== state && <small className="muted block">{operational.connectivity}</small>}
      </td>
      <td className="primary-cell">
        <strong>{collector.name}</strong>
        <small>{collector.collector_id} · {collector.observed_ip || t("common.notAvailable")}</small>
      </td>
      <td>
        {collector.type ? <Tag tone="accent">{collector.type}</Tag> : "—"}
        <small className="muted block">{collector.version || "—"}</small>
      </td>
      <td>
        {sources.length ? <>{formatNumber(sources.length - degraded)}/{formatNumber(sources.length)}
          {degraded > 0 && <small className="danger block">{t("collectorsPage.sourcesDegraded", { count: degraded })}</small>}</> : "—"}
      </td>
      <td title={t("collectorsPage.epsTooltip")}>
        <strong>{formatRate(operational?.delivery_rate_eps ?? 0)}</strong>
        <small className="muted block">{t("collectorsPage.collected")} {formatRate(operational?.collection_rate_eps ?? 0)}</small>
      </td>
      <td title={backlog ? `${backlog.depth} events / ${backlog.bytes} bytes` : undefined}>
        <strong className={backlog?.growing ? "danger" : undefined}>{formatNumber(backlog?.depth ?? 0)}</strong>
        <small className="muted block">{formatBytes(backlog?.bytes ?? 0)}</small>
      </td>
      <td className="nowrap">{collector.last_seen_at ? formatDateTime(collector.last_seen_at) : t("collectorsPage.neverSeen")}</td>
      <td><TableAction /></td>
    </tr>
  );
}

function CollectorDetail({ collector }: { collector: CollectorDto }) {
  const { t } = useTranslation();
  const operational = collectorOperational(collector);
  const backlog = backlogView(collector);
  const sources = collectorSources(collector);
  const state = operationalState(collector);

  return (
    <div className="detail-stack">
      <div className="drawer-lead">
        <StatusBadge value={state} />
        {operational && <StatusBadge value={operational.connectivity} />}
        {operational && <StatusBadge value={operational.telemetry} />}
        <strong>{collector.type}</strong>
      </div>

      {operational?.reasons?.length ? (
        <div className="callout warning">
          <AlertTriangle size={16} />
          <div>
            <strong>{t("collectorsPage.degradedBecause")}</strong>
            <ul>{operational.reasons.map((reason) => <li key={reason}>{t(`collectorsPage.reason.${reason}`, { defaultValue: reason })}</li>)}</ul>
          </div>
        </div>
      ) : null}

      <section className="detail-section">
        <h3>{t("collectorsPage.overview")}</h3>
        <dl className="detail-grid">
          <DetailRow label={t("collectorsPage.subject")}>{collector.auth_subject || "—"}</DetailRow>
          <DetailRow label={t("common.version")}>{collector.version || "—"}</DetailRow>
          <DetailRow label={t("collectorsPage.observedIp")}>{collector.observed_ip || "—"}</DetailRow>
          <DetailRow label={t("collectorsPage.tenant")}>{collector.tenant_id || "—"}</DetailRow>
          <DetailRow label={t("collectorsPage.lastSeen")}>{collector.last_seen_at ? formatFullDateTime(collector.last_seen_at) : t("collectorsPage.neverSeen")}</DetailRow>
          <DetailRow label={t("collectorsPage.uptime")}>{formatDuration(operational?.uptime_seconds)}</DetailRow>
          <DetailRow label={t("common.created")}>{formatFullDateTime(collector.created_at)}</DetailRow>
          <DetailRow label={t("common.updated")}>{formatFullDateTime(collector.updated_at)}</DetailRow>
        </dl>
      </section>

      {backlog && (
        <section className="detail-section">
          <h3>{t("collectorsPage.queueState")}</h3>
          <dl className="detail-grid">
            <DetailRow label={t("collectorsPage.queueDepth")}><span title={String(backlog.depth)}>{formatNumber(backlog.depth)}</span></DetailRow>
            <DetailRow label={t("collectorsPage.queueBytes")}><span title={`${backlog.bytes} B`}>{formatBytes(backlog.bytes)}</span></DetailRow>
            <DetailRow label={t("collectorsPage.oldestEvent")}>{formatDuration(backlog.oldestAgeSeconds)}</DetailRow>
            <DetailRow label={t("collectorsPage.collectionRate")}>{formatRate(backlog.collectionRate)} {t("collectorsPage.epsShort")}</DetailRow>
            <DetailRow label={t("collectorsPage.deliveryRate")}>{formatRate(backlog.deliveryRate)} {t("collectorsPage.epsShort")}</DetailRow>
            <DetailRow label={t("collectorsPage.netBacklog")}>
              <span className={backlog.growing ? "danger" : backlog.draining ? "good" : undefined}>
                {backlog.netRate > 0 ? "+" : ""}{formatRate(backlog.netRate)} {t("collectorsPage.epsShort")}
                {" · "}
                {backlog.growing ? t("collectorsPage.backlogGrowing") : backlog.draining ? t("collectorsPage.backlogDraining") : t("collectorsPage.backlogSteady")}
              </span>
            </DetailRow>
            {backlog.drainEtaSeconds !== null && <DetailRow label={t("collectorsPage.drainEta")}>{formatDuration(backlog.drainEtaSeconds)}</DetailRow>}
            <DetailRow label={t("collectorsPage.eventsDelivered")}>{formatNumber(operational?.events_delivered_total ?? 0)}</DetailRow>
            <DetailRow label={t("collectorsPage.sendFailures")}>{formatNumber(operational?.send_failures_total ?? 0)}</DetailRow>
          </dl>
          {operational?.last_send_error && <p className="danger small">{operational.last_send_error}</p>}
        </section>
      )}

      <section className="detail-section">
        <h3>{t("collectorsPage.sourceHealth")}</h3>
        {sources.length ? (
          <div className="table-scroll"><table className="data-table"><thead><tr>
            <th>{t("collectorsPage.state")}</th><th>{t("common.source")}</th><th>{t("collectorsPage.lastSuccess")}</th>
            <th>{t("collectorsPage.lag")}</th><th>{t("collectorsPage.checkpoint")}</th><th>{t("collectorsPage.events")}</th>
            <th>{t("collectorsPage.errors")}</th>
          </tr></thead><tbody>
            {sources.map((source) => {
              const lag = sourceLagSeconds(source);
              return <tr key={source.name}>
                <td><StatusBadge value={source.state} /></td>
                <td className="primary-cell">
                  <strong>{source.channel || source.name}</strong>
                  {source.last_error && <small className="danger">{source.last_error}</small>}
                  {source.next_attempt_at && <small className="muted">{t("collectorsPage.retryAt", { time: formatDateTime(source.next_attempt_at) })}</small>}
                </td>
                <td className="nowrap">{source.last_success_at ? formatDateTime(source.last_success_at) : t("common.notAvailable")}</td>
                <td className="nowrap">{formatDuration(lag)}</td>
                <td>{formatNumber(source.checkpoint)}</td>
                <td>
                  {formatNumber(source.events_read)}
                  {source.quarantined ? <small className="danger block">{formatNumber(source.quarantined)} {t("collectorsPage.quarantined")}</small> : null}
                </td>
                <td>{formatNumber(source.error_count)}</td>
              </tr>;
            })}
          </tbody></table></div>
        ) : <EmptyState title={t("collectorsPage.noSources")} icon={RadioTower} />}
      </section>

      <section className="detail-section">
        <h3>{t("collectorsPage.capabilities")}</h3>
        <div className="tag-list">
          {collector.capabilities?.length
            ? collector.capabilities.map((capability) => <Tag key={capability}>{capability}</Tag>)
            : <span className="muted">{t("common.noData")}</span>}
        </div>
      </section>

      <details className="raw-details"><summary>{t("collectorsPage.healthMetadata")}</summary><JsonBlock value={collector.health_metadata || {}} /></details>
    </div>
  );
}
