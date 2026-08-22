import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Braces, Clock3, FileSearch, Play, Search, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { EventDto, FindingDto } from "../api/types";
import {
  DetailRow,
  Drawer,
  EmptyState,
  ErrorState,
  JsonBlock,
  LoadingState,
  PageHeader,
  SeverityBadge,
  TableAction,
  Tag,
} from "../components/ui";
import { eventId, formatDateTime, formatFullDateTime, formatNumber, sourceLabel } from "../utils/format";

type Tab = "events" | "findings";
type Selection = { kind: "event"; value: EventDto } | { kind: "finding"; value: FindingDto } | null;

const ranges: Record<string, number> = {
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  "7d": 7 * 24 * 60 * 60_000,
};

function buildWindow(range: string) {
  const to = new Date();
  const from = new Date(to.getTime() - (ranges[range] || ranges["24h"]!));
  return { from: from.toISOString(), to: to.toISOString() };
}

export default function HuntPage() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>("events");
  const [draftQuery, setDraftQuery] = useState("");
  const [draftRange, setDraftRange] = useState("24h");
  const [searchRequest, setSearchRequest] = useState({ query: "", range: "24h", run: 0 });
  const [selection, setSelection] = useState<Selection>(null);
  const window = useMemo(() => buildWindow(searchRequest.range), [searchRequest]);

  const events = useQuery({
    queryKey: ["events", searchRequest],
    queryFn: ({ signal }) => api.events({ q: searchRequest.query, from: window.from, to: window.to, limit: 200, offset: 0 }, signal),
    enabled: tab === "events",
  });
  const findings = useQuery({
    queryKey: ["findings", searchRequest],
    queryFn: ({ signal }) => api.findings({ q: searchRequest.query, from: window.from, to: window.to, limit: 200, offset: 0 }, signal),
    enabled: tab === "findings",
  });

  const runSearch = () => setSearchRequest({ query: draftQuery.trim(), range: draftRange, run: Date.now() });
  const activeQuery = tab === "events" ? events : findings;
  const isSearching = activeQuery.isFetching;

  const examples = [
    { label: t("hunt.authFailures"), query: 'event.category = "authentication" and event.outcome = "failure"' },
    { label: t("hunt.powershell"), query: 'process.name = "powershell.exe"' },
    { label: t("hunt.privileged"), query: 'user.privilege = "administrator"' },
  ];

  return (
    <div className="page">
      <PageHeader eyebrow={t("hunt.eyebrow")} title={t("hunt.title")} subtitle={t("hunt.subtitle")} />

      <section className="query-console panel">
        <div className="query-toolbar"><label><Braces size={16} />{t("hunt.queryLabel")}</label><div className="query-examples"><span>{t("hunt.examples")}:</span>{examples.map((example) => <button key={example.label} type="button" onClick={() => setDraftQuery(example.query)}>{example.label}</button>)}</div></div>
        <textarea className="cql-editor" spellCheck={false} value={draftQuery} onChange={(event) => setDraftQuery(event.target.value)} onKeyDown={(event) => { if ((event.ctrlKey || event.metaKey) && event.key === "Enter") runSearch(); }} placeholder={t("hunt.queryPlaceholder")} aria-label={t("hunt.queryLabel")} />
        <div className="query-actions">
          <label className="select-field"><Clock3 size={16} /><select value={draftRange} onChange={(event) => setDraftRange(event.target.value)} aria-label={t("hunt.timeRange")}><option value="15m">{t("hunt.last15m")}</option><option value="1h">{t("hunt.last1h")}</option><option value="24h">{t("hunt.last24h")}</option><option value="7d">{t("hunt.last7d")}</option></select></label>
          <span className="keyboard-hint">Ctrl ↵</span>
          <button className="button primary" type="button" onClick={runSearch} disabled={isSearching}>{isSearching ? <span className="button-spinner" /> : <Play size={16} fill="currentColor" />}{t(isSearching ? "hunt.running" : "hunt.run")}</button>
        </div>
      </section>

      <section className="results-panel panel">
        <div className="result-tabs" role="tablist">
          <button type="button" role="tab" aria-selected={tab === "events"} className={tab === "events" ? "active" : ""} onClick={() => setTab("events")}><FileSearch size={16} />{t("hunt.eventsTab")}<span>{formatNumber(events.data?.total)}</span></button>
          <button type="button" role="tab" aria-selected={tab === "findings"} className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}><ShieldCheck size={16} />{t("hunt.findingsTab")}<span>{formatNumber(findings.data?.total)}</span></button>
          <div className="result-window">{formatDateTime(window.from)} → {formatDateTime(window.to)}</div>
        </div>

        {tab === "events" && (
          events.isPending ? <LoadingState rows={8} /> : events.isError ? <ErrorState error={events.error} onRetry={() => void events.refetch()} /> : !events.data.items.length ? <EmptyState title={t("hunt.noEvents")} description={t("hunt.queryReady")} icon={Search} /> : (
            <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.time")}</th><th>{t("common.severity")}</th><th>{t("hunt.eventClass")}</th><th>{t("common.user")}</th><th>{t("hunt.network")}</th><th>{t("common.source")}</th><th /></tr></thead><tbody>
              {events.data.items.map((event, index) => <tr key={`${eventId(event)}-${index}`} className="clickable-row" tabIndex={0} onClick={() => setSelection({ kind: "event", value: event })} onKeyDown={(keyEvent) => keyEvent.key === "Enter" && setSelection({ kind: "event", value: event })}>
                <td className="nowrap"><strong>{formatDateTime(event.event_time || event.ingest_time)}</strong><small>{eventId(event)}</small></td>
                <td><SeverityBadge value={event.severity} /></td>
                <td className="primary-cell"><strong>{event.activity_name || event.message || event.category || event.class_name || "—"}</strong><small>{event.category || event.class_name || ""}</small></td>
                <td>{event.user_name || "—"}</td><td><span className="mono-small">{event.src_ip || "—"} → {event.dst_ip || "—"}</span></td>
                <td>{sourceLabel(event.source, event.source_type)}</td><td><TableAction /></td>
              </tr>)}
            </tbody></table></div>
          )
        )}

        {tab === "findings" && (
          findings.isPending ? <LoadingState rows={8} /> : findings.isError ? <ErrorState error={findings.error} onRetry={() => void findings.refetch()} /> : !findings.data.items.length ? <EmptyState title={t("hunt.noFindings")} description={t("hunt.queryReady")} icon={ShieldCheck} /> : (
            <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.time")}</th><th>{t("common.severity")}</th><th>{t("common.title")}</th><th>{t("hunt.detectionRule")}</th><th>{t("common.asset")}</th><th>{t("common.confidence")}</th><th /></tr></thead><tbody>
              {findings.data.items.map((finding) => <tr key={finding.id} className="clickable-row" tabIndex={0} onClick={() => setSelection({ kind: "finding", value: finding })} onKeyDown={(event) => event.key === "Enter" && setSelection({ kind: "finding", value: finding })}>
                <td className="nowrap"><strong>{formatDateTime(finding.event_time || finding.created_at)}</strong><small>{finding.finding_id || finding.id}</small></td>
                <td><SeverityBadge value={finding.severity} /></td><td className="primary-cell"><strong>{finding.title || finding.description || finding.id}</strong><small>{finding.description || ""}</small></td>
                <td>{finding.rule_title || finding.rule_id || "—"}</td><td>{finding.asset_name || finding.user_name || "—"}</td><td>{finding.confidence != null ? `${finding.confidence}%` : "—"}</td><td><TableAction /></td>
              </tr>)}
            </tbody></table></div>
          )
        )}
      </section>

      <Drawer open={Boolean(selection)} onClose={() => setSelection(null)} wide title={selection?.kind === "event" ? t("hunt.normalizedEvent") : selection?.value.title || t("hunt.findingsTab")} eyebrow={selection?.kind === "event" ? eventId(selection.value) : selection?.value.id}>
        {selection?.kind === "event" && <div className="detail-stack">
          <div className="drawer-lead"><SeverityBadge value={selection.value.severity} /><strong>{selection.value.activity_name || selection.value.message || selection.value.category || selection.value.class_name || eventId(selection.value)}</strong></div>
          <dl className="detail-grid"><DetailRow label={t("common.time")}>{formatFullDateTime(selection.value.event_time)}</DetailRow><DetailRow label={t("common.source")}>{sourceLabel(selection.value.source, selection.value.source_type)}</DetailRow><DetailRow label={t("common.user")}>{selection.value.user_name || "—"}</DetailRow><DetailRow label={t("common.asset")}>{selection.value.device_name || "—"}</DetailRow><DetailRow label="Source IP">{selection.value.src_ip || "—"}</DetailRow><DetailRow label="Destination IP">{selection.value.dst_ip || "—"}</DetailRow></dl>
          <section className="detail-section"><h3>{t("common.rawData")}</h3><JsonBlock value={selection.value} /></section>
        </div>}
        {selection?.kind === "finding" && <div className="detail-stack">
          <div className="drawer-lead"><SeverityBadge value={selection.value.severity} /><strong>{selection.value.title || selection.value.id}</strong></div><p className="lead-description">{selection.value.description || t("common.notAvailable")}</p>
          <dl className="detail-grid"><DetailRow label={t("hunt.detectionRule")}>{selection.value.rule_title || selection.value.rule_id || "—"}</DetailRow><DetailRow label={t("common.time")}>{formatFullDateTime(selection.value.event_time || selection.value.created_at)}</DetailRow><DetailRow label={t("common.confidence")}>{selection.value.confidence != null ? `${selection.value.confidence}%` : "—"}</DetailRow><DetailRow label={t("common.risk")}>{selection.value.risk_score ?? "—"}</DetailRow><DetailRow label={t("common.asset")}>{selection.value.asset_name || "—"}</DetailRow><DetailRow label={t("common.user")}>{selection.value.user_name || "—"}</DetailRow></dl>
          <div className="tag-list">{selection.value.mitre_techniques?.map((technique) => <Tag key={technique} tone="accent">{technique}</Tag>)}</div>
          <details className="raw-details"><summary>{t("common.rawData")}</summary><JsonBlock value={selection.value} /></details>
        </div>}
      </Drawer>
    </div>
  );
}
