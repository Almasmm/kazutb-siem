import { useDeferredValue, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Radar, Search, ShieldCheck, ToggleLeft, ToggleRight } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { RuleDto } from "../api/types";
import {
  DetailRow,
  Drawer,
  EmptyState,
  ErrorState,
  JsonBlock,
  LoadingState,
  PageHeader,
  SeverityBadge,
  StatusBadge,
  TableAction,
  Tag,
} from "../components/ui";
import { formatDateTime, formatFullDateTime, formatNumber } from "../utils/format";

function ruleTitle(rule: RuleDto): string {
  return rule.title || rule.description || rule.rule_id || rule.id;
}

export default function RulesPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [enabled, setEnabled] = useState("");
  const [selected, setSelected] = useState<RuleDto | null>(null);
  const deferredSearch = useDeferredValue(search);
  const rules = useQuery({
    queryKey: ["rules", deferredSearch, enabled],
    queryFn: ({ signal }) => api.rules({ q: deferredSearch, enabled, limit: 200, offset: 0 }, signal),
  });
  const visible = useMemo(() => (rules.data?.items || []).filter((rule) => {
    const text = [rule.id, rule.rule_id, rule.title, rule.description, rule.owner, ...(rule.mitre_techniques || [])].filter(Boolean).join(" ").toLowerCase();
    const enabledMatches = !enabled || String(Boolean(rule.enabled)) === enabled;
    return enabledMatches && (!deferredSearch || text.includes(deferredSearch.toLowerCase()));
  }), [deferredSearch, enabled, rules.data?.items]);

  return (
    <div className="page">
      <PageHeader eyebrow={t("rulesPage.eyebrow")} title={t("rulesPage.title")} subtitle={t("rulesPage.subtitle")} />
      <section className="filter-bar panel">
        <label className="search-field grow"><Search size={17} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("rulesPage.searchPlaceholder")} /></label>
        <label className="select-field"><select value={enabled} onChange={(event) => setEnabled(event.target.value)}><option value="">{t("common.status")}: {t("common.all")}</option><option value="true">{t("rulesPage.enabled")}</option><option value="false">{t("rulesPage.disabled")}</option></select></label>
        <span className="result-count"><strong>{formatNumber(rules.data?.total)}</strong> {t("common.total").toLowerCase()}</span>
      </section>
      <section className="panel table-panel">
        {rules.isPending ? <LoadingState rows={8} /> : rules.isError ? <ErrorState error={rules.error} onRetry={() => void rules.refetch()} /> : !visible.length ? <EmptyState title={t("rulesPage.noRules")} icon={Radar} /> : (
          <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("common.title")}</th><th>{t("common.severity")}</th><th>MITRE ATT&CK</th><th>{t("rulesPage.matches")}</th><th>{t("common.updated")}</th><th /></tr></thead><tbody>
            {visible.map((rule) => <tr key={rule.id} className="clickable-row" tabIndex={0} onClick={() => setSelected(rule)} onKeyDown={(event) => event.key === "Enter" && setSelected(rule)}>
              <td><span className={`enabled-indicator ${rule.enabled ? "on" : "off"}`}>{rule.enabled ? <ToggleRight size={23} /> : <ToggleLeft size={23} />}<StatusBadge value={rule.enabled ? "ENABLED" : "DISABLED"} /></span></td>
              <td className="primary-cell"><strong>{ruleTitle(rule)}</strong><small>{rule.rule_id || rule.id} · {rule.type || rule.source || "Sigma"}</small></td>
              <td><SeverityBadge value={rule.severity} /></td><td><div className="tag-list compact-tags">{rule.mitre_techniques?.slice(0, 3).map((technique) => <Tag key={technique} tone="accent">{technique}</Tag>)}{(rule.mitre_techniques?.length || 0) > 3 && <Tag>+{rule.mitre_techniques!.length - 3}</Tag>}</div></td>
              <td><strong>{formatNumber(rule.match_count)}</strong></td><td className="nowrap">{formatDateTime(rule.updated_at || rule.created_at)}</td><td><TableAction /></td>
            </tr>)}
          </tbody></table></div>
        )}
      </section>
      <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected ? ruleTitle(selected) : ""} eyebrow={selected?.rule_id || selected?.id} wide>
        {selected && <div className="detail-stack">
          <div className="drawer-lead"><StatusBadge value={selected.enabled ? "ENABLED" : "DISABLED"} /><SeverityBadge value={selected.severity} /><strong>{selected.type || selected.source || "Sigma"}</strong></div>
          <p className="lead-description">{selected.description || t("common.notAvailable")}</p>
          <dl className="detail-grid"><DetailRow label={t("common.version")}>{selected.version ?? "—"}</DetailRow><DetailRow label={t("rulesPage.owner")}>{selected.owner || "—"}</DetailRow><DetailRow label={t("common.confidence")}>{selected.confidence != null ? `${selected.confidence}%` : "—"}</DetailRow><DetailRow label={t("rulesPage.matches")}>{formatNumber(selected.match_count)}</DetailRow><DetailRow label={t("common.created")}>{formatFullDateTime(selected.created_at)}</DetailRow><DetailRow label={t("common.updated")}>{formatFullDateTime(selected.updated_at)}</DetailRow></dl>
          <section className="detail-section"><h3>MITRE ATT&CK</h3><div className="tag-list">{selected.mitre_techniques?.length ? selected.mitre_techniques.map((technique) => <Tag key={technique} tone="accent">{technique}</Tag>) : <span className="muted">{t("common.noData")}</span>}</div></section>
          <section className="detail-section"><h3>{t("rulesPage.requiredSources")}</h3><div className="tag-list">{selected.required_sources?.length ? selected.required_sources.map((source) => <Tag key={source}>{source}</Tag>) : <span className="muted">{t("common.noData")}</span>}</div></section>
          <details className="raw-details"><summary>{t("common.rawData")}</summary><JsonBlock value={selected} /></details>
        </div>}
      </Drawer>
    </div>
  );
}
