import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Braces, CheckCircle2, Code2, FlaskConical, Plus, Send, ShieldCheck, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { ParserContentDto, ParserSpecDto } from "../api/types";
import { DetailRow, Drawer, EmptyState, ErrorState, LoadingState, MetricCard, Modal, PageHeader, StatusBadge, TableAction } from "../components/ui";
import { formatDateTime, formatFullDateTime } from "../utils/format";

const defaultMappings = JSON.stringify({ category: "event.category", activity_name: "event.action", severity: "event.severity", "user.name": "identity.user", "device.hostname": "host.name", "src_endpoint.ip": "network.src_ip", "dst_endpoint.ip": "network.dst_ip" }, null, 2);
const defaultDefaults = JSON.stringify({ "source.vendor": "University", "source.product": "Custom Source", "source.type": "network" }, null, 2);
const defaultSample = JSON.stringify({ event: { category: "Network Activity", action: "Allowed", severity: 3 }, identity: { user: "student" }, host: { name: "edge-01" }, network: { src_ip: "10.10.1.7", dst_ip: "10.10.1.1" } }, null, 2);

export default function ParserStudioPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<ParserContentDto | null>(null);
  const [draftOpen, setDraftOpen] = useState(false);
  const [parentID, setParentID] = useState("");
  const [name, setName] = useState("University custom JSON");
  const [format, setFormat] = useState("university.custom-json");
  const [inputKind, setInputKind] = useState<"JSON" | "KV">("JSON");
  const [mappings, setMappings] = useState(defaultMappings);
  const [defaults, setDefaults] = useState(defaultDefaults);
  const [sample, setSample] = useState(defaultSample);
  const [expected, setExpected] = useState(JSON.stringify({ category: "Network Activity", "user.name": "student", "device.hostname": "edge-01" }, null, 2));
  const [simulation, setSimulation] = useState<Record<string, string> | null>(null);
  const custom = useQuery({ queryKey: ["parser-studio"], queryFn: ({ signal }) => api.parsers(signal) });
  const builtIn = useQuery({ queryKey: ["parser-built-in"], queryFn: ({ signal }) => api.builtInParsers(signal) });
  const items = custom.data?.items || [];
  const published = items.filter((item) => item.state === "PUBLISHED").length;
  const validated = items.filter((item) => item.validation?.valid).length;
  const latest = useMemo(() => items.filter((item, index, all) => all.findIndex((candidate) => candidate.parser_id === item.parser_id) === index), [items]);

  const refresh = (item?: ParserContentDto) => {
    if (item) setSelected(item);
    void queryClient.invalidateQueries({ queryKey: ["parser-studio"] });
  };
  const create = useMutation({
    mutationFn: () => {
      const spec: ParserSpecDto = { format, input_kind: inputKind, mappings: parseMap(mappings), defaults: parseMap(defaults), tests: sample.trim() ? [{ name: "studio-sample", payload: sample, expected: parseMap(expected) }] : [] };
      const payload = { name: name.trim(), spec };
      return parentID ? api.createParserVersion(parentID, payload) : api.createParser(payload);
    },
    onSuccess: (item) => { refresh(item); setDraftOpen(false); setParentID(""); },
  });
  const validate = useMutation({ mutationFn: (item: ParserContentDto) => api.validateParser(item.parser_id, item.version), onSuccess: refresh, onSettled: () => void queryClient.invalidateQueries({ queryKey: ["parser-studio"] }) });
  const publish = useMutation({ mutationFn: (item: ParserContentDto) => api.publishParser(item.parser_id, item.version), onSuccess: refresh });
  const disable = useMutation({ mutationFn: (item: ParserContentDto) => api.disableParser(item.parser_id), onSuccess: refresh });
  const simulate = useMutation({ mutationFn: () => api.simulateParser(selected!.parser_id, selected!.version, sample), onSuccess: (result) => setSimulation(result.fields) });

  const openVersion = (item: ParserContentDto) => {
    setParentID(item.parser_id); setName(item.name); setFormat(item.spec.format); setInputKind(item.spec.input_kind);
    setMappings(JSON.stringify(item.spec.mappings, null, 2)); setDefaults(JSON.stringify(item.spec.defaults, null, 2)); setSample(item.spec.tests?.[0]?.payload || defaultSample); setExpected(JSON.stringify(item.spec.tests?.[0]?.expected || {}, null, 2)); setDraftOpen(true);
  };

  return <div className="page parser-studio-page">
    <PageHeader eyebrow={t("parserPage.eyebrow")} title={t("parserPage.title")} subtitle={t("parserPage.subtitle")} actions={<button className="button primary" type="button" onClick={() => { setParentID(""); setDraftOpen(true); }}><Plus size={16} />{t("parserPage.newParser")}</button>} />
    <section className="metrics-grid compact-metrics"><MetricCard label={t("parserPage.builtIn")} value={builtIn.data?.total || 0} icon={ShieldCheck} tone="good" /><MetricCard label={t("parserPage.customParsers")} value={latest.length} icon={Braces} /><MetricCard label={t("parserPage.published")} value={published} icon={Send} tone="good" /><MetricCard label={t("parserPage.validatedVersions")} value={validated} icon={CheckCircle2} /></section>
    <section className="parser-catalog-grid"><div className="panel table-panel"><div className="panel-heading"><div><span>{t("parserPage.tenantCatalog")}</span><strong>{t("parserPage.versionedContent")}</strong></div></div>{custom.isPending ? <LoadingState rows={7} /> : custom.isError ? <ErrorState error={custom.error} onRetry={() => void custom.refetch()} /> : !items.length ? <EmptyState title={t("parserPage.noCustom")} icon={Code2} /> : <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("parserPage.parser")}</th><th>{t("parserPage.format")}</th><th>{t("parserPage.tests")}</th><th>{t("common.updated")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={`${item.parser_id}-${item.version}`} className="clickable-row" onClick={() => { setSelected(item); setSample(item.spec.tests?.[0]?.payload || defaultSample); setSimulation(null); }}><td><StatusBadge value={item.state} /></td><td className="primary-cell"><strong>{item.name}</strong><small>{item.parser_id} · v{item.version}</small></td><td><code className="parser-format">{item.spec.format}</code></td><td>{item.validation?.tests_passed || 0}/{item.validation?.tests_total || item.spec.tests?.length || 0}</td><td>{formatDateTime(item.updated_at)}</td><td><TableAction /></td></tr>)}</tbody></table></div>}</div>
      <aside className="panel builtin-parsers"><div className="panel-heading"><div><span>{t("parserPage.protectedRuntime")}</span><strong>{t("parserPage.builtInParsers")}</strong></div></div>{builtIn.isPending ? <LoadingState rows={6} compact /> : builtIn.isError ? <ErrorState error={builtIn.error} compact /> : <div className="builtin-list">{builtIn.data?.items.map((item) => <div key={item.parser_id}><span><ShieldCheck size={14} /></span><div><strong>{item.product}</strong><small>{item.vendor} · {item.formats.join(", ")}</small></div><em>v{item.version}</em></div>)}</div>}</aside></section>
    <Drawer open={Boolean(selected)} onClose={() => { setSelected(null); setSimulation(null); }} wide title={selected?.name || ""} eyebrow={selected ? `${selected.parser_id} · v${selected.version}` : ""} footer={selected && <><button className="button ghost" type="button" onClick={() => openVersion(selected)}><Plus size={15} />{t("parserPage.newVersion")}</button>{selected.state === "PUBLISHED" ? <button className="button danger" type="button" onClick={() => disable.mutate(selected)}>{t("common.disable")}</button> : <><button className="button ghost" type="button" onClick={() => validate.mutate(selected)}><FlaskConical size={15} />{t("parserPage.validate")}</button><button className="button primary" type="button" disabled={!selected.validation?.valid} onClick={() => publish.mutate(selected)}><Send size={15} />{t("parserPage.publish")}</button></>}</>}>
      {selected && <div className="detail-stack"><div className="parser-lead"><StatusBadge value={selected.state} /><code>{selected.spec.format}</code><span>{selected.spec.input_kind} → OCSF {selected.validation?.ocsf_compatible || "1.4.0"}</span></div><dl className="detail-grid"><DetailRow label={t("parserPage.compiler")}>{selected.validation?.compiler || "—"}</DetailRow><DetailRow label={t("parserPage.mappedFields")}>{Object.keys(selected.spec.mappings || {}).length}</DetailRow><DetailRow label={t("common.created")}>{formatFullDateTime(selected.created_at)}</DetailRow><DetailRow label={t("common.updated")}>{formatFullDateTime(selected.updated_at)}</DetailRow></dl>
        <section className="detail-section"><h3>{t("parserPage.validation")}</h3><div className={`validation-banner ${selected.validation?.valid ? "valid" : "pending"}`}>{selected.validation?.valid ? <CheckCircle2 size={18} /> : <TriangleAlert size={18} />}<div><strong>{selected.validation?.valid ? t("parserPage.validationPassed") : t("parserPage.validationRequired")}</strong><small>{selected.validation?.tests_passed || 0}/{selected.validation?.tests_total || selected.spec.tests?.length || 0} {t("parserPage.testsPassed")}</small></div></div>{[...(selected.validation?.errors || []), ...(selected.validation?.warnings || [])].map((message) => <p className="validation-message" key={message}>{message}</p>)}</section>
        <section className="detail-section"><h3>{t("parserPage.mapping")}</h3><div className="mapping-grid">{Object.entries(selected.spec.mappings || {}).map(([target, source]) => <div key={target}><code>{source}</code><span>→</span><strong>{target}</strong></div>)}{Object.entries(selected.spec.defaults || {}).map(([target, value]) => <div key={`default-${target}`}><code className="default-value">{value}</code><span>→</span><strong>{target}</strong></div>)}</div></section>
        <section className="detail-section"><h3>{t("parserPage.simulator")}</h3><textarea className="code-editor compact" value={sample} onChange={(event) => setSample(event.target.value)} spellCheck={false} /><button className="button ghost simulate-button" type="button" disabled={!sample.trim() || simulate.isPending} onClick={() => simulate.mutate()}><FlaskConical size={15} />{t("parserPage.runSample")}</button>{simulate.isError && <ErrorState error={simulate.error} compact />}{simulation && <div className="ocsf-preview">{Object.entries(simulation).map(([field, value]) => <div key={field}><span>{field}</span><code>{value}</code></div>)}</div>}</section>
      </div>}
    </Drawer>
    <Modal open={draftOpen} onClose={() => setDraftOpen(false)} title={parentID ? t("parserPage.newVersion") : t("parserPage.createTitle")} footer={<><button className="button ghost" type="button" onClick={() => setDraftOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={!name.trim() || !format.trim() || create.isPending} onClick={() => create.mutate()}><Code2 size={15} />{t("common.create")}</button></>}><div className="parser-form-grid"><label className="form-field"><span>{t("common.name")}</span><input value={name} onChange={(event) => setName(event.target.value)} /></label><label className="form-field"><span>{t("parserPage.format")}</span><input value={format} disabled={Boolean(parentID)} onChange={(event) => setFormat(event.target.value)} /></label><label className="form-field"><span>{t("parserPage.inputKind")}</span><select value={inputKind} onChange={(event) => setInputKind(event.target.value as "JSON" | "KV")}><option>JSON</option><option>KV</option></select></label></div><label className="form-field"><span>{t("parserPage.mappingJson")}</span><textarea className="code-editor" rows={9} value={mappings} onChange={(event) => setMappings(event.target.value)} spellCheck={false} /></label><label className="form-field"><span>{t("parserPage.defaultsJson")}</span><textarea className="code-editor" rows={5} value={defaults} onChange={(event) => setDefaults(event.target.value)} spellCheck={false} /></label><label className="form-field"><span>{t("parserPage.regressionSample")}</span><textarea className="code-editor" rows={7} value={sample} onChange={(event) => setSample(event.target.value)} spellCheck={false} /></label><label className="form-field"><span>{t("parserPage.expectedFields")}</span><textarea className="code-editor" rows={5} value={expected} onChange={(event) => setExpected(event.target.value)} spellCheck={false} /></label>{create.isError && <ErrorState error={create.error} compact />}</Modal>
  </div>;
}

function parseMap(value: string): Record<string, string> {
  const parsed: unknown = JSON.parse(value || "{}");
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("Expected a JSON object");
  return Object.fromEntries(Object.entries(parsed).map(([key, item]) => [key, String(item)]));
}
