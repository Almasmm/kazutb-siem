import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Cable, Clock3, Play, ShieldCheck, Workflow, XCircle } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { SOARApprovalDto, SOARConnectorDto, SOARExecutionDto, SOARPlaybookDto } from "../api/types";
import { DetailRow, Drawer, EmptyState, ErrorState, JsonBlock, LoadingState, MetricCard, Modal, PageHeader, StatusBadge, TableAction, Tag } from "../components/ui";
import { formatDateTime, formatFullDateTime } from "../utils/format";

type Tab = "executions" | "approvals" | "playbooks" | "connectors";
type Selection = { kind: "execution"; value: SOARExecutionDto } | { kind: "approval"; value: SOARApprovalDto } | { kind: "playbook"; value: SOARPlaybookDto } | { kind: "connector"; value: SOARConnectorDto } | null;

export default function SoarPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("executions");
  const [selection, setSelection] = useState<Selection>(null);
  const [decisionOpen, setDecisionOpen] = useState(false);
  const [decision, setDecision] = useState("APPROVED");
  const [reason, setReason] = useState("");
  const playbooks = useQuery({ queryKey: ["soar-playbooks"], queryFn: ({ signal }) => api.soarPlaybooks(signal) });
  const executions = useQuery({ queryKey: ["soar-executions"], queryFn: ({ signal }) => api.soarExecutions({ limit: 500 }, signal), refetchInterval: 15_000 });
  const approvals = useQuery({ queryKey: ["soar-approvals"], queryFn: ({ signal }) => api.soarApprovals({ limit: 500 }, signal), refetchInterval: 15_000 });
  const connectors = useQuery({ queryKey: ["soar-connectors"], queryFn: ({ signal }) => api.soarConnectors(signal), refetchInterval: 30_000 });
  const decide = useMutation({ mutationFn: () => api.decideSOARApproval((selection as { kind: "approval"; value: SOARApprovalDto }).value.approval_id, { decision, reason: reason.trim() }), onSuccess: (item) => { setSelection({ kind: "approval", value: item }); setDecisionOpen(false); setReason(""); void queryClient.invalidateQueries({ queryKey: ["soar-approvals"] }); void queryClient.invalidateQueries({ queryKey: ["soar-executions"] }); } });
  const pending = (approvals.data?.items || []).filter((item) => ["PENDING", "WAITING"].includes(item.status)).length;
  const running = (executions.data?.items || []).filter((item) => ["QUEUED", "RUNNING", "WAITING_APPROVAL", "WAITING_MANUAL"].includes(item.status)).length;
  const healthy = (connectors.data?.items || []).filter((item) => item.health_status === "HEALTHY").length;
  const loading = playbooks.isPending || executions.isPending || approvals.isPending || connectors.isPending;
  const error = playbooks.error || executions.error || approvals.error || connectors.error;

  return <div className="page"><PageHeader eyebrow={t("soarPage.eyebrow")} title={t("soarPage.title")} subtitle={t("soarPage.subtitle")} />
    <section className="metrics-grid compact-metrics"><MetricCard label={t("soarPage.running")} value={running} icon={Play} tone={running ? "warning" : "good"} /><MetricCard label={t("soarPage.pendingApprovals")} value={pending} icon={Clock3} tone={pending ? "critical" : "good"} /><MetricCard label={t("soarPage.playbooks")} value={playbooks.data?.total || 0} icon={Workflow} /><MetricCard label={t("soarPage.healthyConnectors")} value={`${healthy}/${connectors.data?.total || 0}`} icon={Cable} tone={healthy === (connectors.data?.total || 0) ? "good" : "warning"} /></section>
    <section className="panel results-panel"><div className="result-tabs" role="tablist">{(["executions", "approvals", "playbooks", "connectors"] as Tab[]).map((value) => <button key={value} type="button" className={tab === value ? "active" : ""} onClick={() => setTab(value)}>{value === "executions" ? <Play size={16} /> : value === "approvals" ? <ShieldCheck size={16} /> : value === "playbooks" ? <Workflow size={16} /> : <Cable size={16} />}{t(`soarPage.${value}`)}<span>{value === "executions" ? executions.data?.total || 0 : value === "approvals" ? approvals.data?.total || 0 : value === "playbooks" ? playbooks.data?.total || 0 : connectors.data?.total || 0}</span></button>)}</div>
      {loading ? <LoadingState rows={8} /> : error ? <ErrorState error={error} /> : tab === "executions" ? <ExecutionTable items={executions.data?.items || []} onSelect={(value) => setSelection({ kind: "execution", value })} t={t} /> : tab === "approvals" ? <ApprovalTable items={approvals.data?.items || []} onSelect={(value) => setSelection({ kind: "approval", value })} t={t} /> : tab === "playbooks" ? <PlaybookTable items={playbooks.data?.items || []} onSelect={(value) => setSelection({ kind: "playbook", value })} t={t} /> : <ConnectorTable items={connectors.data?.items || []} onSelect={(value) => setSelection({ kind: "connector", value })} t={t} />}
    </section>
    <Drawer open={Boolean(selection)} onClose={() => setSelection(null)} wide title={selectionTitle(selection)} eyebrow={selection?.kind ? t(`soarPage.${selection.kind}`) : ""} footer={selection?.kind === "approval" && ["PENDING", "WAITING"].includes(selection.value.status) ? <button className="button primary" type="button" onClick={() => setDecisionOpen(true)}>{t("soarPage.decide")}</button> : undefined}>
      {selection && <div className="detail-stack"><div className="drawer-lead"><StatusBadge value={selectionState(selection)} /><strong>{selectionTitle(selection)}</strong></div>
        {selection.kind === "execution" && <><dl className="detail-grid"><DetailRow label={t("soarPage.playbook")}>{selection.value.playbook_id} v{selection.value.playbook_version}</DetailRow><DetailRow label={t("soarPage.trigger")}>{selection.value.trigger_type}</DetailRow><DetailRow label={t("common.actor")}>{selection.value.triggered_by}</DetailRow><DetailRow label={t("common.created")}>{formatFullDateTime(selection.value.created_at)}</DetailRow></dl><section className="detail-section"><h3>{t("soarPage.nodes")}</h3><div className="compact-list">{selection.value.nodes?.map((node) => <div key={node.node_execution_id}><div><strong>{node.node_name}</strong><small>{node.node_type} · attempt {node.attempt}</small></div><StatusBadge value={node.status} /></div>)}</div></section></>}
        {selection.kind === "approval" && <><dl className="detail-grid"><DetailRow label={t("soarPage.execution")}>{selection.value.execution_id}</DetailRow><DetailRow label={t("common.risk")}>{selection.value.risk_level}/100</DetailRow><DetailRow label={t("soarPage.requiredApprovals")}>{selection.value.required_approvals}</DetailRow><DetailRow label={t("soarPage.expires")}>{formatFullDateTime(selection.value.expires_at)}</DetailRow></dl><section className="detail-section"><h3>{t("soarPage.decisions")}</h3>{selection.value.decisions?.length ? <div className="compact-list">{selection.value.decisions.map((item, index) => <div key={`${item.approver}-${index}`}><div><strong>{item.approver}</strong><small>{item.reason}</small></div><StatusBadge value={item.decision} /></div>)}</div> : <EmptyState title={t("soarPage.noDecisions")} icon={ShieldCheck} />}</section></>}
        {selection.kind === "playbook" && <><p className="lead-description">{selection.value.description || t("common.notAvailable")}</p><dl className="detail-grid"><DetailRow label={t("common.version")}>{selection.value.latest_version}</DetailRow><DetailRow label={t("soarPage.publishedVersion")}>{selection.value.published_version || "—"}</DetailRow><DetailRow label={t("common.updated")}>{formatFullDateTime(selection.value.updated_at)}</DetailRow><DetailRow label={t("common.actor")}>{selection.value.updated_by || "—"}</DetailRow></dl></>}
        {selection.kind === "connector" && <><dl className="detail-grid"><DetailRow label={t("soarPage.kind")}>{selection.value.kind}</DetailRow><DetailRow label={t("soarPage.health")}>{selection.value.health_status}</DetailRow><DetailRow label={t("soarPage.authType")}>{selection.value.auth_type}</DetailRow><DetailRow label={t("soarPage.lastTested")}>{formatFullDateTime(selection.value.last_tested_at)}</DetailRow></dl><section className="detail-section"><h3>{t("soarPage.allowedActions")}</h3><div className="tag-list">{selection.value.allowed_actions?.map((action) => <Tag key={action}>{action}</Tag>)}</div></section><details className="raw-details"><summary>{t("common.rawData")}</summary><JsonBlock value={selection.value} /></details></>}
      </div>}
    </Drawer>
    <Modal open={decisionOpen && selection?.kind === "approval"} onClose={() => setDecisionOpen(false)} title={t("soarPage.decisionTitle")} footer={<><button className="button ghost" type="button" onClick={() => setDecisionOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={!reason.trim() || decide.isPending} onClick={() => decide.mutate()}>{decision === "APPROVED" ? <CheckCircle2 size={16} /> : <XCircle size={16} />}{t("common.save")}</button></>}><label className="form-field"><span>{t("common.decision")}</span><select value={decision} onChange={(event) => setDecision(event.target.value)}><option value="APPROVED">{t("common.approve")}</option><option value="REJECTED">{t("common.reject")}</option></select></label><label className="form-field"><span>{t("common.reason")}</span><textarea rows={4} value={reason} onChange={(event) => setReason(event.target.value)} /></label>{decide.isError && <ErrorState error={decide.error} compact />}</Modal>
  </div>;
}

type TFunction = ReturnType<typeof useTranslation>["t"];
function ExecutionTable({ items, onSelect, t }: { items: SOARExecutionDto[]; onSelect: (value: SOARExecutionDto) => void; t: TFunction }) { if (!items.length) return <EmptyState title={t("soarPage.noExecutions")} icon={Play} />; return <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("soarPage.execution")}</th><th>{t("soarPage.playbook")}</th><th>{t("soarPage.trigger")}</th><th>{t("common.actor")}</th><th>{t("common.updated")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.execution_id} className="clickable-row" onClick={() => onSelect(item)}><td><StatusBadge value={item.status} /></td><td className="primary-cell"><strong>{item.execution_id}</strong><small>{item.request_id}</small></td><td>{item.playbook_id} v{item.playbook_version}</td><td>{item.trigger_type}</td><td>{item.triggered_by}</td><td>{formatDateTime(item.updated_at || item.created_at)}</td><td><TableAction /></td></tr>)}</tbody></table></div>; }
function ApprovalTable({ items, onSelect, t }: { items: SOARApprovalDto[]; onSelect: (value: SOARApprovalDto) => void; t: TFunction }) { if (!items.length) return <EmptyState title={t("soarPage.noApprovals")} icon={ShieldCheck} />; return <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("soarPage.approval")}</th><th>{t("soarPage.execution")}</th><th>{t("common.risk")}</th><th>{t("common.actor")}</th><th>{t("soarPage.expires")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.approval_id} className="clickable-row" onClick={() => onSelect(item)}><td><StatusBadge value={item.status} /></td><td className="primary-cell"><strong>{item.approval_id}</strong><small>{item.node_execution_id}</small></td><td>{item.execution_id}</td><td>{item.risk_level}/100</td><td>{item.requested_by}</td><td>{formatDateTime(item.expires_at)}</td><td><TableAction /></td></tr>)}</tbody></table></div>; }
function PlaybookTable({ items, onSelect, t }: { items: SOARPlaybookDto[]; onSelect: (value: SOARPlaybookDto) => void; t: TFunction }) { if (!items.length) return <EmptyState title={t("soarPage.noPlaybooks")} icon={Workflow} />; return <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("soarPage.playbook")}</th><th>{t("common.version")}</th><th>{t("soarPage.publishedVersion")}</th><th>{t("common.updated")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.playbook_id} className="clickable-row" onClick={() => onSelect(item)}><td><StatusBadge value={item.state} /></td><td className="primary-cell"><strong>{item.name}</strong><small>{item.playbook_id}</small></td><td>{item.latest_version}</td><td>{item.published_version || "—"}</td><td>{formatDateTime(item.updated_at)}</td><td><TableAction /></td></tr>)}</tbody></table></div>; }
function ConnectorTable({ items, onSelect, t }: { items: SOARConnectorDto[]; onSelect: (value: SOARConnectorDto) => void; t: TFunction }) { if (!items.length) return <EmptyState title={t("soarPage.noConnectors")} icon={Cable} />; return <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("soarPage.health")}</th><th>{t("soarPage.connector")}</th><th>{t("soarPage.kind")}</th><th>{t("soarPage.authType")}</th><th>{t("soarPage.lastTested")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.connector_id} className="clickable-row" onClick={() => onSelect(item)}><td><StatusBadge value={item.health_status} /></td><td className="primary-cell"><strong>{item.name}</strong><small>{item.connector_id}</small></td><td>{item.kind}</td><td>{item.auth_type}</td><td>{formatDateTime(item.last_tested_at)}</td><td><TableAction /></td></tr>)}</tbody></table></div>; }

function selectionTitle(selection: Selection): string {
  if (!selection) return "";
  switch (selection.kind) {
    case "execution": return selection.value.execution_id;
    case "approval": return selection.value.approval_id;
    case "playbook": return selection.value.name;
    case "connector": return selection.value.name;
  }
}

function selectionState(selection: Exclude<Selection, null>): string {
  switch (selection.kind) {
    case "playbook": return selection.value.state;
    case "execution": return selection.value.status;
    case "approval": return selection.value.status;
    case "connector": return selection.value.state;
  }
}
