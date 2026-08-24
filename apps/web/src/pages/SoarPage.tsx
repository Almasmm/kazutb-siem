import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Cable, Clock3, FlaskConical, Pencil, Play, Plus, Power, ShieldCheck, Workflow, XCircle } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import { ApprovalDecision, type ApprovalDecision as ApprovalDecisionValue, type SOARApprovalDto, type SOARConnectorDraftDto, type SOARConnectorDto, type SOARExecutionDto, type SOARPlaybookDto } from "../api/types";
import { DetailRow, Drawer, EmptyState, ErrorState, InlineNotice, JsonBlock, LoadingState, MetricCard, Modal, PageHeader, StatusBadge, TableAction, Tag } from "../components/ui";
import { approvalErrorMessageKey, approvalResultMessageKey, approvalSubmitDisabled, buildApprovalDecisionRequest, createApprovalSubmissionGate, isApprovalVersionConflict } from "../soar/approval";
import { formatDateTime, formatFullDateTime } from "../utils/format";

type Tab = "executions" | "approvals" | "playbooks" | "connectors";
type Selection = { kind: "execution"; value: SOARExecutionDto } | { kind: "approval"; value: SOARApprovalDto } | { kind: "playbook"; value: SOARPlaybookDto } | { kind: "connector"; value: SOARConnectorDto } | null;

const connectorActions = {
  WEBHOOK: ["kcsp.ticket.create", "kcsp.notification.send"],
  FIREWALL_REST: ["firewall.block_ip", "firewall.unblock_ip"],
  ITSM_REST: ["kcsp.ticket.create", "kcsp.ticket.update", "kcsp.ticket.comment", "kcsp.ticket.close"],
  KCSP_API: ["kcsp.ticket.create", "kcsp.notification.send", "threat_intel.indicator.submit"],
  THREAT_INTEL_REST: ["threat_intel.indicator.submit"],
  NOTIFICATION_REST: ["kcsp.notification.send"],
  EDR_XDR_REST: ["endpoint.isolate", "endpoint.release"],
  EMAIL_SMTP: ["kcsp.notification.send"],
  LDAP_DIRECTORY: ["identity.disable_account", "identity.enable_account"],
} as const;

type ConnectorKind = keyof typeof connectorActions;
interface ConnectorForm {
  name: string;
  kind: ConnectorKind;
  endpoint: string;
  authType: string;
  secretRef: string;
  allowedActions: string[];
  healthMethod: string;
  healthPath: string;
  expectedStatus: number;
  timeoutSeconds: number;
  rateLimitPerMinute: number;
  provider: string;
  channel: string;
  apiKeyHeader: string;
  fromAddress: string;
  heloName: string;
  directoryType: string;
  baseDN: string;
  accountAttribute: string;
  disabledAttribute: string;
  disabledValue: string;
  enabledValue: string;
  projectKey: string;
  issueType: string;
  closeTransitionId: string;
  teamId: string;
  channelId: string;
}

const emptyConnectorForm = (): ConnectorForm => ({
  name: "", kind: "WEBHOOK", endpoint: "", authType: "BEARER", secretRef: "",
  allowedActions: ["kcsp.notification.send"], healthMethod: "HEAD", healthPath: "",
  expectedStatus: 200, timeoutSeconds: 10, rateLimitPerMinute: 60,
  provider: "GENERIC", channel: "", apiKeyHeader: "X-API-Key", fromAddress: "", heloName: "",
  directoryType: "ACTIVE_DIRECTORY", baseDN: "", accountAttribute: "", disabledAttribute: "pwdAccountLockedTime",
  disabledValue: "000001010000Z", enabledValue: "",
  projectKey: "", issueType: "Incident", closeTransitionId: "",
  teamId: "", channelId: "",
});

function connectorDraft(form: ConnectorForm): SOARConnectorDraftDto {
  const settings: Record<string, string | number | boolean> = {};
  if (form.kind === "EMAIL_SMTP") {
    settings.from_address = form.fromAddress.trim();
    if (form.heloName.trim()) settings.helo_name = form.heloName.trim();
  } else if (form.kind === "LDAP_DIRECTORY") {
    settings.directory_type = form.directoryType;
    settings.base_dn = form.baseDN.trim();
    if (form.accountAttribute.trim()) settings.account_attribute = form.accountAttribute.trim();
    if (form.directoryType === "LDAP") {
      if (form.disabledAttribute.trim()) settings.disabled_attribute = form.disabledAttribute.trim();
      if (form.disabledValue) settings.disabled_value = form.disabledValue;
      settings.enabled_value = form.enabledValue;
    }
  } else if (!(form.kind === "ITSM_REST" && form.provider !== "GENERIC")) {
    settings.health_method = form.healthMethod;
    settings.expected_status = form.expectedStatus;
    if (form.healthPath.trim()) settings.health_path = form.healthPath.trim();
  }
  if (form.authType === "API_KEY") settings.api_key_header = form.apiKeyHeader.trim() || "X-API-Key";
  if (form.kind === "NOTIFICATION_REST") {
    settings.provider = form.provider;
    if ((form.provider === "SLACK" || form.provider === "SLACK_WEB_API") && form.channel.trim()) settings.channel = form.channel.trim();
    if (form.provider === "TEAMS_GRAPH") {
      settings.team_id = form.teamId.trim();
      settings.channel_id = form.channelId.trim();
    }
  }
  if (form.kind === "EDR_XDR_REST") settings.provider = form.provider;
  if (form.kind === "ITSM_REST") {
    settings.provider = form.provider;
    if (form.provider === "JIRA") {
      settings.project_key = form.projectKey.trim().toUpperCase();
      settings.issue_type = form.issueType.trim() || "Incident";
      if (form.closeTransitionId.trim()) settings.close_transition_id = form.closeTransitionId.trim();
    }
  }
  return {
    name: form.name.trim(), kind: form.kind, endpoint: form.endpoint.trim(), auth_type: form.authType,
    secret_ref: form.authType === "NONE" ? "" : form.secretRef.trim(), allowed_actions: form.allowedActions,
    settings, timeout_seconds: form.timeoutSeconds, rate_limit_per_minute: form.rateLimitPerMinute,
  };
}

export default function SoarPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>("executions");
  const [selection, setSelection] = useState<Selection>(null);
  const [decisionOpen, setDecisionOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [approvalNotice, setApprovalNotice] = useState("");
  const [connectorEditorOpen, setConnectorEditorOpen] = useState(false);
  const [editingConnector, setEditingConnector] = useState<SOARConnectorDto | null>(null);
  const [connectorForm, setConnectorForm] = useState<ConnectorForm>(emptyConnectorForm);
  const [connectorNotice, setConnectorNotice] = useState("");
  const approvalSubmissionGate = useRef(createApprovalSubmissionGate());
  const session = useQuery({ queryKey: ["session"], queryFn: ({ signal }) => api.session(signal), staleTime: 5 * 60_000 });
  const playbooks = useQuery({ queryKey: ["soar-playbooks"], queryFn: ({ signal }) => api.soarPlaybooks(signal) });
  const executions = useQuery({ queryKey: ["soar-executions"], queryFn: ({ signal }) => api.soarExecutions({ limit: 500 }, signal), refetchInterval: 15_000 });
  const approvals = useQuery({ queryKey: ["soar-approvals"], queryFn: ({ signal }) => api.soarApprovals({ limit: 500 }, signal), refetchInterval: 15_000 });
  const connectors = useQuery({ queryKey: ["soar-connectors"], queryFn: ({ signal }) => api.soarConnectors(signal), refetchInterval: 30_000 });
  const selectedConnectorID = selection?.kind === "connector" ? selection.value.connector_id : "";
  const connectorTests = useQuery({
    queryKey: ["soar-connector-tests", selectedConnectorID],
    queryFn: ({ signal }) => api.soarConnectorTests(selectedConnectorID, signal),
    enabled: Boolean(selectedConnectorID),
    refetchInterval: selectedConnectorID ? 5_000 : false,
  });
  const decide = useMutation({
    mutationFn: (submittedDecision: ApprovalDecisionValue) => {
      if (selection?.kind !== "approval") throw new Error("approval selection is required");
      return api.decideSOARApproval(selection.value.approval_id,
        buildApprovalDecisionRequest(submittedDecision, reason, selection.value.version));
    },
    onSuccess: (item) => {
      setSelection({ kind: "approval", value: item }); setDecisionOpen(false); setReason("");
      setApprovalNotice(t(approvalResultMessageKey(item.status)));
      void queryClient.invalidateQueries({ queryKey: ["soar-approvals"] });
      void queryClient.invalidateQueries({ queryKey: ["soar-executions"] });
    },
    onError: (mutationError) => {
      setApprovalNotice(t(approvalErrorMessageKey(mutationError)));
      if (isApprovalVersionConflict(mutationError)) {
        void queryClient.invalidateQueries({ queryKey: ["soar-approvals"] });
        void queryClient.invalidateQueries({ queryKey: ["soar-executions"] });
      }
    },
    onSettled: () => approvalSubmissionGate.current.release(),
  });
  const submitApprovalDecision = (submittedDecision: ApprovalDecisionValue) => {
    if (!approvalSubmissionGate.current.tryAcquire()) return;
    decide.mutate(submittedDecision);
  };
  const saveConnector = useMutation({
    mutationFn: () => {
      const draft = connectorDraft(connectorForm);
      if (!editingConnector) return api.createSOARConnector(draft);
      const { kind: _kind, ...patch } = draft;
      return api.updateSOARConnector(editingConnector.connector_id, { ...patch, version: editingConnector.version });
    },
    onSuccess: (item) => {
      setSelection({ kind: "connector", value: item }); setConnectorEditorOpen(false); setEditingConnector(null);
      setConnectorNotice(t("soarPage.connectorSaved")); void queryClient.invalidateQueries({ queryKey: ["soar-connectors"] });
    },
  });
  const testConnector = useMutation({
    mutationFn: (item: SOARConnectorDto) => api.testSOARConnector(item.connector_id),
    onSuccess: (_test, item) => {
      setConnectorNotice(t("soarPage.testQueued"));
      void queryClient.invalidateQueries({ queryKey: ["soar-connector-tests", item.connector_id] });
      void queryClient.invalidateQueries({ queryKey: ["soar-connectors"] });
    },
  });
  const disableConnector = useMutation({
    mutationFn: (item: SOARConnectorDto) => api.disableSOARConnector(item.connector_id, item.version),
    onSuccess: (item) => {
      setSelection({ kind: "connector", value: item }); setConnectorNotice(t("soarPage.connectorDisabled"));
      void queryClient.invalidateQueries({ queryKey: ["soar-connectors"] });
    },
  });
  const can = (permission: string) => Boolean(session.data?.permissions.includes("*") || session.data?.permissions.includes(permission));
  const canManageConnectors = can("soar.connectors.manage");
  const canTestConnectors = can("soar.connectors.test");
  const canApprove = can("soar.actions.approve");

  const openConnectorEditor = (item?: SOARConnectorDto) => {
    if (!item) {
      setEditingConnector(null); setConnectorForm(emptyConnectorForm()); setConnectorEditorOpen(true); return;
    }
    const kind = item.kind in connectorActions ? item.kind as ConnectorKind : "WEBHOOK";
    const settings = item.settings || {};
    setEditingConnector(item);
    setConnectorForm({
      name: item.name, kind, endpoint: item.endpoint, authType: item.auth_type, secretRef: item.secret_ref || "",
      allowedActions: item.allowed_actions || [connectorActions[kind][0]],
      healthMethod: String(settings.health_method || "HEAD"), healthPath: String(settings.health_path || ""),
      expectedStatus: Number(settings.expected_status || 200), timeoutSeconds: item.timeout_seconds || 10,
      rateLimitPerMinute: item.rate_limit_per_minute || 60, provider: String(settings.provider || "GENERIC"),
      channel: String(settings.channel || ""), apiKeyHeader: String(settings.api_key_header || "X-API-Key"),
      fromAddress: String(settings.from_address || ""), heloName: String(settings.helo_name || ""),
      directoryType: String(settings.directory_type || "ACTIVE_DIRECTORY"), baseDN: String(settings.base_dn || ""),
      accountAttribute: String(settings.account_attribute || ""), disabledAttribute: String(settings.disabled_attribute || "pwdAccountLockedTime"),
      disabledValue: String(settings.disabled_value || "000001010000Z"), enabledValue: String(settings.enabled_value || ""),
      projectKey: String(settings.project_key || ""), issueType: String(settings.issue_type || "Incident"),
      closeTransitionId: String(settings.close_transition_id || ""),
      teamId: String(settings.team_id || ""), channelId: String(settings.channel_id || ""),
    });
    setConnectorEditorOpen(true);
  };
  const pending = (approvals.data?.items || []).filter((item) => ["PENDING", "WAITING"].includes(item.status)).length;
  const running = (executions.data?.items || []).filter((item) => ["QUEUED", "RUNNING", "WAITING_APPROVAL", "WAITING_MANUAL"].includes(item.status)).length;
  const healthy = (connectors.data?.items || []).filter((item) => item.health_status === "HEALTHY").length;
  const loading = playbooks.isPending || executions.isPending || approvals.isPending || connectors.isPending;
  const error = playbooks.error || executions.error || approvals.error || connectors.error;

  return <div className="page"><PageHeader eyebrow={t("soarPage.eyebrow")} title={t("soarPage.title")} subtitle={t("soarPage.subtitle")} actions={canManageConnectors ? <button className="button primary" type="button" onClick={() => openConnectorEditor()}><Plus size={16} />{t("soarPage.newConnector")}</button> : undefined} />
    {approvalNotice && <InlineNotice tone="info">{approvalNotice}</InlineNotice>}
    <section className="metrics-grid compact-metrics"><MetricCard label={t("soarPage.running")} value={running} icon={Play} tone={running ? "warning" : "good"} /><MetricCard label={t("soarPage.pendingApprovals")} value={pending} icon={Clock3} tone={pending ? "critical" : "good"} /><MetricCard label={t("soarPage.playbooks")} value={playbooks.data?.total || 0} icon={Workflow} /><MetricCard label={t("soarPage.healthyConnectors")} value={`${healthy}/${connectors.data?.total || 0}`} icon={Cable} tone={healthy === (connectors.data?.total || 0) ? "good" : "warning"} /></section>
    <section className="panel results-panel"><div className="result-tabs" role="tablist">{(["executions", "approvals", "playbooks", "connectors"] as Tab[]).map((value) => <button key={value} type="button" className={tab === value ? "active" : ""} onClick={() => setTab(value)}>{value === "executions" ? <Play size={16} /> : value === "approvals" ? <ShieldCheck size={16} /> : value === "playbooks" ? <Workflow size={16} /> : <Cable size={16} />}{t(`soarPage.${value}`)}<span>{value === "executions" ? executions.data?.total || 0 : value === "approvals" ? approvals.data?.total || 0 : value === "playbooks" ? playbooks.data?.total || 0 : connectors.data?.total || 0}</span></button>)}</div>
      {loading ? <LoadingState rows={8} /> : error ? <ErrorState error={error} /> : tab === "executions" ? <ExecutionTable items={executions.data?.items || []} onSelect={(value) => setSelection({ kind: "execution", value })} t={t} /> : tab === "approvals" ? <ApprovalTable items={approvals.data?.items || []} onSelect={(value) => setSelection({ kind: "approval", value })} t={t} /> : tab === "playbooks" ? <PlaybookTable items={playbooks.data?.items || []} onSelect={(value) => setSelection({ kind: "playbook", value })} t={t} /> : <ConnectorTable items={connectors.data?.items || []} onSelect={(value) => { setSelection({ kind: "connector", value }); setConnectorNotice(""); }} t={t} />}
    </section>
    <Drawer open={Boolean(selection)} onClose={() => setSelection(null)} wide title={selectionTitle(selection)} eyebrow={selection?.kind ? t(`soarPage.${selection.kind}`) : ""} footer={selection?.kind === "approval" && ["PENDING", "WAITING"].includes(selection.value.status) && canApprove ? <button className="button primary" type="button" onClick={() => setDecisionOpen(true)}>{t("soarPage.decide")}</button> : selection?.kind === "connector" && selection.value.state !== "DISABLED" && (canManageConnectors || canTestConnectors) ? <>{canManageConnectors && <button className="button ghost" type="button" onClick={() => openConnectorEditor(selection.value)}><Pencil size={15} />{t("soarPage.editConnector")}</button>}{canTestConnectors && <button className="button primary" type="button" disabled={testConnector.isPending} onClick={() => testConnector.mutate(selection.value)}><FlaskConical size={15} />{t("soarPage.testConnection")}</button>}{canManageConnectors && <button className="button danger" type="button" disabled={disableConnector.isPending} onClick={() => disableConnector.mutate(selection.value)}><Power size={15} />{t("soarPage.disableConnector")}</button>}</> : undefined}>
      {selection && <div className="detail-stack"><div className="drawer-lead"><StatusBadge value={selectionState(selection)} /><strong>{selectionTitle(selection)}</strong></div>
        {selection.kind === "execution" && <><dl className="detail-grid"><DetailRow label={t("soarPage.playbook")}>{selection.value.playbook_id} v{selection.value.playbook_version}</DetailRow><DetailRow label={t("soarPage.trigger")}>{selection.value.trigger_type}</DetailRow><DetailRow label={t("common.actor")}>{selection.value.triggered_by}</DetailRow><DetailRow label={t("common.created")}>{formatFullDateTime(selection.value.created_at)}</DetailRow></dl><section className="detail-section"><h3>{t("soarPage.nodes")}</h3><div className="compact-list">{selection.value.nodes?.map((node) => <div key={node.node_execution_id}><div><strong>{node.node_name}</strong><small>{node.node_type} · attempt {node.attempt}</small></div><StatusBadge value={node.status} /></div>)}</div></section></>}
        {selection.kind === "approval" && <><dl className="detail-grid"><DetailRow label={t("soarPage.execution")}>{selection.value.execution_id}</DetailRow><DetailRow label={t("common.version")}>{selection.value.version}</DetailRow><DetailRow label={t("common.risk")}>{selection.value.risk_level}/100</DetailRow><DetailRow label={t("soarPage.requiredApprovals")}>{selection.value.required_approvals}</DetailRow><DetailRow label={t("soarPage.expires")}>{formatFullDateTime(selection.value.expires_at)}</DetailRow></dl>{selection.value.status === "PENDING" && !canApprove && <InlineNotice tone="warning">{t("soarPage.permissionDenied")}</InlineNotice>}<section className="detail-section"><h3>{t("soarPage.decisions")}</h3>{selection.value.decisions?.length ? <div className="compact-list">{selection.value.decisions.map((item, index) => <div key={`${item.approver}-${index}`}><div><strong>{item.approver}</strong><small>{item.reason}</small></div><StatusBadge value={item.decision} /></div>)}</div> : <EmptyState title={t("soarPage.noDecisions")} icon={ShieldCheck} />}</section></>}
        {selection.kind === "playbook" && <><p className="lead-description">{selection.value.description || t("common.notAvailable")}</p><dl className="detail-grid"><DetailRow label={t("common.version")}>{selection.value.latest_version}</DetailRow><DetailRow label={t("soarPage.publishedVersion")}>{selection.value.published_version || "—"}</DetailRow><DetailRow label={t("common.updated")}>{formatFullDateTime(selection.value.updated_at)}</DetailRow><DetailRow label={t("common.actor")}>{selection.value.updated_by || "—"}</DetailRow></dl></>}
        {selection.kind === "connector" && <>{connectorNotice && <div className="validation-banner valid"><CheckCircle2 size={18} /><div><strong>{connectorNotice}</strong></div></div>}<dl className="detail-grid"><DetailRow label={t("soarPage.kind")}>{selection.value.kind}</DetailRow><DetailRow label={t("soarPage.health")}>{selection.value.health_status}</DetailRow><DetailRow label={t("soarPage.authType")}>{selection.value.auth_type}</DetailRow><DetailRow label={t("soarPage.lastTested")}>{formatFullDateTime(selection.value.last_tested_at)}</DetailRow><DetailRow label={t("soarPage.endpoint")}>{selection.value.endpoint}</DetailRow><DetailRow label={t("soarPage.secretRef")}>{selection.value.secret_ref || t("common.notAvailable")}</DetailRow></dl>{selection.value.health_detail && <section className="detail-section"><h3>{t("soarPage.healthDetail")}</h3><p className="lead-description">{selection.value.health_error_class ? `${selection.value.health_error_class}: ` : ""}{selection.value.health_detail}</p></section>}<section className="detail-section"><h3>{t("soarPage.allowedActions")}</h3><div className="tag-list">{selection.value.allowed_actions?.map((action) => <Tag key={action}>{action}</Tag>)}</div></section><section className="detail-section"><h3>{t("soarPage.connectionTests")}</h3>{connectorTests.isPending ? <LoadingState rows={3} compact /> : connectorTests.isError ? <ErrorState error={connectorTests.error} compact /> : connectorTests.data?.items.length ? <div className="compact-list">{connectorTests.data.items.map((item) => <div key={item.test_id}><div><strong>{item.detail || item.test_id}</strong><small>{formatDateTime(item.completed_at || item.created_at)} · {item.latency_ms || 0} ms{item.http_status ? ` · HTTP ${item.http_status}` : ""}</small></div><StatusBadge value={item.status} /></div>)}</div> : <EmptyState title={t("soarPage.noConnectionTests")} icon={FlaskConical} />}</section>{(testConnector.isError || disableConnector.isError) && <ErrorState error={testConnector.error || disableConnector.error} compact />}<details className="raw-details"><summary>{t("common.rawData")}</summary><JsonBlock value={selection.value} /></details></>}
      </div>}
    </Drawer>
    <Modal open={decisionOpen && selection?.kind === "approval"} onClose={() => !decide.isPending && setDecisionOpen(false)} title={t("soarPage.decisionTitle")} footer={<><button className="button ghost" type="button" disabled={decide.isPending} onClick={() => setDecisionOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={approvalSubmitDisabled(reason, decide.isPending)} onClick={() => submitApprovalDecision(ApprovalDecision.APPROVE)}><CheckCircle2 size={16} />{t("common.approve")}</button><button className="button danger" type="button" disabled={approvalSubmitDisabled(reason, decide.isPending)} onClick={() => submitApprovalDecision(ApprovalDecision.REJECT)}><XCircle size={16} />{t("common.reject")}</button></>}><label className="form-field"><span>{t("common.reason")}</span><textarea rows={4} minLength={2} maxLength={2000} required value={reason} onChange={(event) => setReason(event.target.value)} /></label>{decide.isError && <InlineNotice tone="warning">{t(approvalErrorMessageKey(decide.error))}</InlineNotice>}</Modal>
    <Modal open={connectorEditorOpen} onClose={() => setConnectorEditorOpen(false)} title={editingConnector ? t("soarPage.editConnectorTitle") : t("soarPage.createConnectorTitle")} footer={<><button className="button ghost" type="button" onClick={() => setConnectorEditorOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={!connectorForm.name.trim() || !connectorForm.endpoint.trim() || !connectorForm.allowedActions.length || (connectorForm.kind === "EMAIL_SMTP" && !connectorForm.fromAddress.trim()) || (connectorForm.kind === "LDAP_DIRECTORY" && !connectorForm.baseDN.trim()) || (connectorForm.kind === "ITSM_REST" && connectorForm.provider === "JIRA" && (!connectorForm.projectKey.trim() || (connectorForm.allowedActions.includes("kcsp.ticket.close") && !connectorForm.closeTransitionId.trim()))) || (connectorForm.kind === "NOTIFICATION_REST" && connectorForm.provider === "SLACK_WEB_API" && !connectorForm.channel.trim()) || (connectorForm.kind === "NOTIFICATION_REST" && connectorForm.provider === "TEAMS_GRAPH" && (!connectorForm.teamId.trim() || !connectorForm.channelId.trim())) || saveConnector.isPending} onClick={() => saveConnector.mutate()}><Cable size={15} />{editingConnector ? t("common.save") : t("common.create")}</button></>}>
      <div className="parser-form-grid"><label className="form-field"><span>{t("common.name")}</span><input value={connectorForm.name} onChange={(event) => setConnectorForm({ ...connectorForm, name: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.kind")}</span><select value={connectorForm.kind} disabled={Boolean(editingConnector)} onChange={(event) => { const kind = event.target.value as ConnectorKind; const nativeBasic = kind === "EMAIL_SMTP" || kind === "LDAP_DIRECTORY"; setConnectorForm({ ...connectorForm, kind, allowedActions: [connectorActions[kind][0]], authType: nativeBasic ? "BASIC" : kind !== "WEBHOOK" && connectorForm.authType === "NONE" ? "BEARER" : connectorForm.authType, provider: kind === "ITSM_REST" ? "SERVICENOW" : kind === "NOTIFICATION_REST" || kind === "EDR_XDR_REST" ? "GENERIC" : connectorForm.provider }); }}>{Object.keys(connectorActions).map((kind) => <option key={kind} value={kind}>{kind}</option>)}</select></label><label className="form-field"><span>{t("soarPage.authType")}</span><select value={connectorForm.authType} disabled={connectorForm.kind === "EMAIL_SMTP" || connectorForm.kind === "LDAP_DIRECTORY"} onChange={(event) => setConnectorForm({ ...connectorForm, authType: event.target.value })}>{connectorForm.kind === "EMAIL_SMTP" || connectorForm.kind === "LDAP_DIRECTORY" ? <option value="BASIC">BASIC</option> : <>{connectorForm.kind === "WEBHOOK" && <option value="NONE">NONE</option>}<option value="BEARER">BEARER</option><option value="HMAC_SHA256">HMAC_SHA256</option><option value="BASIC">BASIC</option><option value="API_KEY">API_KEY</option>{connectorForm.kind === "EDR_XDR_REST" && <option value="OAUTH2_CLIENT_CREDENTIALS">OAUTH2_CLIENT_CREDENTIALS</option>}</>}</select></label></div>
      <label className="form-field"><span>{t("soarPage.endpoint")}</span><input type="url" placeholder={connectorForm.kind === "EMAIL_SMTP" ? "smtps://mail.example.edu:465" : connectorForm.kind === "LDAP_DIRECTORY" ? "ldaps://dc01.example.edu:636" : connectorForm.kind === "ITSM_REST" && connectorForm.provider === "SERVICENOW" ? "https://university.service-now.com" : connectorForm.kind === "ITSM_REST" && connectorForm.provider === "JIRA" ? "https://university.atlassian.net" : connectorForm.kind === "NOTIFICATION_REST" && connectorForm.provider === "SLACK_WEB_API" ? "https://slack.com" : connectorForm.kind === "NOTIFICATION_REST" && connectorForm.provider === "TEAMS_GRAPH" ? "https://graph.microsoft.com" : connectorForm.kind === "EDR_XDR_REST" && connectorForm.provider === "MICROSOFT_DEFENDER_ENDPOINT" ? "https://api.security.microsoft.com" : connectorForm.kind === "EDR_XDR_REST" && connectorForm.provider === "CROWDSTRIKE_FALCON" ? "https://api.crowdstrike.com" : "https://connector.example.edu/api/actions"} value={connectorForm.endpoint} onChange={(event) => setConnectorForm({ ...connectorForm, endpoint: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.secretRef")}</span><input disabled={connectorForm.authType === "NONE"} placeholder="env://KCSP_CONNECTOR_SECRET_NAME" value={connectorForm.secretRef} onChange={(event) => setConnectorForm({ ...connectorForm, secretRef: event.target.value })} /><small>{t("soarPage.secretRefHint")}</small></label>
      <label className="form-field"><span>{t("soarPage.allowedActions")}</span><select multiple size={Math.min(4, connectorActions[connectorForm.kind].length)} value={connectorForm.allowedActions} onChange={(event) => setConnectorForm({ ...connectorForm, allowedActions: Array.from(event.currentTarget.selectedOptions, (option) => option.value) })}>{connectorActions[connectorForm.kind].map((action) => <option key={action} value={action}>{action}</option>)}</select><small>{t("soarPage.multiSelectHint")}</small></label>
      {connectorForm.kind === "NOTIFICATION_REST" && <><div className="parser-form-grid"><label className="form-field"><span>{t("soarPage.provider")}</span><select value={connectorForm.provider} onChange={(event) => { const provider = event.target.value; setConnectorForm({ ...connectorForm, provider, authType: provider === "SLACK_WEB_API" || provider === "TEAMS_GRAPH" ? "BEARER" : connectorForm.authType }); }}><option value="SLACK_WEB_API">SLACK_WEB_API</option><option value="TEAMS_GRAPH">TEAMS_GRAPH</option><option value="GENERIC">GENERIC</option><option value="SLACK">SLACK_LEGACY</option><option value="TEAMS">TEAMS_LEGACY</option></select></label>{(connectorForm.provider === "SLACK" || connectorForm.provider === "SLACK_WEB_API") && <label className="form-field"><span>{t("soarPage.channel")}</span><input placeholder="C0123456789" value={connectorForm.channel} onChange={(event) => setConnectorForm({ ...connectorForm, channel: event.target.value })} /></label>}{connectorForm.provider === "TEAMS_GRAPH" && <><label className="form-field"><span>{t("soarPage.teamId")}</span><input value={connectorForm.teamId} onChange={(event) => setConnectorForm({ ...connectorForm, teamId: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.channelId")}</span><input placeholder="19:...@thread.tacv2" value={connectorForm.channelId} onChange={(event) => setConnectorForm({ ...connectorForm, channelId: event.target.value })} /></label></>}</div>{(connectorForm.provider === "SLACK_WEB_API" || connectorForm.provider === "TEAMS_GRAPH") && <small>{t("soarPage.nativeNotificationHint")}</small>}</>}
      {connectorForm.kind === "EDR_XDR_REST" && <><label className="form-field"><span>{t("soarPage.provider")}</span><select value={connectorForm.provider} onChange={(event) => { const provider = event.target.value; setConnectorForm({ ...connectorForm, provider, authType: provider === "GENERIC" ? (connectorForm.authType === "OAUTH2_CLIENT_CREDENTIALS" ? "BEARER" : connectorForm.authType) : "OAUTH2_CLIENT_CREDENTIALS" }); }}><option value="MICROSOFT_DEFENDER_ENDPOINT">MICROSOFT_DEFENDER_ENDPOINT</option><option value="CROWDSTRIKE_FALCON">CROWDSTRIKE_FALCON</option><option value="GENERIC">GENERIC</option></select></label>{connectorForm.provider !== "GENERIC" && <small>{t("soarPage.nativeEDRHint")}</small>}</>}
      {connectorForm.kind === "ITSM_REST" && <><div className="parser-form-grid"><label className="form-field"><span>{t("soarPage.provider")}</span><select value={connectorForm.provider} onChange={(event) => setConnectorForm({ ...connectorForm, provider: event.target.value })}><option value="SERVICENOW">SERVICENOW</option><option value="JIRA">JIRA</option><option value="GENERIC">GENERIC</option></select></label>{connectorForm.provider === "JIRA" && <><label className="form-field"><span>{t("soarPage.projectKey")}</span><input placeholder="SOC" value={connectorForm.projectKey} onChange={(event) => setConnectorForm({ ...connectorForm, projectKey: event.target.value.toUpperCase() })} /></label><label className="form-field"><span>{t("soarPage.issueType")}</span><input placeholder="Incident" value={connectorForm.issueType} onChange={(event) => setConnectorForm({ ...connectorForm, issueType: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.closeTransitionId")}</span><input inputMode="numeric" placeholder="31" value={connectorForm.closeTransitionId} onChange={(event) => setConnectorForm({ ...connectorForm, closeTransitionId: event.target.value })} /></label></>}</div>{connectorForm.provider !== "GENERIC" && <small>{t("soarPage.nativeITSMHint")}</small>}</>}
      {connectorForm.kind === "EMAIL_SMTP" && <div className="parser-form-grid"><label className="form-field"><span>{t("soarPage.fromAddress")}</span><input type="email" placeholder="kcsp-soc@example.edu" value={connectorForm.fromAddress} onChange={(event) => setConnectorForm({ ...connectorForm, fromAddress: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.heloName")}</span><input placeholder="soc.example.edu" value={connectorForm.heloName} onChange={(event) => setConnectorForm({ ...connectorForm, heloName: event.target.value })} /></label></div>}
      {connectorForm.kind === "LDAP_DIRECTORY" && <><div className="parser-form-grid"><label className="form-field"><span>{t("soarPage.directoryType")}</span><select value={connectorForm.directoryType} onChange={(event) => setConnectorForm({ ...connectorForm, directoryType: event.target.value, accountAttribute: "" })}><option value="ACTIVE_DIRECTORY">ACTIVE_DIRECTORY</option><option value="LDAP">LDAP</option></select></label><label className="form-field"><span>{t("soarPage.baseDN")}</span><input placeholder="OU=Students,DC=example,DC=edu" value={connectorForm.baseDN} onChange={(event) => setConnectorForm({ ...connectorForm, baseDN: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.accountAttribute")}</span><input placeholder={connectorForm.directoryType === "ACTIVE_DIRECTORY" ? "sAMAccountName" : "uid"} value={connectorForm.accountAttribute} onChange={(event) => setConnectorForm({ ...connectorForm, accountAttribute: event.target.value })} /></label></div>{connectorForm.directoryType === "LDAP" && <div className="parser-form-grid"><label className="form-field"><span>{t("soarPage.disabledAttribute")}</span><input value={connectorForm.disabledAttribute} onChange={(event) => setConnectorForm({ ...connectorForm, disabledAttribute: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.disabledValue")}</span><input value={connectorForm.disabledValue} onChange={(event) => setConnectorForm({ ...connectorForm, disabledValue: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.enabledValue")}</span><input value={connectorForm.enabledValue} onChange={(event) => setConnectorForm({ ...connectorForm, enabledValue: event.target.value })} /></label></div>}</>}
      {connectorForm.authType === "API_KEY" && <label className="form-field"><span>{t("soarPage.apiKeyHeader")}</span><input value={connectorForm.apiKeyHeader} onChange={(event) => setConnectorForm({ ...connectorForm, apiKeyHeader: event.target.value })} /></label>}
      <div className="parser-form-grid">{connectorForm.kind !== "EMAIL_SMTP" && connectorForm.kind !== "LDAP_DIRECTORY" && !(connectorForm.kind === "ITSM_REST" && connectorForm.provider !== "GENERIC") && !(connectorForm.kind === "NOTIFICATION_REST" && (connectorForm.provider === "SLACK_WEB_API" || connectorForm.provider === "TEAMS_GRAPH")) && !(connectorForm.kind === "EDR_XDR_REST" && connectorForm.provider !== "GENERIC") && <><label className="form-field"><span>{t("soarPage.healthMethod")}</span><select value={connectorForm.healthMethod} onChange={(event) => setConnectorForm({ ...connectorForm, healthMethod: event.target.value })}><option value="HEAD">HEAD</option><option value="GET">GET</option></select></label><label className="form-field"><span>{t("soarPage.healthPath")}</span><input placeholder="/health" value={connectorForm.healthPath} onChange={(event) => setConnectorForm({ ...connectorForm, healthPath: event.target.value })} /></label><label className="form-field"><span>{t("soarPage.expectedStatus")}</span><input type="number" min={100} max={599} value={connectorForm.expectedStatus} onChange={(event) => setConnectorForm({ ...connectorForm, expectedStatus: Number(event.target.value) })} /></label></>}<label className="form-field"><span>{t("soarPage.timeoutSeconds")}</span><input type="number" min={1} max={60} value={connectorForm.timeoutSeconds} onChange={(event) => setConnectorForm({ ...connectorForm, timeoutSeconds: Number(event.target.value) })} /></label><label className="form-field"><span>{t("soarPage.rateLimit")}</span><input type="number" min={1} max={600} value={connectorForm.rateLimitPerMinute} onChange={(event) => setConnectorForm({ ...connectorForm, rateLimitPerMinute: Number(event.target.value) })} /></label></div>{saveConnector.isError && <ErrorState error={saveConnector.error} compact />}
    </Modal>
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
