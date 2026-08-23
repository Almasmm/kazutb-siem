import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Clock3, Copy, KeyRound, Plus, RefreshCw, RotateCw, ShieldCheck, ShieldOff, Workflow } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { ServiceAccountDto, ServiceAccountIssueDto } from "../api/types";
import { DetailRow, Drawer, EmptyState, ErrorState, InlineNotice, LoadingState, MetricCard, Modal, PageHeader, StatusBadge, Tag } from "../components/ui";
import { formatFullDateTime } from "../utils/format";
import "./service-accounts.css";

const automationScopes = [
  "platform.overview.read", "siem.events.read", "siem.events.export", "siem.events.ingest", "siem.findings.read", "siem.hunt.read", "siem.hunt.execute",
  "soc.alerts.read", "soc.alerts.manage", "soc.incidents.read", "soc.incidents.create", "soc.incidents.manage",
  "ti.indicators.read", "ti.indicators.manage", "reports.read", "reports.generate", "soar.playbooks.read", "soar.playbooks.execute",
  "platform.collectors.read", "platform.collectors.heartbeat",
] as const;

export default function ServiceAccountsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<ServiceAccountDto | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [issued, setIssued] = useState<ServiceAccountIssueDto | null>(null);
  const [copied, setCopied] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [ttlDays, setTtlDays] = useState(90);
  const [scopes, setScopes] = useState<string[]>(["siem.events.read"]);

  const session = useQuery({ queryKey: ["session"], queryFn: ({ signal }) => api.session(signal), staleTime: 60_000 });
  const can = (permission: string) => Boolean(session.data?.permissions.includes("*") || session.data?.permissions.includes(permission));
  const canRead = can("platform.service_accounts.read");
  const canManage = can("platform.service_accounts.write");
  const accounts = useQuery({ queryKey: ["service-accounts"], queryFn: ({ signal }) => api.serviceAccounts(signal), enabled: session.isSuccess && canRead, refetchInterval: 30_000 });
  const availableScopes = useMemo(() => automationScopes.filter((scope) => can(scope)), [session.data?.permissions]);

  const createAccount = useMutation({
    mutationFn: () => api.createServiceAccount({ name: name.trim(), description: description.trim(), scopes, expires_in_seconds: ttlDays * 86_400 }),
    onSuccess: (issue) => {
      setIssued(issue); setCreateOpen(false); setName(""); setDescription(""); setScopes(["siem.events.read"]); setCopied(false);
      void queryClient.invalidateQueries({ queryKey: ["service-accounts"] });
    },
  });
  const rotateAccount = useMutation({
    mutationFn: (item: ServiceAccountDto) => api.rotateServiceAccount(item.service_account_id, { expires_in_seconds: ttlDays * 86_400 }),
    onSuccess: (issue) => {
      setIssued(issue); setSelected(issue.service_account); setRotateOpen(false); setCopied(false);
      void queryClient.invalidateQueries({ queryKey: ["service-accounts"] });
    },
  });
  const revokeAccount = useMutation({
    mutationFn: (item: ServiceAccountDto) => api.revokeServiceAccount(item.service_account_id),
    onSuccess: (item) => {
      setSelected(item); setRevokeOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["service-accounts"] });
    },
  });

  const items = accounts.data?.items || [];
  const active = items.filter((item) => item.state === "ACTIVE").length;
  const expiring = items.filter((item) => item.state === "ACTIVE" && new Date(item.expires_at).getTime() - Date.now() < 7 * 86_400_000).length;
  const copySecret = async () => {
    if (!issued) return;
    await navigator.clipboard.writeText(issued.access_token);
    setCopied(true);
  };
  const toggleScope = (scope: string) => setScopes((current) => current.includes(scope) ? current.filter((item) => item !== scope) : [...current, scope]);

  if (session.isPending) return <div className="page"><section className="panel"><LoadingState rows={6} /></section></div>;
  if (session.isError) return <div className="page"><section className="panel"><ErrorState error={session.error} /></section></div>;

  return <div className="page service-accounts-page">
    <PageHeader eyebrow={t("serviceAccountsPage.eyebrow")} title={t("serviceAccountsPage.title")} subtitle={t("serviceAccountsPage.subtitle")} actions={canManage ? <button className="button primary" type="button" onClick={() => setCreateOpen(true)}><Plus size={16} />{t("serviceAccountsPage.create")}</button> : undefined} />

    {!canRead ? <section className="panel permission-state"><KeyRound size={26} /><div><strong>{t("serviceAccountsPage.permissionRequired")}</strong><p>{t("serviceAccountsPage.permissionHint")}</p></div></section> : <>
      <section className="metrics-grid compact-metrics">
        <MetricCard label={t("serviceAccountsPage.total")} value={items.length} icon={KeyRound} />
        <MetricCard label={t("serviceAccountsPage.active")} value={active} icon={ShieldCheck} tone="good" />
        <MetricCard label={t("serviceAccountsPage.expiring")} value={expiring} icon={Clock3} tone={expiring ? "warning" : "good"} />
        <MetricCard label={t("serviceAccountsPage.revoked")} value={items.filter((item) => item.state === "REVOKED").length} icon={ShieldOff} />
      </section>

      <section className="panel service-account-ledger">
        <div className="panel-heading"><div><span className="eyebrow">{t("serviceAccountsPage.tenantBound")}</span><h2>{t("serviceAccountsPage.ledger")}</h2></div><button className="icon-button" type="button" onClick={() => void accounts.refetch()} aria-label={t("common.refresh")}><RefreshCw size={16} /></button></div>
        {accounts.isPending ? <LoadingState rows={6} /> : accounts.isError ? <ErrorState error={accounts.error} onRetry={() => void accounts.refetch()} /> : !items.length ? <EmptyState title={t("serviceAccountsPage.noAccounts")} icon={KeyRound} /> : <div className="table-scroll"><table className="data-table"><thead><tr><th>{t("common.status")}</th><th>{t("common.name")}</th><th>{t("serviceAccountsPage.scopes")}</th><th>{t("serviceAccountsPage.lastUsed")}</th><th>{t("serviceAccountsPage.expires")}</th><th /></tr></thead><tbody>{items.map((item) => <tr key={item.service_account_id} className="clickable-row" onClick={() => setSelected(item)}><td><StatusBadge value={item.state} /></td><td className="primary-cell"><strong>{item.name}</strong><small>{item.service_account_id}</small></td><td><span className="scope-count">{item.scopes.length}</span></td><td>{formatFullDateTime(item.last_used_at)}</td><td>{formatFullDateTime(item.expires_at)}</td><td><KeyRound size={15} /></td></tr>)}</tbody></table></div>}
      </section>
    </>}

    <Drawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.name || ""} eyebrow={t("serviceAccountsPage.serviceIdentity")} footer={selected && selected.state === "ACTIVE" && canManage ? <><button className="button ghost" type="button" onClick={() => setRotateOpen(true)}><RotateCw size={15} />{t("serviceAccountsPage.rotate")}</button><button className="button danger" type="button" onClick={() => setRevokeOpen(true)}><ShieldOff size={15} />{t("serviceAccountsPage.revoke")}</button></> : undefined}>
      {selected && <><dl className="detail-grid"><DetailRow label={t("common.status")}><StatusBadge value={selected.state} /></DetailRow><DetailRow label={t("serviceAccountsPage.tokenVersion")}>v{selected.token_version}</DetailRow><DetailRow label={t("serviceAccountsPage.createdBy")}>{selected.created_by}</DetailRow><DetailRow label={t("serviceAccountsPage.created")}>{formatFullDateTime(selected.created_at)}</DetailRow><DetailRow label={t("serviceAccountsPage.lastUsed")}>{formatFullDateTime(selected.last_used_at)}</DetailRow><DetailRow label={t("serviceAccountsPage.expires")}>{formatFullDateTime(selected.expires_at)}</DetailRow></dl>{selected.description && <p className="lead-description">{selected.description}</p>}<section className="detail-section"><h3>{t("serviceAccountsPage.explicitScopes")}</h3><div className="tag-list">{selected.scopes.map((scope) => <Tag key={scope} tone="accent">{scope}</Tag>)}</div></section><InlineNotice tone="info"><Workflow size={17} />{t("serviceAccountsPage.auditNotice")}</InlineNotice></>}
    </Drawer>

    <Modal open={createOpen} onClose={() => setCreateOpen(false)} title={t("serviceAccountsPage.createTitle")} footer={<><button className="button ghost" type="button" onClick={() => setCreateOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={!name.trim() || !scopes.length || createAccount.isPending} onClick={() => createAccount.mutate()}><KeyRound size={15} />{t("serviceAccountsPage.create")}</button></>}>
      <div className="service-account-form"><label className="form-field"><span>{t("common.name")}</span><input value={name} maxLength={128} onChange={(event) => setName(event.target.value)} placeholder={t("serviceAccountsPage.namePlaceholder")} /></label><label className="form-field"><span>{t("serviceAccountsPage.description")}</span><textarea value={description} maxLength={1024} onChange={(event) => setDescription(event.target.value)} /></label><label className="form-field"><span>{t("serviceAccountsPage.ttlDays")}</span><input type="number" min={1} max={365} value={ttlDays} onChange={(event) => setTtlDays(Math.min(365, Math.max(1, Number(event.target.value))))} /></label><div className="scope-picker"><div><strong>{t("serviceAccountsPage.scopeBuilder")}</strong><small>{t("serviceAccountsPage.scopeHint")}</small></div><div className="scope-options">{availableScopes.map((scope) => <button key={scope} type="button" className={scopes.includes(scope) ? "selected" : ""} onClick={() => toggleScope(scope)}><span>{scopes.includes(scope) && <Check size={13} />}</span><code>{scope}</code></button>)}</div></div>{createAccount.isError && <ErrorState error={createAccount.error} compact />}</div>
    </Modal>

    <Modal open={rotateOpen} onClose={() => setRotateOpen(false)} title={t("serviceAccountsPage.rotateTitle")} footer={<><button className="button ghost" type="button" onClick={() => setRotateOpen(false)}>{t("common.cancel")}</button><button className="button primary" type="button" disabled={!selected || rotateAccount.isPending} onClick={() => selected && rotateAccount.mutate(selected)}><RotateCw size={15} />{t("serviceAccountsPage.rotate")}</button></>}><InlineNotice tone="warning"><ShieldOff size={17} />{t("serviceAccountsPage.rotateWarning")}</InlineNotice><label className="form-field"><span>{t("serviceAccountsPage.ttlDays")}</span><input type="number" min={1} max={365} value={ttlDays} onChange={(event) => setTtlDays(Math.min(365, Math.max(1, Number(event.target.value))))} /></label>{rotateAccount.isError && <ErrorState error={rotateAccount.error} compact />}</Modal>

    <Modal open={revokeOpen} onClose={() => setRevokeOpen(false)} title={t("serviceAccountsPage.revokeTitle")} footer={<><button className="button ghost" type="button" onClick={() => setRevokeOpen(false)}>{t("common.cancel")}</button><button className="button danger" type="button" disabled={!selected || revokeAccount.isPending} onClick={() => selected && revokeAccount.mutate(selected)}><ShieldOff size={15} />{t("serviceAccountsPage.revoke")}</button></>}><InlineNotice tone="warning"><ShieldOff size={17} />{t("serviceAccountsPage.revokeWarning")}</InlineNotice>{revokeAccount.isError && <ErrorState error={revokeAccount.error} compact />}</Modal>

    <Modal open={Boolean(issued)} onClose={() => setIssued(null)} title={t("serviceAccountsPage.secretTitle")} footer={<button className="button primary" type="button" onClick={() => setIssued(null)}>{t("serviceAccountsPage.confirmStored")}</button>}><InlineNotice tone="warning"><KeyRound size={17} />{t("serviceAccountsPage.secretWarning")}</InlineNotice>{issued && <div className="issued-secret"><div><span>{issued.token_type}</span><strong>{issued.service_account.name}</strong></div><code>{issued.access_token}</code><button className="button ghost" type="button" onClick={() => void copySecret()}>{copied ? <Check size={15} /> : <Copy size={15} />}{copied ? t("serviceAccountsPage.copied") : t("serviceAccountsPage.copy")}</button></div>}</Modal>
  </div>;
}
