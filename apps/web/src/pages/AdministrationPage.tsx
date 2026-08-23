import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Building2, Gauge, KeyRound, Network, Plus, Power, RefreshCw, ShieldCheck, ShieldOff, UsersRound } from "lucide-react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { LicenseEnvelopeDto, LicenseLimitStatusDto, LicenseStatusDto, TenantSummaryDto } from "../api/types";
import { setTenantId } from "../auth/session";
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, StatusBadge } from "../components/ui";
import { formatFullDateTime } from "../utils/format";
import "./administration.css";

export default function AdministrationPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [licenseOpen, setLicenseOpen] = useState(false);
  const [tenantOpen, setTenantOpen] = useState(false);
  const [packageText, setPackageText] = useState("");
  const [tenantID, setTenantIDValue] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [tenantPage, setTenantPage] = useState(0);

  const status = useQuery({ queryKey: ["license-status"], queryFn: ({ signal }) => api.licenseStatus(signal), refetchInterval: 30_000 });
  const history = useQuery({ queryKey: ["license-history"], queryFn: ({ signal }) => api.licenses(signal) });
  const tenants = useQuery({ queryKey: ["admin-tenants", tenantPage], queryFn: ({ signal }) => api.adminTenants({ limit: 50, offset: tenantPage * 50 }, signal), refetchInterval: 30_000, retry: false });

  const install = useMutation({
    mutationFn: () => {
      const parsed = JSON.parse(packageText) as { envelope?: LicenseEnvelopeDto } | LicenseEnvelopeDto;
      const envelope = "envelope" in parsed && parsed.envelope ? parsed.envelope : parsed as LicenseEnvelopeDto;
      return api.installLicense(envelope);
    },
    onSuccess: () => {
      setLicenseOpen(false);
      setPackageText("");
      void queryClient.invalidateQueries({ queryKey: ["license-status"] });
      void queryClient.invalidateQueries({ queryKey: ["license-history"] });
      void queryClient.invalidateQueries({ queryKey: ["admin-tenants"] });
    },
  });
  const createTenant = useMutation({
    mutationFn: () => api.createTenant({ tenant_id: tenantID.trim(), display_name: tenantName.trim() }),
    onSuccess: () => {
      setTenantOpen(false);
      setTenantIDValue("");
      setTenantName("");
      setTenantPage(0);
      void queryClient.invalidateQueries({ queryKey: ["admin-tenants"] });
      void queryClient.invalidateQueries({ queryKey: ["license-status"] });
    },
  });
  const stateMutation = useMutation({
    mutationFn: ({ id, state }: { id: string; state: "ACTIVE" | "SUSPENDED" }) => api.updateTenantState(id, state),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["admin-tenants"] }),
  });

  const current = status.data;
  const enabledModules = current?.modules.filter((item) => item.enabled).length || 0;
  const warningCount = current?.warnings.length || 0;
  const tenantItems = tenants.data?.items || [];

  return <div className="page administration-page">
    <PageHeader eyebrow={t("adminPage.eyebrow")} title={t("adminPage.title")} subtitle={t("adminPage.subtitle")} actions={<div className="admin-actions"><button type="button" className="admin-button" onClick={() => setTenantOpen((value) => !value)}><Plus size={16} />{t("adminPage.addTenant")}</button><button type="button" className="admin-button primary" onClick={() => setLicenseOpen((value) => !value)}><KeyRound size={16} />{t("adminPage.installLicense")}</button></div>} />

    {status.isPending ? <section className="panel"><LoadingState rows={4} /></section> : status.isError ? <section className="panel"><ErrorState error={status.error} onRetry={() => void status.refetch()} /></section> : current && <LicenseCommand status={current} t={t} />}

    {licenseOpen && <form className="panel admin-form license-form" onSubmit={(event) => { event.preventDefault(); install.mutate(); }}>
      <div><span>{t("adminPage.offlinePackage")}</span><h2>{t("adminPage.installSigned")}</h2><p>{t("adminPage.packageHint")}</p></div>
      <textarea required spellCheck={false} value={packageText} onChange={(event) => setPackageText(event.target.value)} placeholder={'{ "key_id": "...", "payload": "...", "signature": "..." }'} />
      {install.isError && <ErrorState error={install.error} compact />}
      <div className="admin-form-actions"><button type="button" className="admin-button" onClick={() => setLicenseOpen(false)}>{t("common.cancel")}</button><button type="submit" disabled={install.isPending || !packageText.trim()} className="admin-button primary"><ShieldCheck size={16} />{install.isPending ? t("adminPage.verifying") : t("adminPage.verifyInstall")}</button></div>
    </form>}

    {tenantOpen && <form className="panel admin-form tenant-form" onSubmit={(event) => { event.preventDefault(); createTenant.mutate(); }}>
      <div><span>{t("adminPage.tenantControl")}</span><h2>{t("adminPage.createTenant")}</h2><p>{t("adminPage.tenantHint")}</p></div>
      <label><span>{t("adminPage.tenantId")}</span><input required pattern="[a-z0-9][a-z0-9-]{1,62}" value={tenantID} onChange={(event) => setTenantIDValue(event.target.value.toLowerCase())} placeholder="campus-west" /></label>
      <label><span>{t("adminPage.displayName")}</span><input required value={tenantName} onChange={(event) => setTenantName(event.target.value)} /></label>
      {createTenant.isError && <ErrorState error={createTenant.error} compact />}
      <div className="admin-form-actions"><button type="button" className="admin-button" onClick={() => setTenantOpen(false)}>{t("common.cancel")}</button><button type="submit" disabled={createTenant.isPending} className="admin-button primary"><Building2 size={16} />{t("adminPage.create")}</button></div>
    </form>}

    <section className="metrics-grid compact-metrics admin-metrics">
      <MetricCard label={t("adminPage.enabledModules")} value={`${enabledModules}/8`} icon={Network} tone={enabledModules > 0 ? "good" : "critical"} />
      <MetricCard label={t("adminPage.managedTenants")} value={tenants.data?.total || status.data?.limits.find((item) => item.name === "tenants")?.used || 0} icon={Building2} />
      <MetricCard label={t("adminPage.warnings")} value={warningCount} icon={warningCount ? ShieldOff : ShieldCheck} tone={warningCount ? "critical" : "good"} />
      <MetricCard label={t("adminPage.policyMode")} value={current?.read_only ? t("adminPage.readOnly") : t("adminPage.fullAccess")} icon={Gauge} tone={current?.read_only ? "critical" : "good"} />
    </section>

    {current && <div className="admin-grid">
      <section className="panel entitlement-panel"><div className="admin-panel-head"><div><span>{t("adminPage.entitlements")}</span><h2>{t("adminPage.modules")}</h2></div><small>{current.license?.payload.customer || t("adminPage.noCustomer")}</small></div><div className="module-grid">{current.modules.map((item) => <div key={item.module} className={item.enabled ? "enabled" : "disabled"}>{item.enabled ? <ShieldCheck size={18} /> : <ShieldOff size={18} />}<div><strong>{item.module}</strong><small>{item.enabled ? t("adminPage.entitled") : t("adminPage.notEntitled")}</small></div></div>)}</div></section>
      <section className="panel quota-panel"><div className="admin-panel-head"><div><span>{t("adminPage.capacity")}</span><h2>{t("adminPage.licensedLimits")}</h2></div><small>{t("adminPage.zeroUnlimited")}</small></div><div className="quota-list">{current.limits.map((item) => <QuotaRow key={item.name} item={item} t={t} />)}</div></section>
    </div>}

    <section className="panel tenant-panel">
      <div className="admin-panel-head"><div><span>{t("adminPage.msspPlane")}</span><h2>{t("adminPage.tenantHealth")}</h2></div><button type="button" className="admin-icon-button" onClick={() => void tenants.refetch()} aria-label={t("common.refresh")}><RefreshCw size={16} /></button></div>
      {tenants.isPending ? <LoadingState rows={6} /> : tenants.isError ? <div className="permission-state"><KeyRound size={24} /><div><strong>{t("adminPage.platformPermission")}</strong><p>{t("adminPage.platformPermissionHint")}</p></div></div> : !tenantItems.length ? <EmptyState title={t("adminPage.noTenants")} icon={Building2} /> : <><div className="table-scroll"><table className="data-table tenant-table"><thead><tr><th>{t("common.status")}</th><th>{t("adminPage.tenant")}</th><th>{t("adminPage.license")}</th><th>EPS / 24h</th><th>{t("common.alerts")} / {t("common.incidents")}</th><th>{t("adminPage.collectors")}</th><th /></tr></thead><tbody>{tenantItems.map((item) => <TenantRow key={item.tenant.tenant_id} item={item} onSwitch={() => { setTenantId(item.tenant.tenant_id); window.location.assign("/administration"); }} onState={(state) => stateMutation.mutate({ id: item.tenant.tenant_id, state })} t={t} />)}</tbody></table></div><div className="tenant-pagination"><button type="button" disabled={tenantPage === 0} onClick={() => setTenantPage((value) => Math.max(0, value - 1))}>{t("common.previous")}</button><span>{tenantPage * 50 + 1}–{Math.min((tenantPage + 1) * 50, tenants.data?.total || 0)} / {tenants.data?.total || 0}</span><button type="button" disabled={(tenantPage + 1) * 50 >= (tenants.data?.total || 0)} onClick={() => setTenantPage((value) => value + 1)}>{t("common.next")}</button></div></>}
      {stateMutation.isError && <ErrorState error={stateMutation.error} compact />}
    </section>

    <section className="panel license-history"><div className="admin-panel-head"><div><span>{t("adminPage.chainOfTrust")}</span><h2>{t("adminPage.licenseHistory")}</h2></div><small>{history.data?.total || 0}</small></div>{history.isPending ? <LoadingState rows={3} /> : history.isError ? <ErrorState error={history.error} /> : !history.data?.items.length ? <EmptyState title={t("adminPage.noLicenseHistory")} icon={KeyRound} /> : <div className="license-timeline">{history.data.items.map((item) => <div key={item.license_id} className={item.active ? "active" : "historical"}><span /><div><strong>{item.payload.customer}</strong><small>{item.license_id} · {item.key_id}</small><code>{item.fingerprint_sha256}</code></div><div><StatusBadge value={item.active ? "ACTIVE" : "SUPERSEDED"} /><small>{formatFullDateTime(item.installed_at)}</small></div></div>)}</div>}</section>
  </div>;
}

type Translate = ReturnType<typeof useTranslation>["t"];

function LicenseCommand({ status, t }: { status: LicenseStatusDto; t: Translate }) {
  const expires = status.license?.payload.expires_at;
  return <section className={`license-command panel state-${status.state.toLowerCase()}`}><div className="license-state-mark"><KeyRound size={28} /><div><span>{t("adminPage.licenseState")}</span><strong>{status.state}</strong><small>{status.tenant_id}</small></div></div><div className="license-validity"><span>{t("adminPage.validity")}</span><strong>{expires ? formatFullDateTime(expires) : t("adminPage.notApplicable")}</strong><small>{status.license?.license_id || t("adminPage.noSignedLicense")}</small></div><div className="license-warning-stack">{status.warnings.length ? status.warnings.map((warning) => <span key={warning}>{warningLabel(warning, t)}</span>) : <span className="clear"><ShieldCheck size={15} />{t("adminPage.noWarnings")}</span>}</div></section>;
}

function QuotaRow({ item, t }: { item: LicenseLimitStatusDto; t: Translate }) {
  const width = item.limit > 0 ? Math.min(item.percent, 100) : 0;
  return <div className={item.exceeded ? "quota-row exceeded" : "quota-row"}><div><strong>{t(`adminPage.limits.${item.name}`, { defaultValue: item.name })}</strong><span>{formatQuota(item.used)} / {item.limit > 0 ? formatQuota(item.limit) : "∞"} {item.unit}</span></div><div className="quota-rail"><i style={{ width: `${width}%` }} /></div><small>{item.limit > 0 ? `${item.percent}%` : t("adminPage.unlimited")}</small></div>;
}

function TenantRow({ item, onSwitch, onState, t }: { item: TenantSummaryDto; onSwitch: () => void; onState: (state: "ACTIVE" | "SUSPENDED") => void; t: Translate }) {
  const active = item.tenant.state === "ACTIVE";
  return <tr><td><StatusBadge value={item.tenant.state} /></td><td className="primary-cell"><strong>{item.tenant.display_name}</strong><small>{item.tenant.tenant_id}</small></td><td><StatusBadge value={item.license_state} /></td><td><strong>{formatQuota(item.ingestion_eps)}</strong><small>{formatQuota(item.events_24h)}</small></td><td>{formatQuota(item.open_alerts)} / {formatQuota(item.open_incidents)}</td><td><span className={item.collectors_offline ? "tenant-health bad" : "tenant-health"}>{item.collectors_online} / {item.collectors_offline}</span></td><td><div className="tenant-actions"><button type="button" onClick={onSwitch} title={t("adminPage.switchTenant")}><Activity size={15} /></button><button type="button" onClick={() => onState(active ? "SUSPENDED" : "ACTIVE")} title={active ? t("adminPage.suspend") : t("adminPage.activate")}>{active ? <Power size={15} /> : <ShieldCheck size={15} />}</button></div></td></tr>;
}

function formatQuota(value: number): string {
  return Intl.NumberFormat(undefined, { maximumFractionDigits: 2, notation: value >= 1000000 ? "compact" : "standard" }).format(value);
}

function warningLabel(value: string, t: Translate): string {
  if (value.startsWith("QUOTA_EXCEEDED:")) return t("adminPage.quotaExceeded", { limit: t(`adminPage.limits.${value.split(":")[1]}`) });
  if (value.startsWith("QUOTA_WARNING:")) return t("adminPage.quotaWarning", { limit: t(`adminPage.limits.${value.split(":")[1]}`) });
  return t(`adminPage.warningCodes.${value}`, { defaultValue: value });
}
