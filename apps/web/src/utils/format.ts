import i18n from "../i18n";
import { normalizeLanguage } from "../i18n/language";
import { runtimeConfig } from "../config/runtime";

export const TENANT_TIME_ZONE = runtimeConfig.timeZone;

const localeMap: Record<string, string> = {
  ru: "ru-KZ",
  kk: "kk-KZ",
  en: "en-US",
};

export function activeLocale(): string {
  return localeMap[normalizeLanguage(i18n.resolvedLanguage || i18n.language) || "ru"] || "ru-KZ";
}

export function formatDateTime(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(activeLocale(), {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: TENANT_TIME_ZONE,
  }).format(date);
}

export function formatFullDateTime(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(activeLocale(), {
    dateStyle: "medium",
    timeStyle: "long",
    timeZone: TENANT_TIME_ZONE,
  }).format(date);
}

export function formatNumber(value?: number): string {
  return new Intl.NumberFormat(activeLocale(), { maximumFractionDigits: 1 }).format(value ?? 0);
}

export function formatBytes(value?: number): string {
  if (value == null || !Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const unit = value === 0 ? 0 : Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const amount = value / 1024 ** unit;
  return `${new Intl.NumberFormat(activeLocale(), { maximumFractionDigits: unit === 0 ? 0 : 1 }).format(amount)} ${units[unit]}`;
}

export function formatTimeZoneLabel(at = new Date()): string {
  const offset = new Intl.DateTimeFormat("en-US", {
    timeZone: TENANT_TIME_ZONE,
    timeZoneName: "longOffset",
  }).formatToParts(at).find((part) => part.type === "timeZoneName")?.value;
  return offset ? `${offset.replace(/^GMT/, "UTC")} · ${TENANT_TIME_ZONE}` : TENANT_TIME_ZONE;
}

export function titleCaseCode(value?: string): string {
  if (!value) return "—";
  return value.toLowerCase().replaceAll("_", " ").replace(/^./, (character) => character.toUpperCase());
}

export function eventId(event: { id?: string; event_id?: string }): string {
  return event.event_id || event.id || "—";
}

export function sourceLabel(source: unknown, fallback?: string): string {
  if (typeof source === "string") return source;
  if (source && typeof source === "object") {
    const record = source as Record<string, unknown>;
    return [record.vendor, record.product, record.type].filter(Boolean).join(" / ") || fallback || "—";
  }
  return fallback || "—";
}
