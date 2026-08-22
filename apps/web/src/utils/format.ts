import i18n from "../i18n";

export const TENANT_TIME_ZONE = import.meta.env.VITE_TIME_ZONE || "Asia/Almaty";

const localeMap: Record<string, string> = {
  ru: "ru-KZ",
  kk: "kk-KZ",
  en: "en-US",
};

export function activeLocale(): string {
  return localeMap[i18n.resolvedLanguage || i18n.language] || "ru-KZ";
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
  return new Intl.NumberFormat(activeLocale(), { maximumFractionDigits: 1 }).format(value || 0);
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
