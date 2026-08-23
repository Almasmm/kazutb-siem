export const supportedLanguages = ["ru", "kk", "en"] as const;

export type SupportedLanguage = (typeof supportedLanguages)[number];

export interface LanguageStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export function normalizeLanguage(value?: string | null): SupportedLanguage | null {
  const language = value?.trim().toLowerCase().split(/[-_]/, 1)[0];
  return supportedLanguages.find((candidate) => candidate === language) || null;
}

export function resolveInitialLanguage(stored: string | null, preferred: readonly string[]): SupportedLanguage {
  const persisted = normalizeLanguage(stored);
  if (persisted) return persisted;
  for (const candidate of preferred) {
    const normalized = normalizeLanguage(candidate);
    if (normalized) return normalized;
  }
  return "ru";
}

export function readLanguagePreference(storage?: LanguageStorage): SupportedLanguage | null {
  if (!storage) return null;
  try {
    return normalizeLanguage(storage.getItem("kcsp.language"));
  } catch {
    return null;
  }
}

export function writeLanguagePreference(storage: LanguageStorage | undefined, language: SupportedLanguage): void {
  if (!storage) return;
  try {
    storage.setItem("kcsp.language", language);
  } catch {
    // Browser privacy controls may deny storage; language still applies to the live session.
  }
}
