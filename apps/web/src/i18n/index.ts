import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { en } from "./locales/en";
import { kk } from "./locales/kk";
import { ru } from "./locales/ru";
import {
  normalizeLanguage,
  readLanguagePreference,
  resolveInitialLanguage,
  supportedLanguages,
  writeLanguagePreference,
  type LanguageStorage,
} from "./language";

function browserStorage(): LanguageStorage | undefined {
  if (typeof window === "undefined") return undefined;
  try {
    return window.localStorage;
  } catch {
    return undefined;
  }
}

function browserLanguages(): readonly string[] {
  if (typeof navigator === "undefined") return [];
  return navigator.languages?.length ? navigator.languages : navigator.language ? [navigator.language] : [];
}

const storage = browserStorage();
const initialLanguage = resolveInitialLanguage(readLanguagePreference(storage), browserLanguages());

void i18n.use(initReactI18next).init({
  resources: {
    ru: { translation: ru },
    kk: { translation: kk },
    en: { translation: en },
  },
  lng: initialLanguage,
  supportedLngs: supportedLanguages,
  load: "languageOnly",
  fallbackLng: "ru",
  interpolation: { escapeValue: false },
  returnNull: false,
});

if (typeof document !== "undefined") document.documentElement.lang = initialLanguage;

i18n.on("languageChanged", (language) => {
  const normalized = normalizeLanguage(language) || "ru";
  writeLanguagePreference(storage, normalized);
  if (typeof document !== "undefined") document.documentElement.lang = normalized;
});

export default i18n;
