import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { en } from "./locales/en";
import { kk } from "./locales/kk";
import { ru } from "./locales/ru";

const storedLanguage = localStorage.getItem("kcsp.language");
const initialLanguage = storedLanguage === "kk" || storedLanguage === "en" ? storedLanguage : "ru";

void i18n.use(initReactI18next).init({
  resources: {
    ru: { translation: ru },
    kk: { translation: kk },
    en: { translation: en },
  },
  lng: initialLanguage,
  fallbackLng: "ru",
  interpolation: { escapeValue: false },
  returnNull: false,
});

document.documentElement.lang = initialLanguage;

i18n.on("languageChanged", (language) => {
  const normalized = language.startsWith("kk") ? "kk" : language.startsWith("en") ? "en" : "ru";
  localStorage.setItem("kcsp.language", normalized);
  document.documentElement.lang = normalized;
});

export default i18n;
