import { describe, expect, it } from "vitest";
import { normalizeLanguage, readLanguagePreference, resolveInitialLanguage, writeLanguagePreference } from "./language";

describe("language preference", () => {
  it("normalizes supported regional language tags", () => {
    expect(normalizeLanguage("kk-KZ")).toBe("kk");
    expect(normalizeLanguage("RU_kz")).toBe("ru");
    expect(normalizeLanguage("en-GB")).toBe("en");
    expect(normalizeLanguage("de-DE")).toBeNull();
  });

  it("prefers persisted language, then browser languages, then Russian", () => {
    expect(resolveInitialLanguage("en", ["kk-KZ"])).toBe("en");
    expect(resolveInitialLanguage(null, ["de-DE", "kk-KZ", "ru-RU"])).toBe("kk");
    expect(resolveInitialLanguage(null, ["de-DE"])).toBe("ru");
  });

  it("does not fail bootstrap when browser storage is denied", () => {
    const denied = {
      getItem: () => { throw new Error("denied"); },
      setItem: () => { throw new Error("denied"); },
    };
    expect(readLanguagePreference(denied)).toBeNull();
    expect(() => writeLanguagePreference(denied, "kk")).not.toThrow();
  });
});
