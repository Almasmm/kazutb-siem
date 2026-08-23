import { describe, expect, it } from "vitest";
import { en } from "./locales/en";
import { kk } from "./locales/kk";
import { ru } from "./locales/ru";

function leafKeys(value: unknown, prefix = ""): string[] {
  if (!value || typeof value !== "object") return [prefix];
  return Object.entries(value).flatMap(([key, child]) => leafKeys(child, prefix ? `${prefix}.${key}` : key));
}

function leafValues(value: unknown, prefix = ""): Record<string, string> {
  if (typeof value === "string") return { [prefix]: value };
  if (!value || typeof value !== "object") return {};
  return Object.assign({}, ...Object.entries(value).map(([key, child]) => leafValues(child, prefix ? `${prefix}.${key}` : key)));
}

function placeholders(value: string): string[] {
  return [...value.matchAll(/{{\s*([A-Za-z0-9_.-]+)\s*}}/g)]
    .map((match) => match[1])
    .filter((placeholder): placeholder is string => Boolean(placeholder))
    .sort();
}

const sourceFiles = import.meta.glob(["../**/*.ts", "../**/*.tsx", "!../**/*.test.ts", "!../i18n/locales/**"], {
  eager: true,
  import: "default",
  query: "?raw",
}) as Record<string, string>;

describe("locale dictionaries", () => {
  it("keep RU, KK and EN keys in parity", () => {
    const baseline = leafKeys(ru).sort();
    expect(leafKeys(kk).sort()).toEqual(baseline);
    expect(leafKeys(en).sort()).toEqual(baseline);
  });

  it("contains the Kazakh alphabet glyphs used by the interface", () => {
    const content = JSON.stringify(kk).toLocaleUpperCase("kk-KZ");
    for (const glyph of ["Ә", "Ғ", "Қ", "Ң", "Ө", "Ұ", "Ү", "І"]) {
      expect(content).toContain(glyph);
    }
  });

  it("keeps interpolation placeholders in parity", () => {
    const ruValues = leafValues(ru);
    const kkValues = leafValues(kk);
    const enValues = leafValues(en);
    for (const key of Object.keys(ruValues)) {
      const baseline = placeholders(ruValues[key] || "");
      expect(placeholders(kkValues[key] || ""), `KK placeholders for ${key}`).toEqual(baseline);
      expect(placeholders(enValues[key] || ""), `EN placeholders for ${key}`).toEqual(baseline);
    }
  });

  it("defines every literal translation key used by the application", () => {
    const defined = new Set(leafKeys(ru));
    const used = new Set<string>();
    for (const source of Object.values(sourceFiles)) {
      for (const match of source.matchAll(/\bt\(\s*["']([A-Za-z0-9_.-]+)["']/g)) {
        if (match[1]) used.add(match[1]);
      }
    }
    expect([...used].filter((key) => !defined.has(key)).sort()).toEqual([]);
  });
});
