import { describe, expect, it } from "vitest";
import { en } from "./locales/en";
import { kk } from "./locales/kk";
import { ru } from "./locales/ru";

function leafKeys(value: unknown, prefix = ""): string[] {
  if (!value || typeof value !== "object") return [prefix];
  return Object.entries(value).flatMap(([key, child]) => leafKeys(child, prefix ? `${prefix}.${key}` : key));
}

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
});
