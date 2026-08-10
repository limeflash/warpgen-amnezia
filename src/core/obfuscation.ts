/**
 * AmneziaWG obfuscation profiles (AWG 1.0 → 3.0).
 *
 * Each generation adds parameters on top of the previous one:
 *   1.0  Jc/Jmin/Jmax + S1/S2 + H1–H4            (junk packets, padding, magic headers)
 *   1.5  + I1 (CPS — a fake first packet mimicking QUIC/TLS/DNS/…)
 *   2.0  + S3/S4 and H1–H4 as ranges (`5-60000`) + optional I2–I5 chain
 *   3.0  + HeaderProtectionKey (ChaCha20 over the WG header) / ContentPaddingAddition / timers
 *
 * ⚠ Compatibility: a client older than the chosen profile REJECTS the config,
 * so the default stays at the widely-supported level and anything newer is an
 * explicit choice (see `compatWarning`).
 */

export type AwgVersion = "1.0" | "1.5" | "2.0" | "3.0";

export interface JunkParams {
  jc: number;
  jmin: number;
  jmax: number;
}

export interface ObfuscationOptions {
  version?: AwgVersion;
  junk?: JunkParams;
  /** S1/S2 (and S3/S4 on 2.0+). */
  s1?: number;
  s2?: number;
  s3?: number;
  s4?: number;
  /** H1–H4: plain numbers, or `"5-60000"` ranges on 2.0+. */
  h?: [string, string, string, string];
  /** I1 mask token (`<b 0x…>`), already resolved by i1.ts. */
  i1?: string;
  /** Optional extra CPS packets (1.5+). */
  i2?: string;
  i3?: string;
  i4?: string;
  i5?: string;
  /** AWG 3.0: base64 ChaCha20 key; `true` generates a fresh one. */
  headerProtectionKey?: string | true;
  contentPaddingAddition?: number;
}

export const DEFAULT_VERSION: AwgVersion = "1.5";

/** Junk presets shown in the UI. */
export const JUNK_PRESETS: Record<string, JunkParams> = {
  "1": { jc: 4, jmin: 40, jmax: 70 },
  "2": { jc: 120, jmin: 23, jmax: 911 },
  "3": { jc: 10, jmin: 100, jmax: 300 },
};

/** Non-default magic headers (defaults 1/2/3/4 are the WireGuard signature DPI looks for). */
export const DEFAULT_H: [string, string, string, string] = ["1", "2", "3", "4"];
/** Randomised H ranges for 2.0 — each connection picks a value from the range. */
export function randomHRanges(): [string, string, string, string] {
  const span = 60000;
  return [1, 2, 3, 4].map((i) => `${(i - 1) * span + 5}-${i * span}`) as [string, string, string, string];
}

export function compatWarning(v: AwgVersion): string | null {
  switch (v) {
    case "1.0":
      return null;
    case "1.5":
      return "I1 (CPS) требует AmneziaWG 1.5+ — старые клиенты не поймут параметр.";
    case "2.0":
      return "S3/S4 и H-диапазоны требуют AmneziaWG 2.0+ — более старые клиенты отвергнут конфиг.";
    case "3.0":
      return "HeaderProtectionKey требует AmneziaWG 3.0 (kernel-режим) — на других клиентах конфиг не заработает.";
  }
}

/** Generates a ChaCha20 key (32 bytes, base64) for AWG 3.0 header protection. */
export function generateHeaderProtectionKey(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

/**
 * Builds the `[Interface]` obfuscation lines for the chosen profile.
 * Values omitted from `opts` fall back to sane defaults for that version.
 */
export function buildObfuscationLines(opts: ObfuscationOptions = {}): string[] {
  const v = opts.version ?? DEFAULT_VERSION;
  const junk = opts.junk ?? JUNK_PRESETS["1"];
  const is20plus = v === "2.0" || v === "3.0";
  const lines: string[] = [];

  // S1/S2 — must satisfy the AWG rule S1 + 56 ≠ S2.
  let s1 = opts.s1 ?? 0;
  let s2 = opts.s2 ?? 0;
  if (s1 + 56 === s2) s2 += 1;
  lines.push(`S1 = ${s1}`, `S2 = ${s2}`);
  if (is20plus) {
    lines.push(`S3 = ${opts.s3 ?? 0}`, `S4 = ${opts.s4 ?? 0}`);
  }

  lines.push(`Jc = ${junk.jc}`, `Jmin = ${junk.jmin}`, `Jmax = ${junk.jmax}`);

  const h = opts.h ?? (is20plus ? randomHRanges() : DEFAULT_H);
  lines.push(`H1 = ${h[0]}`, `H2 = ${h[1]}`, `H3 = ${h[2]}`, `H4 = ${h[3]}`);

  // CPS: I1 from 1.5 on; I2–I5 are optional extras.
  if (v !== "1.0" && opts.i1) {
    lines.push(`I1 = ${opts.i1}`);
    for (const [k, val] of [["I2", opts.i2], ["I3", opts.i3], ["I4", opts.i4], ["I5", opts.i5]] as const) {
      if (val) lines.push(`${k} = ${val}`);
    }
  }

  if (v === "3.0") {
    const key = opts.headerProtectionKey === true ? generateHeaderProtectionKey() : opts.headerProtectionKey;
    if (key) lines.push(`HeaderProtectionKey = ${key}`);
    if (opts.contentPaddingAddition && opts.contentPaddingAddition > 0) {
      lines.push(`ContentPaddingAddition = ${opts.contentPaddingAddition}`);
    }
  }

  return lines;
}

/** Recommended MTU for a profile (obfuscation adds overhead). */
export function recommendedMtu(v: AwgVersion): number {
  switch (v) {
    case "3.0": return 1280;
    case "2.0": return 1320;
    case "1.5": return 1360;
    default: return 1380;
  }
}
