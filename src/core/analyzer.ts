/**
 * AmneziaWG / WireGuard .conf analyzer — parses a config, detects the AWG
 * profile version, recognises what the I1 first packet mimics, scores the
 * obfuscation and reports per-parameter checks with fixes.
 *
 * Ported from hoaxisr/awg-manager `frontend/src/lib/utils/awgConfAnalyzer.ts`
 * (itself following pumbax/awg-analyzer). Pure client-side: nothing is sent
 * anywhere.
 */

import { validateChainSize } from "./awg-meta.ts";

export type AwgIface = Record<string, string>;
export interface AwgParsed {
  iface: AwgIface;
  peer: AwgIface;
}

export type CheckStatus = "pass" | "warn" | "fail" | "info";

export interface AwgCheck {
  cat: string;
  title: string;
  status: CheckStatus;
  value: string;
  detail: string;
  pts: number;
  max: number;
}

export interface AwgScores {
  /** 0–100 — overall config quality (sum of check points). */
  total: number;
  /** 3–92 — how detectable by DPI (lower is better). */
  dpi: number;
  /** 0–100 — stealth (higher is better). */
  stealth: number;
}

export type AwgCamouflage = "LOW" | "MEDIUM" | "HIGH";

export interface AwgVersionInfo {
  ver: "WireGuard" | "AWG 1.0" | "AWG 1.5" | "AWG 2.0" | "AWG 3.0";
  desc: string;
  /** CPS / obfuscation level label. */
  obfLevel: string | null;
  /** Protocol the I1 packet mimics, if any. */
  protocol: string | null;
}

export interface I1Parsed {
  tags: Array<{ tag: string; arg: string }>;
  firstTag: string | null;
  hexData: string;
  rTagSizes: number[];
  totalRBytes: number;
  hasT: boolean;
  hasC: boolean;
  hasRc: boolean;
  firstByte: number | null;
  firstByteOk: boolean;
  startsWithB: boolean;
  errors: string[];
  protocol: string;
}

// ─────────────── helpers ───────────────

function getStr(o: AwgIface, key: string, def = ""): string {
  return (o[key.toLowerCase()] || def).toString().trim();
}
function getInt(o: AwgIface, key: string, def: number | null = null): number | null {
  const v = o[key.toLowerCase()];
  if (v === undefined || v === null || v === "") return def;
  const n = parseInt(v, 10);
  return Number.isNaN(n) ? def : n;
}
function hasKey(o: AwgIface, key: string): boolean {
  return o[key.toLowerCase()] !== undefined;
}
const isBase64Key = (s: string) => /^[A-Za-z0-9+/]{43}=?$/.test(s);

// ─────────────── parsing ───────────────

/** Parses a `.conf` into lower-cased [Interface] / [Peer] maps. */
export function parseAWG(raw: string): AwgParsed {
  const trimmed = (raw || "").trim();
  if (!trimmed) throw new Error("Пустой конфиг");

  const iface: AwgIface = {};
  const peer: AwgIface = {};
  let section: string | null = null;

  for (const line0 of trimmed.split("\n")) {
    const line = line0.trim();
    if (!line || line.startsWith("#")) continue;
    const sm = line.match(/^\[(\w+)\]$/);
    if (sm) {
      section = sm[1].toLowerCase();
      continue;
    }
    const em = line.match(/^([^=]+?)\s*=\s*(.*)$/);
    if (!em || !section) continue;
    const k = em[1].trim().toLowerCase();
    const v = em[2].trim();
    if (section === "interface") iface[k] = v;
    else if (section === "peer") peer[k] = v;
  }

  if (!iface.privatekey && !trimmed.includes("[Interface]")) {
    throw new Error("Не найдена секция [Interface]. Вставьте .conf файл AmneziaWG / WireGuard.");
  }
  return { iface, peer };
}

/** Recognises the mimicked protocol from the I1 hex payload. */
export function detectI1ProtocolFromHex(hex: string): string {
  if (!hex) return "Unknown";
  const h = hex.toLowerCase();
  if (/^16030[0-3]/.test(h)) return "TLS";
  if (/^16fefd/.test(h) || /^16feff/.test(h)) return "DTLS";
  const knownQuic = ["00000001", "6b3343cf", "ff00001d", "ff00001e"];
  if (h.length >= 10) {
    const fb = parseInt(h.substring(0, 2), 16);
    const ver = h.substring(2, 10);
    if (fb >= 0xc0 && fb <= 0xef && (knownQuic.includes(ver) || h.startsWith("c0000"))) return "QUIC";
  }
  const sipHex = ["494e56495445", "5245474953544552", "4f5054494f4e53", "4d455353414745", "5355425343524942", "4e4f54494659", "535542"];
  if (sipHex.some((s) => h.startsWith(s))) return "SIP";
  if (/^[0-9a-f]{4}01[02]0000[12]/.test(h)) return "DNS";
  if (h.startsWith("474554") || h.startsWith("504f5354") || h.startsWith("48545450")) return "HTTP";
  if (h.startsWith("0001") && h.includes("2112a442")) return "STUN";
  return "Custom";
}

/** Parses a CPS I1 string with `<b 0x…> <r N> <rc N> <t> <c>` tags. */
export function parseI1(i1: string): I1Parsed {
  const r: I1Parsed = {
    tags: [], firstTag: null, hexData: "", rTagSizes: [], totalRBytes: 0,
    hasT: false, hasC: false, hasRc: false, firstByte: null, firstByteOk: true,
    startsWithB: false, errors: [], protocol: "Unknown",
  };

  const tagRegex = /<(\w+)(?:\s+([^>]*))?>/g;
  let m: RegExpExecArray | null;
  while ((m = tagRegex.exec(i1)) !== null) {
    const tag = m[1].toLowerCase();
    const arg = (m[2] || "").trim();
    r.tags.push({ tag, arg });
    if (tag === "b") {
      const hex = arg.match(/0x([0-9a-fA-F]+)/);
      if (hex) r.hexData = hex[1].toLowerCase();
    } else if (tag === "r") {
      const n = parseInt(arg, 10);
      if (!Number.isNaN(n)) {
        r.rTagSizes.push(n);
        r.totalRBytes += n;
      }
    } else if (tag === "rc") {
      r.hasRc = true;
    } else if (tag === "t") {
      r.hasT = true;
    } else if (tag === "c") {
      r.hasC = true;
    }
  }

  if (!r.tags.length) return r;

  r.firstTag = r.tags[0].tag;
  r.startsWithB = r.firstTag === "b";
  if (!r.startsWithB) {
    r.errors.push("Первый тег в I1 должен быть <b …> — иначе amneziawg-go может отказать в handshake.");
  }
  for (const n of r.rTagSizes) {
    if (n >= 1000) r.errors.push(`Тег <r> с размером ${n} ≥ 1000 — разбейте на части ≤999.`);
  }
  if (r.hasC) r.errors.push("Тег <c> устарел — на старых клиентах AmneziaVPN возможен ErrorCode 1000.");

  r.protocol = detectI1ProtocolFromHex(r.hexData);
  if (r.hexData.length >= 2) {
    const fb = parseInt(r.hexData.substring(0, 2), 16);
    r.firstByte = fb;
    if (r.protocol === "QUIC") {
      r.firstByteOk = fb >= 0xc0 && fb <= 0xef;
      if (!r.firstByteOk) r.errors.push(`Первый байт 0x${fb.toString(16)} — для QUIC ожидается 0xC0–0xEF.`);
    } else if (r.protocol === "TLS" || r.protocol === "DTLS") {
      r.firstByteOk = fb === 0x16;
      if (!r.firstByteOk) r.errors.push(`Первый байт 0x${fb.toString(16)} — для ${r.protocol} ожидается 0x16.`);
    }
  }
  return r;
}

function protocolFromI1(iface: AwgIface): string | null {
  const i1 = getStr(iface, "i1");
  if (!i1) return null;
  if (/<\s*b\b/i.test(i1)) return parseI1(i1).protocol;
  const hex = i1.replace(/[^0-9a-f]/gi, "");
  if (hex.length >= 4) return detectI1ProtocolFromHex(hex);
  return "Custom";
}

function cpsLabel(iface: AwgIface): string {
  const chain = ["i1", "i2", "i3", "i4", "i5"].map((k) => getStr(iface, k)).filter(Boolean).length;
  if (!chain) return "Без CPS (нет I1)";
  return chain <= 1 ? "CPS: только I1" : `CPS: цепочка I1–I${chain}`;
}

const AWG3_KEYS = ["headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts"];

function parseH(iface: AwgIface, key: string, def: number | null): { val: number | null; isRange: boolean; raw: string | null } {
  const v = getStr(iface, key);
  if (!v) return { val: def, isRange: false, raw: null };
  const rm = v.match(/^(\d+)-(\d+)$/);
  if (rm) return { val: parseInt(rm[1], 10), isRange: true, raw: v };
  const n = parseInt(v, 10);
  return { val: Number.isNaN(n) ? def : n, isRange: false, raw: v };
}

/** Detects which AmneziaWG generation the config targets. */
export function detectVersion(iface: AwgIface): AwgVersionInfo {
  const proto = protocolFromI1(iface);

  // AWG 3.0 outranks everything — device params sit on top of AWG 1.x/2.0 obfuscation.
  if (AWG3_KEYS.some((k) => getStr(iface, k) !== "")) {
    const hp = getStr(iface, "headerprotectionkey") !== "";
    return {
      ver: "AWG 3.0",
      desc: hp
        ? "AmneziaWG 3.0 — шифрование заголовка (HeaderProtectionKey, ChaCha20) прячет сигнатуру WireGuard-заголовка от DPI."
        : "AmneziaWG 3.0 — настраиваемые таймеры (rekey/reject/keepalive) и/или padding поверх обфускации AWG.",
      obfLevel: hp ? "Header Protection (ChaCha20)" : cpsLabel(iface),
      protocol: proto && proto !== "Unknown" ? proto : null,
    };
  }

  const Jc = getInt(iface, "jc", 0) ?? 0;
  const S1 = getInt(iface, "s1", 0) ?? 0;
  const S2 = getInt(iface, "s2", 0) ?? 0;
  const i1Present = !!getStr(iface, "i1");
  const hasS3 = hasKey(iface, "s3");
  const hasS4 = hasKey(iface, "s4");

  const hs = [parseH(iface, "h1", 1), parseH(iface, "h2", 2), parseH(iface, "h3", 3), parseH(iface, "h4", 4)];
  const headersHaveRanges = hs.some((h) => h.isRange);
  const headersDefault = !headersHaveRanges && hs[0].val === 1 && hs[1].val === 2 && hs[2].val === 3 && hs[3].val === 4;

  if ((!hasKey(iface, "jc") || Jc === 0) && (!hasKey(iface, "s1") || (S1 === 0 && S2 === 0)) && headersDefault && !i1Present) {
    return { ver: "WireGuard", desc: "Стандартный WireGuard без обфускации. DPI легко обнаружит трафик.", obfLevel: null, protocol: null };
  }

  if ((hasS3 || hasS4) && headersHaveRanges) {
    const known = proto && proto !== "Unknown";
    return {
      ver: "AWG 2.0",
      desc: i1Present && known
        ? `AmneziaWG 2.0 — S3/S4, H1–H4 диапазоны и CPS: I1 имитирует ${proto}.`
        : "AmneziaWG 2.0 — S3/S4 и H1–H4 диапазоны; I1 опционально усиливает мимикрию.",
      obfLevel: cpsLabel(iface),
      protocol: i1Present && known ? proto : null,
    };
  }

  if (i1Present) {
    const p = proto && proto !== "Unknown" ? proto : null;
    return {
      ver: "AWG 1.5",
      desc: `AmneziaWG 1.5 — Jc/S1/S2/H1–H4 + CPS (I1 имитирует ${p ?? "Custom"}). Для 2.0 добавьте S3/S4 и H-диапазоны.`,
      obfLevel: cpsLabel(iface),
      protocol: p,
    };
  }

  if (Jc > 0) {
    return {
      ver: "AWG 1.0",
      desc: "AmneziaWG 1.0 — junk-пакеты (Jc/Jmin/Jmax) + S1/S2 рандомизируют размер handshake, H1–H4 скрывают сигнатуру.",
      obfLevel: "Jc + S1/S2 + H (без CPS)",
      protocol: null,
    };
  }
  return { ver: "AWG 1.0", desc: "AmneziaWG 1.0 — минимальная обфускация.", obfLevel: "Минимальная", protocol: null };
}

/** Recommended MTU ceiling for the detected profile. */
export function mtuCeilingForProfile(version: AwgVersionInfo): number {
  switch (version.ver) {
    case "WireGuard": return 1420;
    case "AWG 3.0": return 1300;
    case "AWG 2.0": return 1320;
    case "AWG 1.5": return 1360;
    default: return 1380;
  }
}

export function mtuCheatsheet(): string[] {
  return [
    ">1500 — в большинстве случаев не будет работать",
    "1500 — Ethernet без tunnel overhead",
    "1420 — стандартный WireGuard",
    "1380 — баланс / AWG 1.0",
    "1360 — PPPoE overhead, AWG 1.5 + CPS",
    "1340 — мобильный 4G/LTE",
    "1320 — AWG 2.0 + CPS (рекомендуется)",
    "1280 — максимальная совместимость",
  ];
}

/** Camouflage strength implied by what I1 mimics. */
export function camouflageFromI1(iface: AwgIface): AwgCamouflage {
  const i1 = getStr(iface, "i1");
  if (!i1) return "LOW";
  const proto = /<\s*b\b/i.test(i1) ? parseI1(i1).protocol : detectI1ProtocolFromHex(i1.replace(/[^0-9a-f]/gi, ""));
  if (proto === "QUIC" || proto === "TLS" || proto === "DTLS") return "HIGH";
  if (proto === "DNS" || proto === "SIP" || proto === "HTTP" || proto === "STUN") return "MEDIUM";
  return "LOW";
}

// ─────────────── checks ───────────────

/** Per-parameter checks with points, mirroring the reference analyzer. */
export function runChecks(iface: AwgIface, peer: AwgIface, version: AwgVersionInfo): AwgCheck[] {
  const out: AwgCheck[] = [];
  const add = (cat: string, title: string, status: CheckStatus, value: unknown, detail: string, pts: number, max: number) =>
    out.push({ cat, title, status, value: String(value), detail, pts, max });

  // Keys
  const priv = getStr(iface, "privatekey");
  const privOk = isBase64Key(priv);
  add("Ключи", "PrivateKey", privOk ? "pass" : "fail", privOk ? `${priv.slice(0, 12)}…` : "(отсутствует)",
    privOk ? "Корректный base64 Curve25519 ключ" : "Приватный ключ отсутствует или невалиден", privOk ? 10 : 0, 10);

  const pub = getStr(peer, "publickey");
  const pubOk = isBase64Key(pub);
  add("Ключи", "PublicKey (Peer)", pubOk ? "pass" : "fail", pubOk ? `${pub.slice(0, 12)}…` : "(отсутствует)",
    pubOk ? "Публичный ключ сервера присутствует" : "Публичный ключ сервера отсутствует", pubOk ? 8 : 0, 8);

  const psk = getStr(peer, "presharedkey");
  const pskOk = isBase64Key(psk);
  add("Ключи", "PresharedKey", pskOk ? "pass" : "warn", pskOk ? `${psk.slice(0, 12)}…` : "(отсутствует)",
    pskOk ? "PresharedKey задан — доп. слой симметричного шифрования" : "PresharedKey отсутствует — доп. защита не активна",
    pskOk ? 6 : 2, 6);

  // Junk packets
  const Jc = getInt(iface, "jc", null);
  const Jmin = getInt(iface, "jmin", null);
  const Jmax = getInt(iface, "jmax", null);
  const jcGood = Jc !== null && Jc >= 3 && Jc <= 10;
  add("Junk-пакеты", "Jc (количество)", Jc === null ? "fail" : Jc === 0 ? "warn" : jcGood ? "pass" : "warn",
    Jc ?? "(не задан)",
    Jc === null ? "Jc не задан — handshake детектируется по размеру"
      : Jc === 0 ? "Jc=0 — junk-пакеты отключены"
      : jcGood ? `Jc=${Jc} — в рекомендуемом диапазоне 3–10 ✓`
      : Jc > 10 ? `Jc=${Jc} — слишком много (рекомендуется 3–10)` : `Jc=${Jc} — мало (рекомендуется 3–10)`,
    Jc === null || Jc === 0 ? 0 : jcGood ? 8 : 4, 8);

  if (Jc !== null && Jc > 0) {
    const jminOk = Jmin !== null && Jmin >= 10 && Jmin <= 500;
    const jmaxOk = Jmax !== null && Jmax >= (Jmin ?? 0) && Jmax <= 1280;
    const rangeOk = jminOk && jmaxOk && Jmax! - Jmin! >= 30;
    add("Junk-пакеты", "Jmin/Jmax (диапазон)", rangeOk ? "pass" : jminOk && jmaxOk ? "warn" : "fail",
      Jmin !== null && Jmax !== null ? `${Jmin}–${Jmax}` : "(не задан)",
      Jmin === null || Jmax === null ? "Jmin/Jmax не заданы — нужны при Jc>0"
        : !jmaxOk ? `Jmax=${Jmax} должен быть ≤ 1280`
        : !jminOk ? `Jmin=${Jmin} слишком мало`
        : Jmax! - Jmin! < 30 ? "Диапазон слишком мал — паттерн предсказуем"
        : `Jmin=${Jmin} Jmax=${Jmax} — хороший диапазон ✓`,
      rangeOk ? 6 : jminOk && jmaxOk ? 3 : 0, 6);
  }

  // S1/S2 (+S3/S4)
  const S1 = getInt(iface, "s1", null);
  const S2 = getInt(iface, "s2", null);
  const S3 = getInt(iface, "s3", null);
  const S4 = getInt(iface, "s4", null);
  for (const [key, val, label] of [["s1", S1, "S1 — Init prefix"], ["s2", S2, "S2 — Response prefix"]] as const) {
    const ok = val !== null && val >= 0 && val <= 64;
    add("Handshake Padding", label, val === null ? "info" : val === 0 ? "warn" : ok ? "pass" : "warn",
      val ?? "(не задан)",
      val === null ? `${key.toUpperCase()} не задан — только в AWG 1.5/2.0`
        : val === 0 ? `${key.toUpperCase()}=0 — рандомный префикс отключён`
        : ok ? `${key.toUpperCase()}=${val} — в диапазоне 0–64 ✓` : `${key.toUpperCase()}=${val} — вне диапазона 0–64`,
      val === null ? 1 : val === 0 ? 0 : ok ? 6 : 3, 6);
  }
  if (S1 !== null && S2 !== null && S1 + 56 === S2) {
    add("Handshake Padding", "S1+56 = S2 конфликт", "fail", `S1=${S1} S2=${S2}`,
      `S1+56=${S1 + 56} совпадает с S2 — правило AWG: S1+56 ≠ S2, иначе пакеты предсказуемы!`, 0, 0);
  }
  if (S3 !== null || S4 !== null) {
    const ok = S3 !== null && S3 >= 0 && S3 <= 64 && S4 !== null && S4 >= 0 && S4 <= 64;
    add("Handshake Padding", "S3/S4 (AWG 2.0)", ok ? "pass" : "warn", `S3=${S3 ?? "—"} S4=${S4 ?? "—"}`,
      "S3/S4 — расширенные префиксы AWG 2.0 для Cookie и Data пакетов.", ok ? 4 : 2, 4);
  }

  // Magic headers
  const hs = [parseH(iface, "h1", null), parseH(iface, "h2", null), parseH(iface, "h3", null), parseH(iface, "h4", null)];
  const hasAllH = hs.every((h) => h.raw !== null);
  const haveRanges = hs.some((h) => h.isRange);
  const vals = hs.map((h) => h.val).filter((v): v is number => v !== null);
  const defaultH = !haveRanges && vals.length === 4 && vals[0] === 1 && vals[1] === 2 && vals[2] === 3 && vals[3] === 4;
  const uniqueH = hasAllH && new Set(vals).size === 4;
  const display = hasAllH ? hs.map((h) => (h.isRange && h.raw ? h.raw : h.val)).join(" / ") : "(не заданы)";

  let hStatus: CheckStatus, hPts: number, hDetail: string;
  if (!hasAllH) { hStatus = "warn"; hPts = 0; hDetail = "H1–H4 не заданы — сигнатура handshake не скрыта"; }
  else if (defaultH) { hStatus = "fail"; hPts = 0; hDetail = "H1=1 H2=2 H3=3 H4=4 — ДЕФОЛТ WireGuard! Handshake легко идентифицируется DPI."; }
  else if (!uniqueH) { hStatus = "fail"; hPts = 0; hDetail = "H1–H4 повторяются — конфиг невалиден (значения должны быть уникальны)"; }
  else if (haveRanges) { hStatus = "pass"; hPts = 12; hDetail = "H1–H4 заданы диапазонами — режим AWG 2.0, случайное значение на соединение ✓"; }
  else { hStatus = "pass"; hPts = 10; hDetail = "H1–H4 уникальны — сигнатура handshake скрыта ✓"; }
  add("Magic Headers", "H1–H4", hStatus, display, hDetail, hPts, 12);

  if (hasAllH && uniqueH && !defaultH && !haveRanges) {
    const small = vals.filter((h) => h < 5);
    if (small.length) {
      add("Magic Headers", "H значения < 5", "warn", small.join(", "),
        "Значения H < 5 пересекаются с типами WireGuard (1–4). Рекомендуется H ≥ 5", 0, 0);
    }
  }

  // CPS / I1
  const I1 = getStr(iface, "i1");
  const chain = ["i1", "i2", "i3", "i4", "i5"].map((k) => getStr(iface, k)).filter(Boolean).length;
  add("CPS Мимикрия", "I1 — Protocol Signature", I1 ? "pass" : "info",
    I1 ? (version.protocol ?? "задан") : "(не задан)",
    I1 ? `I1 задан${version.protocol ? ` — имитирует ${version.protocol}` : ""}${chain > 1 ? `, цепочка I1–I${chain}` : ""}`
       : version.ver === "AWG 2.0"
         ? "I1 не задан — профиль уже AWG 2.0; I1 опционально усиливает мимикрию первого пакета."
         : "I1 не задан — для CPS и мимикрии под QUIC/TLS/DNS добавьте I1.",
    I1 ? 12 : 0, 12);

  if (I1 && /<\s*b\b/i.test(I1)) {
    for (const e of parseI1(I1).errors) add("CPS Мимикрия", "Проблема в I1", "warn", "—", e, 0, 0);
  }

  // AmneziaWG rejects a config whose combined I1–I5 chain exceeds 4096 bytes.
  if (chain > 0) {
    const size = validateChainSize({
      i1: I1, i2: getStr(iface, "i2"), i3: getStr(iface, "i3"), i4: getStr(iface, "i4"), i5: getStr(iface, "i5"),
    });
    add("CPS Мимикрия", "Размер цепочки I1–I5", size.ok ? "pass" : "fail", `${size.bytes} / ${size.limit} Б`,
      size.message ?? `Цепочка ${size.bytes} Б — в пределах лимита ${size.limit} Б ✓`, size.ok ? 3 : 0, 3);
  }

  // MTU
  const mtu = getInt(iface, "mtu", null);
  const ceiling = mtuCeilingForProfile(version);
  if (mtu !== null) {
    const ok = mtu > 0 && mtu <= ceiling;
    add("MTU", "MTU", ok ? "pass" : "warn", mtu,
      ok ? `MTU=${mtu} — в пределах для ${version.ver} (≤${ceiling}) ✓`
         : `MTU=${mtu} превышает рекомендуемый потолок ${ceiling} для ${version.ver} — возможна фрагментация`,
      ok ? 4 : 1, 4);
  } else {
    add("MTU", "MTU", "info", "(не задан)", `MTU не задан — рекомендуется ≤${ceiling} для ${version.ver}`, 1, 4);
  }

  return out;
}

/** Overall / DPI-detectability / stealth scores. */
export function calcScores(checks: AwgCheck[], iface: AwgIface, version: AwgVersionInfo): AwgScores {
  const tp = checks.reduce((a, c) => a + c.pts, 0);
  const mp = checks.reduce((a, c) => a + c.max, 0);
  const total = mp > 0 ? Math.round((tp / mp) * 100) : 0;

  let dpi = 95;
  if (version.ver === "AWG 3.0") dpi -= 70;
  else if (version.ver === "AWG 2.0") dpi -= 55;
  else if (version.ver === "AWG 1.5") dpi -= 40;
  else if (version.ver === "AWG 1.0") dpi -= 25;

  if ((getInt(iface, "jc", 0) ?? 0) >= 3) dpi -= 10;
  const h = [1, 2, 3, 4].map((i) => getInt(iface, `h${i}`, i) ?? i);
  if (!(h[0] === 1 && h[1] === 2 && h[2] === 3 && h[3] === 4)) dpi -= 5;
  dpi = Math.max(3, Math.min(92, dpi));

  return { total, dpi, stealth: Math.round(100 - dpi * 0.75) };
}

export function dpiLabel(dpi: number): AwgCamouflage {
  return dpi <= 20 ? "LOW" : dpi <= 45 ? "MEDIUM" : "HIGH";
}

/** Suggestions for strengthening the config. */
export function buildUpgradeHints(iface: AwgIface, version: AwgVersionInfo): string[] {
  const hints: string[] = [];
  const i1 = getStr(iface, "i1");
  if (i1 && /<\s*b\b/i.test(i1)) hints.push(...parseI1(i1).errors);

  switch (version.ver) {
    case "WireGuard":
      hints.push("Перейдите на AmneziaWG: добавьте Jc/Jmin/Jmax, S1/S2 и уникальные H1–H4 вместо дефолта 1–4.");
      break;
    case "AWG 1.0":
      hints.push("Добавьте I1 (CPS) для мимикрии под живой протокол → уровень AWG 1.5.");
      hints.push("Или доведите до AWG 2.0: параметры S3/S4 и H1–H4 в виде диапазонов.");
      break;
    case "AWG 1.5":
      hints.push("Для AWG 2.0: задайте S3 и S4, а H1–H4 — диапазонами (например 5-60000).");
      break;
    case "AWG 2.0":
      if (!i1) hints.push("Опционально: добавьте I1 с QUIC/TLS/DNS — первый пакет будет похож на обычный протокол.");
      hints.push("Для AWG 3.0: включите HeaderProtectionKey — шифрование WG-заголовка прячет сигнатуру пакета от DPI.");
      break;
  }
  return hints;
}

export interface AnalysisResult {
  parsed: AwgParsed;
  version: AwgVersionInfo;
  checks: AwgCheck[];
  scores: AwgScores;
  camouflage: AwgCamouflage;
  hints: string[];
  summary: Array<{ label: string; value: string }>;
}

/** One-call analysis of a raw `.conf`. */
export function analyzeConfig(raw: string): AnalysisResult {
  const parsed = parseAWG(raw);
  const version = detectVersion(parsed.iface);
  const checks = runChecks(parsed.iface, parsed.peer, version);
  const scores = calcScores(checks, parsed.iface, version);

  const summary: Array<{ label: string; value: string }> = [{ label: "Профиль", value: version.ver }];
  if (version.obfLevel) summary.push({ label: "Обфускация / CPS", value: version.obfLevel });
  if (version.protocol) summary.push({ label: "Мимикрия (I1)", value: version.protocol });
  const ep = getStr(parsed.peer, "endpoint");
  if (ep) summary.push({ label: "Endpoint", value: ep });
  const jc = getInt(parsed.iface, "jc", null);
  if (jc !== null) summary.push({ label: "Jc", value: String(jc) });
  const s34 = [getStr(parsed.iface, "s3"), getStr(parsed.iface, "s4")].filter(Boolean).join(" / ");
  if (s34) summary.push({ label: "S3 / S4", value: s34 });
  const hraw = ["h1", "h2", "h3", "h4"].map((k) => getStr(parsed.iface, k)).filter(Boolean);
  if (hraw.length) summary.push({ label: "H1–H4", value: hraw.join(" · ") });
  const mtu = getInt(parsed.iface, "mtu", null);
  if (mtu !== null) summary.push({ label: "MTU", value: String(mtu) });

  return {
    parsed,
    version,
    checks,
    scores,
    camouflage: camouflageFromI1(parsed.iface),
    hints: buildUpgradeHints(parsed.iface, version),
    summary,
  };
}
