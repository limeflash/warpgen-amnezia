// AmneziaWG `I1` masking parameter — the fake first packet the tunnel sends so
// DPI classifies it as ordinary traffic. Three sources, in order of quality:
//   1. Valid QUIC Initial generated for an SNI (quic.ts) — the modern default.
//   2. Verified real-traffic captures (i1-captures.ts).
//   3. Generated DNS / STUN / NTP / DTLS packets (below).
//
// `resolveI1(key, customDomain?)` returns the `<b 0x...>` token (no `I1 = `
// prefix — generate.ts adds that), or "" for no masking.

import { asciiBytes, concatBytes, randomBytes, toHex, u8 } from "./bytes";
import { generateQuicMask } from "./quic";
import { CAPTURE_MASKS, DEFAULT_I1_MASKS } from "./i1-captures";

// ─────────────── Generated protocol packets ───────────────

function prependLen16(buf: Uint8Array): Uint8Array {
  return concatBytes(u8((buf.length >> 8) & 0xff, buf.length & 0xff), buf);
}

function buildDNSResponse(domain: string): string {
  const txId = randomBytes(2);
  const flags = u8(0x81, 0x80);
  const counts = u8(0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00);
  const nameParts = domain.split(".").map((l) => concatBytes(u8(l.length), asciiBytes(l)));
  const qname = concatBytes(...nameParts, u8(0x00));
  const question = concatBytes(qname, u8(0x00, 0x01, 0x00, 0x01));
  const answer = concatBytes(
    u8(0xc0, 0x0c),
    u8(0x00, 0x01),
    u8(0x00, 0x01),
    u8(0x00, 0x00, 0x00, 0x3c),
    u8(0x00, 0x04),
    randomBytes(4),
  );
  return `<b 0x${toHex(concatBytes(txId, flags, counts, question, answer))}>`;
}

function buildSTUNRequest(): string {
  const magicCookie = u8(0x21, 0x12, 0xa4, 0x42);
  const packet = concatBytes(u8(0x00, 0x01), u8(0x00, 0x00), magicCookie, randomBytes(12));
  return `<b 0x${toHex(packet)}>`;
}

function buildNTPRequest(): string {
  const pkt = new Uint8Array(48);
  pkt[0] = 0x1b;
  pkt.set(randomBytes(8), 24);
  return `<b 0x${toHex(pkt)}>`;
}

function buildDTLS12Hello(): string {
  const cipherSuites = prependLen16(u8(0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0xff));
  const helloBody = concatBytes(u8(0xfe, 0xfd), randomBytes(32), u8(0x00), u8(0x00), cipherSuites, u8(0x01, 0x00));
  const len3 = u8((helloBody.length >> 16) & 0xff, (helloBody.length >> 8) & 0xff, helloBody.length & 0xff);
  const handshake = concatBytes(u8(0x01), len3, u8(0x00, 0x00), u8(0x00, 0x00, 0x00), len3, helloBody);
  const record = concatBytes(u8(0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), prependLen16(handshake));
  return `<b 0x${toHex(record)}>`;
}

// ─────────────── Preset registry ───────────────

type Builder = () => string | Promise<string>;

interface Preset {
  label: string;
  build: Builder;
}

export interface I1Option {
  key: string;
  label: string;
}

export interface I1Group {
  label: string;
  options: I1Option[];
}

const capture = (key: string): Builder => () => CAPTURE_MASKS[key];
const quic = (domain: string): Builder => () => generateQuicMask(domain);

const PRESETS: Record<string, Preset> = {
  // Verified captures
  warpgen: { label: "QUIC — warpgen.net ✓", build: capture("warpgen") },
  ya_ru_capture: { label: "QUIC — ya.ru ✓", build: capture("ya_ru_capture") },
  cloudflare_capture: { label: "QUIC — Cloudflare ✓", build: capture("cloudflare_capture") },
  google_capture: { label: "QUIC — Google ✓", build: capture("google_capture") },
  capture_195_85_59_162: { label: "QUIC — 195.85.59.162 ✓", build: capture("capture_195_85_59_162") },
  capture_87_245_197_142: { label: "QUIC — 87.245.197.142 ✓", build: capture("capture_87_245_197_142") },
  yandex: { label: "DNS — Яндекс/Кинопоиск ✓", build: capture("yandex") },
  dns_web_max_ru: { label: "DNS — web.max.ru ✓", build: capture("dns_web_max_ru") },

  // Valid QUIC generated per SNI
  q_ya: { label: "QUIC → ya.ru", build: quic("ya.ru") },
  q_vk: { label: "QUIC → vk.com", build: quic("vk.com") },
  q_ok: { label: "QUIC → ok.ru", build: quic("ok.ru") },
  q_mail: { label: "QUIC → mail.ru", build: quic("mail.ru") },
  q_gosuslugi: { label: "QUIC → gosuslugi.ru", build: quic("gosuslugi.ru") },
  q_sberbank: { label: "QUIC → sberbank", build: quic("online.sberbank.ru") },
  q_rutube: { label: "QUIC → rutube.ru", build: quic("rutube.ru") },
  q_ozon: { label: "QUIC → ozon.ru", build: quic("ozon.ru") },
  q_google: { label: "QUIC → google.com", build: quic("www.google.com") },
  q_youtube: { label: "QUIC → youtube.com", build: quic("www.youtube.com") },
  q_discord: { label: "QUIC → discord.com", build: quic("discord.com") },
  q_apple: { label: "QUIC → apple.com", build: quic("www.apple.com") },
  q_microsoft: { label: "QUIC → microsoft.com", build: quic("www.microsoft.com") },
  q_whatsapp: { label: "QUIC → whatsapp.com", build: quic("www.whatsapp.com") },
  q_github: { label: "QUIC → github.com", build: quic("github.com") },
  q_steam: { label: "QUIC → steam", build: quic("steampowered.com") },
  q_twitch: { label: "QUIC → twitch.tv", build: quic("www.twitch.tv") },

  // Generated DNS responses
  dns_ya: { label: "DNS → ya.ru", build: () => buildDNSResponse("ya.ru") },
  dns_vk: { label: "DNS → vk.com", build: () => buildDNSResponse("vk.com") },
  dns_ozon: { label: "DNS → ozon.ru", build: () => buildDNSResponse("ozon.ru") },
  dns_rutube: { label: "DNS → rutube.ru", build: () => buildDNSResponse("rutube.ru") },
  dns_google: { label: "DNS → google.com", build: () => buildDNSResponse("www.google.com") },
  dns_youtube: { label: "DNS → youtube.com", build: () => buildDNSResponse("www.youtube.com") },

  // Standard protocols
  stun: { label: "STUN — WebRTC/VoIP", build: buildSTUNRequest },
  ntp: { label: "NTP — синхронизация времени", build: buildNTPRequest },
  dtls: { label: "DTLS 1.2 — WebRTC медиа", build: buildDTLS12Hello },
};

/** Random default valid-QUIC mask. */
export function pickI1(): string {
  return DEFAULT_I1_MASKS[Math.floor(Math.random() * DEFAULT_I1_MASKS.length)];
}

/**
 * Resolves an I1 preset key to a `<b 0x...>` mask token.
 *   none        → "" (no masking)
 *   custom      → valid QUIC for `customDomain` (falls back to a default mask)
 *   random_quic → a random default valid-QUIC mask
 *   random      → a random concrete preset
 *   <preset>    → that preset's mask
 */
export async function resolveI1(key: string, customDomain?: string): Promise<string> {
  if (key === "none") return "";
  if (key === "custom") {
    const domain = (customDomain ?? "").trim();
    return domain ? generateQuicMask(domain) : pickI1();
  }
  if (key === "random_quic") return pickI1();
  if (key === "random") {
    const keys = Object.keys(PRESETS);
    const pick = keys[Math.floor(Math.random() * keys.length)];
    return PRESETS[pick].build();
  }
  const preset = PRESETS[key];
  return preset ? preset.build() : pickI1();
}

/** Option groups for the UI `<select>`. */
export const I1_GROUPS: I1Group[] = [
  {
    label: "Рекомендуется",
    options: [
      { key: "random_quic", label: "🎲 Случайная валидная QUIC-маска (рекомендуется)" },
      { key: "custom", label: "✏️ Свой домен (валидный QUIC)" },
      { key: "random", label: "🎲 Случайный из всех пресетов" },
    ],
  },
  {
    label: "Верифицированные захваты (реальный трафик)",
    options: [
      "warpgen",
      "ya_ru_capture",
      "cloudflare_capture",
      "google_capture",
      "capture_195_85_59_162",
      "capture_87_245_197_142",
      "yandex",
      "dns_web_max_ru",
    ].map((key) => ({ key, label: PRESETS[key].label })),
  },
  {
    label: "QUIC (валидный, генерируется под SNI)",
    options: [
      "q_ya", "q_vk", "q_ok", "q_mail", "q_gosuslugi", "q_sberbank", "q_rutube", "q_ozon",
      "q_google", "q_youtube", "q_discord", "q_apple", "q_microsoft", "q_whatsapp", "q_github", "q_steam", "q_twitch",
    ].map((key) => ({ key, label: PRESETS[key].label })),
  },
  {
    label: "DNS-ответ (генерируется)",
    options: ["dns_ya", "dns_vk", "dns_ozon", "dns_rutube", "dns_google", "dns_youtube"].map((key) => ({
      key,
      label: PRESETS[key].label,
    })),
  },
  {
    label: "STUN / NTP / DTLS",
    options: ["stun", "ntp", "dtls"].map((key) => ({ key, label: PRESETS[key].label })),
  },
  {
    label: "Без маскировки",
    options: [{ key: "none", label: "Без маскировки (без I1)" }],
  },
];

export const DEFAULT_I1_KEY = "random_quic";
