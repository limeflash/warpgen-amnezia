/**
 * AmneziaWG metadata: per-parameter hints for the UI, mimicry-profile
 * descriptions, and CPS packet size accounting.
 *
 * Hints/descriptions from hoaxisr/awg-manager (MIT); the 4096-byte ceiling on
 * the combined I1–I5 chain is an AmneziaWG constraint — exceeding it breaks the
 * config, so `validateChainSize` is used by both the generator and the analyzer.
 */

import type { MimicProfile } from "./vendor/awg-architect.ts";

/** Short Russian explanation for every obfuscation parameter. */
export const AWG_PARAM_HINTS: Record<string, string> = {
  jc: "Количество junk-пакетов, отправляемых перед handshake. Диапазон: 0–128.",
  jmin: "Минимальный размер junk-пакета в байтах. Диапазон: 0–1280.",
  jmax: "Максимальный размер junk-пакета в байтах. Диапазон: 0–1280.",
  s1: "Padding для Init Handshake.",
  s2: "Padding для Response Handshake.",
  s3: "Padding для Transport Handshake Init (AWG 2.0).",
  s4: "Padding для Transport Handshake Response (AWG 2.0).",
  h1: "Кастомный заголовок для Init Handshake. Число или диапазон (мин-макс).",
  h2: "Кастомный заголовок для Response Handshake. Число или диапазон (мин-макс).",
  h3: "Кастомный заголовок для Cookie Reply. Число или диапазон (мин-макс).",
  h4: "Кастомный заголовок для Transport. Число или диапазон (мин-макс).",
  i1: "Signature-пакет I1 — имитация протокола. Поддерживает CPS-теги.",
  i2: "Signature-пакет I2 (цепочка CPS).",
  i3: "Signature-пакет I3 (цепочка CPS).",
  i4: "Signature-пакет I4 (цепочка CPS).",
  i5: "Signature-пакет I5 (цепочка CPS).",
  headerprotectionkey: "AWG 3.0: ChaCha20-ключ, шифрующий сам заголовок WireGuard — прячет сигнатуру от DPI.",
  contentpaddingaddition: "AWG 3.0: дополнительный паддинг содержимого пакетов.",
  mtu: "MTU интерфейса. Обфускация добавляет overhead — чем сильнее профиль, тем ниже потолок.",
};

/** Human labels + descriptions for the mimicry profiles. */
export const PROTOCOL_INFO: Partial<Record<MimicProfile, { name: string; description: string }>> = {
  quic_initial: { name: "QUIC Initial", description: "RFC 9000 — основной протокол для обхода DPI" },
  quic_0rtt: { name: "QUIC 0-RTT", description: "Early Data — возобновление сессии" },
  tls_client_hello: { name: "TLS 1.3", description: "Client Hello — HTTPS handshake" },
  dtls: { name: "DTLS 1.3", description: "WebRTC, VoIP — медиа-трафик" },
  http3: { name: "HTTP/3", description: "QUIC с расширенными типами пакетов" },
  sip: { name: "SIP", description: "VoIP сигнализация — REGISTER" },
  wireguard_noise: { name: "Noise_IK", description: "WireGuard handshake — нативный силуэт" },
  dns_query: { name: "DNS Query", description: "UDP DNS-запрос (A/AAAA)" },
  tls_to_quic: { name: "TLS → QUIC", description: "Смена протокола внутри цепочки" },
  quic_burst: { name: "QUIC burst", description: "Серия QUIC-пакетов подряд" },
  random: { name: "Случайный", description: "Случайный профиль при каждой генерации" },
};

/** AmneziaWG limit: the combined I1–I5 chain must stay under this. */
export const CPS_MAX_BYTES = 4096;

const CPS_TAG_RE = /<(\w+)(?:\s+([^>]*))?>/g;

/** Byte size of one CPS pattern: <b> hex payload, <r>/<rc>/<rd> lengths, 4 bytes for <c>/<t>. */
export function calcByteSize(pattern: string): number {
  if (!pattern) return 0;
  let total = 0;
  let m: RegExpExecArray | null;
  CPS_TAG_RE.lastIndex = 0;
  while ((m = CPS_TAG_RE.exec(pattern)) !== null) {
    const tag = m[1].toLowerCase();
    const arg = (m[2] ?? "").trim();
    if (tag === "b") {
      const hex = arg.match(/0x([0-9a-fA-F]*)/);
      if (hex) total += hex[1].length / 2;
    } else if (tag === "r" || tag === "rc" || tag === "rd") {
      const n = Number.parseInt(arg, 10);
      if (Number.isFinite(n) && n > 0) total += n;
    } else if (tag === "c" || tag === "t") {
      total += 4;
    }
  }
  return total;
}

/** Combined size of the I1–I5 chain. */
export function calcChainSize(packets: { i1?: string; i2?: string; i3?: string; i4?: string; i5?: string }): number {
  return (["i1", "i2", "i3", "i4", "i5"] as const).reduce((sum, k) => sum + calcByteSize(packets[k] ?? ""), 0);
}

export interface ChainSizeCheck {
  bytes: number;
  limit: number;
  ok: boolean;
  message: string | null;
}

/** Validates the chain against the 4096-byte ceiling. */
export function validateChainSize(packets: { i1?: string; i2?: string; i3?: string; i4?: string; i5?: string }): ChainSizeCheck {
  const bytes = calcChainSize(packets);
  const ok = bytes < CPS_MAX_BYTES;
  return {
    bytes,
    limit: CPS_MAX_BYTES,
    ok,
    message: ok ? null : `Суммарный размер I1–I5 = ${bytes} Б превышает лимит ${CPS_MAX_BYTES} Б — конфиг будет отвергнут.`,
  };
}
