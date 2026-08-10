import { httpFetch } from "./http.ts";
import { isIP } from "./ip.ts";
import { DNS_SERVERS } from "./dns-servers.ts";

export { DNS_SERVERS };
export const DEFAULT_DNS_ID = "malw_link";

/**
 * Encrypted-DNS presets for Clash/Mihomo (DoH/DoT), with the IP + SNI pairs
 * verified against live servers upstream (hoaxisr/awg-manager, MIT).
 *
 * Gotchas — do NOT "fix" these from memory:
 *  - Yandex serves DoH on the same host as DoT: `common.dot.dns.yandex.net`.
 *    The plausible-looking `common.dns.yandex.net` does not resolve and is not
 *    in the certificate.
 *  - Cloudflare picks the filtering profile by SNI too: 1.1.1.1 with
 *    `family.cloudflare-dns.com` already filters content. The clean pair is
 *    `cloudflare-dns.com` (or `one.one.one.one`).
 *  - AdGuard's legacy `dns-unfiltered.adguard.com` presents a `*.adguard.com`
 *    certificate with no IP in the SAN — unusable.
 *  - 9.9.9.9 and 94.140.14.14 are the providers' default *filtering* profiles
 *    (malware / ads respectively).
 */
export interface DohPreset {
  id: string;
  label: string;
  ip: string;
  sni: string;
}

export const DOH_PRESETS: readonly DohPreset[] = [
  { id: "cloudflare", label: "Cloudflare", ip: "1.1.1.1", sni: "cloudflare-dns.com" },
  { id: "google", label: "Google", ip: "8.8.8.8", sni: "dns.google" },
  { id: "quad9", label: "Quad9", ip: "9.9.9.9", sni: "dns.quad9.net" },
  { id: "adguard", label: "AdGuard", ip: "94.140.14.14", sni: "dns.adguard-dns.com" },
  { id: "yandex", label: "Яндекс", ip: "77.88.8.8", sni: "common.dot.dns.yandex.net" },
];

/** Clash/Mihomo nameserver entries for a preset: DoH first, DoT as the second. */
export function clashDnsServers(presetId: string): string[] {
  const p = DOH_PRESETS.find((x) => x.id === presetId);
  if (!p) return ["https://cloudflare-dns.com/dns-query", "tls://one.one.one.one"];
  return [`https://${p.sni}/dns-query`, `tls://${p.sni}`];
}

/** The `DNS = ...` line for a server preset (falls back to Cloudflare). */
export function dnsLine(dnsId: string): string {
  return DNS_SERVERS[dnsId] || DNS_SERVERS.cloudflare;
}

/** Drops IPv6 entries from a DNS line (used when IPv6 is disabled). */
export function dnsLineIPv4Only(line: string): string {
  return line
    .split(",")
    .map((s) => s.trim())
    .filter((h) => isIP(h) !== 6)
    .join(", ");
}

/** Host routes (/32, /128) for the resolver IPs — added to selective AllowedIPs. */
export function dnsLineToCidrs(line: string): string[] {
  const out = new Set<string>();
  for (const raw of (line || "").split(",")) {
    const host = raw.trim();
    const t = isIP(host);
    if (t === 4) out.add(`${host}/32`);
    else if (t === 6) out.add(`${host}/128`);
  }
  return [...out];
}

// DNS-over-HTTPS (JSON) via the HTTP plugin — the webview has no resolver.
async function doh(name: string, type: "A" | "AAAA"): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
  try {
    const res = await httpFetch(url, {
      method: "GET",
      headers: { Accept: "application/dns-json" },
      connectTimeout: 8000,
    });
    if (!res.ok) return [];
    const data: any = await res.json();
    const want = type === "A" ? 1 : 28; // RR type numbers
    return (data?.Answer ?? [])
      .filter((a: any) => a?.type === want && typeof a.data === "string")
      .map((a: any) => a.data as string);
  } catch {
    return [];
  }
}

export const resolve4 = (name: string): Promise<string[]> => doh(name, "A");
export const resolve6 = (name: string): Promise<string[]> => doh(name, "AAAA");
