import { httpFetch } from "./http";
import { isIP } from "./ip";
import { DNS_SERVERS } from "./dns-servers";

export { DNS_SERVERS };
export const DEFAULT_DNS_ID = "malw_link";

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
