// Clash Meta (mihomo) config output + import — ported from the web app's
// lib/clash.js. Emits a YAML profile whose proxies are `wireguard` nodes, an
// url-test/select group, fake-ip DNS and DOMAIN-SUFFIX / IP-CIDR routing rules.
// Also imports a WireGuard/AmneziaWG `.conf` or an Amnezia `vpn://` link.

import { normalizeInterfaceAddress } from "./ip";

export const WARP_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

export const CDN_CIDRS: Record<string, string[]> = {
  cloudflare: ["104.16.0.0/13", "172.64.0.0/13", "188.114.96.0/20", "162.159.0.0/16", "2606:4700::/32", "2a06:98c0::/29"],
  akamai: ["23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "2600:1400::/24"],
  aws: ["3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/7", "18.0.0.0/8", "35.71.0.0/16"],
  cdn77: ["37.19.192.0/19", "45.64.64.0/22", "2a02:26f0::/32"],
  digitalocean: ["104.131.0.0/16", "159.65.0.0/16", "167.99.0.0/16", "2a03:b0c0::/32"],
  fastly: ["23.235.32.0/20", "43.249.72.0/22", "2a04:4e42::/32"],
  hetzner: ["49.12.0.0/16", "88.198.0.0/16", "2a01:4f8::/32"],
  ovh: ["51.68.0.0/16", "54.36.0.0/15", "2001:41d0::/32"],
};

export const CLASH_DOMAIN_PRESETS = {
  blocked_sites: [
    "discord.com", "discord.gg", "discordapp.net", "youtube.com", "googlevideo.com", "x.com",
    "twitter.com", "t.co", "instagram.com", "twitch.tv", "telegram.org", "t.me",
    "steamcommunity.com", "steampowered.com", "steam-chat.com", "faceit.com", "open.faceit.com",
    "apexlegends.com", "ea.com", "origin.com", "battle.net", "blizzard.com",
    "playhearthstone.com", "pubg.com", "playbattlegrounds.com", "krafton.com",
    "whatsapp.com", "whatsapp.net", "viber.com", "tiktok.com", "tiktokv.com",
    "jetbrains.com", "download.jetbrains.com", "plugins.jetbrains.com",
  ],
  ru_direct: ["yandex.ru", "vk.com", "rutube.ru", "gosuslugi.ru", "sberbank.ru"],
};

export type ClashNodeType = "warp" | "amnezia" | "wireguard";

export interface ClashNode {
  name: string;
  type: ClashNodeType;
  server: string;
  port: number;
  privateKey: string;
  publicKey: string;
  address: string;
  reserved?: number[] | null;
}

export interface ClashProfile {
  name: string;
  nodes: ClashNode[];
  dns: { mode?: string; nameservers?: string[]; fallback?: string[] };
  routing: { proxyDomains: string[]; ruDirectDomains: string[]; cdnCidrs: string[] };
}

function toYamlValue(value: string | number | boolean | null | undefined): string {
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value === null || value === undefined) return '""';
  const str = String(value);
  const escaped = str.replace(/\\/g, "\\\\").replace(/\r/g, "\\r").replace(/\n/g, "\\n").replace(/"/g, '\\"');
  if (/^[a-zA-Z0-9._:@/+-]+$/.test(str) && !/^(true|false|null|~|yes|no|on|off)$/i.test(str)) return str;
  return `"${escaped}"`;
}

export function buildClashYaml(profile: ClashProfile): string {
  const proxyNames = profile.nodes.map((n) => n.name);
  const dnsNameservers = profile.dns.nameservers?.length ? profile.dns.nameservers : ["https://dns.malw.link/dns-query"];
  const dnsFallback = profile.dns.fallback?.length ? profile.dns.fallback : ["https://1.1.1.1/dns-query", "tls://1.1.1.1"];

  const rules: string[] = [];
  for (const d of profile.routing.ruDirectDomains) rules.push(`DOMAIN-SUFFIX,${d},DIRECT`);
  for (const d of profile.routing.proxyDomains) rules.push(`DOMAIN-SUFFIX,${d},WARP Auto`);
  for (const c of profile.routing.cdnCidrs) rules.push(`IP-CIDR,${c},WARP Auto,no-resolve`);
  rules.push("MATCH,DIRECT");

  const lines: string[] = ["mixed_port: 7890", "allow_lan: true", "mode: rule", "log-level: info", "ipv6: true", "proxies:"];

  for (const node of profile.nodes) {
    lines.push(`  - name: ${toYamlValue(node.name)}`);
    lines.push("    type: wireguard");
    lines.push(`    server: ${toYamlValue(node.server)}`);
    lines.push(`    port: ${node.port}`);
    lines.push(`    ip: ${toYamlValue(node.address)}`);
    lines.push(`    private-key: ${toYamlValue(node.privateKey)}`);
    lines.push(`    public-key: ${toYamlValue(node.publicKey)}`);
    lines.push("    udp: true");
    lines.push("    remote-dns-resolve: true");
    lines.push("    mtu: 1280");
    if (Array.isArray(node.reserved) && node.reserved.length === 3) {
      lines.push(`    reserved: [${node.reserved.map((n) => Number.parseInt(String(n), 10) || 0).join(", ")}]`);
    }
    if (node.type === "amnezia") lines.push("    x-note: amnezia-metadata-only");
  }

  lines.push("proxy-groups:");
  lines.push('  - name: "WARP Auto"');
  lines.push("    type: url-test");
  lines.push("    proxies:");
  for (const n of proxyNames) lines.push(`      - ${toYamlValue(n)}`);
  lines.push("    url: http://www.gstatic.com/generate_204");
  lines.push("    interval: 300");
  lines.push("    tolerance: 80");
  lines.push('  - name: "WARP Manual"');
  lines.push("    type: select");
  lines.push("    proxies:");
  for (const n of [...proxyNames, "WARP Auto", "DIRECT"]) lines.push(`      - ${toYamlValue(n)}`);

  lines.push("dns:");
  lines.push("  enable: true");
  lines.push("  listen: 0.0.0.0:1053");
  lines.push("  ipv6: true");
  lines.push(`  enhanced-mode: ${profile.dns.mode === "redir-host" ? "redir-host" : "fake-ip"}`);
  lines.push("  fake-ip-range: 198.18.0.1/16");
  lines.push("  nameserver:");
  for (const v of dnsNameservers) lines.push(`    - ${toYamlValue(v)}`);
  lines.push("  fallback:");
  for (const v of dnsFallback) lines.push(`    - ${toYamlValue(v)}`);

  lines.push("rules:");
  for (const r of rules) lines.push(`  - ${toYamlValue(r)}`);
  return `${lines.join("\n")}\n`;
}

export interface ClashBuildOpts {
  name?: string;
  dnsNameservers?: string[];
  cdnKeys?: string[];
}

/** Single-node Clash profile with the default routing preset (blocked → WARP, ru → direct). */
export function clashFromNode(node: ClashNode, opts: ClashBuildOpts = {}): string {
  const cdnKeys = opts.cdnKeys?.length ? opts.cdnKeys : ["cloudflare"];
  const cdnCidrs = [...new Set(cdnKeys.flatMap((k) => CDN_CIDRS[k] ?? []))];
  return buildClashYaml({
    name: opts.name || node.name,
    nodes: [{ ...node, address: normalizeInterfaceAddress(node.address) }],
    dns: { mode: "fake-ip", nameservers: opts.dnsNameservers },
    routing: {
      proxyDomains: CLASH_DOMAIN_PRESETS.blocked_sites,
      ruDirectDomains: CLASH_DOMAIN_PRESETS.ru_direct,
      cdnCidrs,
    },
  });
}

/** Convenience for a freshly generated WARP node. */
export function clashFromWarp(node: Omit<ClashNode, "name" | "type">, opts: ClashBuildOpts = {}): string {
  return clashFromNode({ ...node, name: "warp-auto", type: "warp" }, { name: "WARP", ...opts });
}

// ─────────────── Import (.conf / vpn://) ───────────────

function parseIniWireGuard(raw: string): { iface: Record<string, string>; peer: Record<string, string> } {
  const iface: Record<string, string> = {};
  const peer: Record<string, string> = {};
  let section = "";
  for (const rawLine of String(raw || "").replace(/\u0000/g, "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) {
      section = sec[1].trim().toLowerCase();
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    const value = line.slice(eq + 1).trim();
    if (section === "interface") iface[key] = value;
    else if (section === "peer") peer[key] = value;
  }
  return { iface, peer };
}

function parseEndpoint(raw: string): { host: string; port: number } | null {
  const value = String(raw || "").trim();
  let m = value.match(/^\[([^\]]+)\]:(\d{1,5})$/) || value.match(/^([^:]+):(\d{1,5})$/);
  if (!m) return null;
  const port = Number.parseInt(m[2], 10);
  if (!m[1] || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host: m[1].trim(), port };
}

function detectNodeType(server: string, publicKey: string, iface: Record<string, string>): ClashNodeType {
  const hasAmnezia = ["s1", "s2", "jc", "jmin", "jmax", "h1", "h2", "h3", "h4", "i1"].some((k) => iface[k]?.trim());
  if (hasAmnezia) return "amnezia";
  const host = server.trim().toLowerCase();
  if (publicKey === WARP_PUBLIC_KEY || host === "engage.cloudflareclient.com" || host.includes("cloudflareclient.com")) {
    return "warp";
  }
  return "wireguard";
}

/** Parse a WireGuard/AmneziaWG `.conf` into a Clash node. */
export function parseImportedConf(raw: string): ClashNode {
  const text = String(raw || "").trim();
  if (!text) throw new Error("Пустой конфиг.");
  const { iface, peer } = parseIniWireGuard(text);
  const privateKey = iface.privatekey?.trim() || "";
  if (!privateKey) throw new Error("В конфиге не найден Interface.PrivateKey.");
  const endpoint = parseEndpoint(peer.endpoint || "");
  if (!endpoint) throw new Error("В конфиге не найден корректный Peer.Endpoint (host:port).");
  const publicKey = peer.publickey?.trim() || WARP_PUBLIC_KEY;
  const type = detectNodeType(endpoint.host, publicKey, iface);
  const addresses = (iface.address || "").split(",").map((a) => a.trim()).filter(Boolean);
  const address = normalizeInterfaceAddress(addresses.find((a) => a.includes(".")) || addresses[0] || "172.16.0.2/32");
  const safe = endpoint.host.replace(/[^a-zA-Z0-9.-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  return { name: `${type}-${safe || "imported"}`.slice(0, 64), type, server: endpoint.host, port: endpoint.port, privateKey, publicKey, address };
}

function base64UrlToBytes(value: string): Uint8Array {
  const norm = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = norm + "=".repeat((4 - (norm.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function inflate(bytes: Uint8Array): Promise<string> {
  // Amnezia vpn:// uses Qt qCompress: 4-byte length prefix + zlib (deflate) data.
  const tail = new Uint8Array(bytes.subarray(4)); // fresh ArrayBuffer-backed copy
  const stream = new Blob([tail]).stream().pipeThrough(new DecompressionStream("deflate"));
  return new Response(stream).text();
}

/** Decode an Amnezia `vpn://` link to the inner WireGuard/AmneziaWG config text. */
export async function decodeAmneziaVpnLink(link: string): Promise<string> {
  const raw = String(link || "").trim();
  if (!raw.toLowerCase().startsWith("vpn://")) throw new Error("Некорректная vpn:// ссылка.");
  const compressed = base64UrlToBytes(raw.slice("vpn://".length));
  if (compressed.length <= 4) throw new Error("Поврежденный vpn:// payload.");
  const root = JSON.parse(await inflate(compressed));
  const container = Array.isArray(root?.containers) ? root.containers[0] : null;
  if (!container?.awg?.last_config) throw new Error("В vpn:// payload отсутствует awg.last_config.");
  const nested = JSON.parse(String(container.awg.last_config || "{}"));
  const config = typeof nested?.config === "string" ? nested.config : "";
  if (!config.trim()) throw new Error("В awg.last_config отсутствует поле config.");
  const dns1 = root?.dns1?.trim() || "1.1.1.1";
  const dns2 = root?.dns2?.trim() || "1.0.0.1";
  return config.replace(/\$PRIMARY_DNS/g, dns1).replace(/\$SECONDARY_DNS/g, dns2);
}

/** Accepts a `.conf` or a `vpn://` link and returns the raw config text. */
export async function normalizeImportedConfig(input: string): Promise<string> {
  const text = String(input || "").trim();
  if (!text) throw new Error("Пустой конфиг.");
  return text.toLowerCase().startsWith("vpn://") ? decodeAmneziaVpnLink(text) : text;
}
