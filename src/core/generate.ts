import { cfRequest } from "./http";
import { generateWireGuardKeys } from "./keys";
import { resolveI1, DEFAULT_I1_KEY } from "./i1";
import { dnsLine, dnsLineIPv4Only, dnsLineToCidrs, resolve4, DEFAULT_DNS_ID } from "./dns";
import { normalizeSplitTargets, resolveSplitAllowedIPs } from "./split";
import { isIP, normalizeInterfaceAddress } from "./ip";
import { clashFromWarp, WARP_PUBLIC_KEY } from "./clash";
import { buildObfuscationLines, JUNK_PRESETS, DEFAULT_VERSION, type AwgVersion, type ObfuscationOptions } from "./obfuscation";
import { generateSignature, type SignatureOptions } from "./signature";

export type ConfigType = "amnezia" | "wireguard" | "clash";
export type SplitMode = "full" | "selective";

export interface GenerateOptions {
  licenseKey?: string;
  configType?: ConfigType;
  obfsProfile?: string;
  endpointPort?: string;
  endpointIp?: string;
  i1Preset?: string;
  customI1Domain?: string;
  dnsServer?: string;
  splitMode?: SplitMode;
  splitTargets?: string[];
  mtu?: number;
  persistentKeepalive?: number | null;
  includeIpv6?: boolean;
  /** Explicit junk params (obfsProfile === "custom"), e.g. from warpscout find-junk. */
  customJunk?: { jc: number; jmin: number; jmax: number };
  /** AmneziaWG generation to target (1.0 / 1.5 / 2.0 / 3.0). Default 1.5. */
  awgVersion?: AwgVersion;
  /** Advanced obfuscation overrides (S1–S4, H1–H4, I2–I5, AWG 3.0 fields). */
  obfuscation?: Omit<ObfuscationOptions, "version" | "junk" | "i1">;
  /**
   * Generate the whole obfuscation set (I1–I5 chain + H/S/junk) with the
   * AmneziaWG Architect generator, mimicking a real protocol. Overrides
   * obfsProfile / i1Preset when set.
   */
  signature?: SignatureOptions;
}

export interface SplitTunnelInfo {
  mode: SplitMode;
  selectedTargets: string[];
  resolvedAllowedIps: number;
  unresolvedDomains: string[];
  sourceDomains?: number;
}

export interface GenerateResult {
  config: string;
  accountType: string;
  endpoint: string;
  licenseError: string | null;
  splitTunnel: SplitTunnelInfo;
  configType: ConfigType;
}

export class GenerateError extends Error {}

async function resolveHost(host: string): Promise<string> {
  if (!host || isIP(host)) return host || "162.159.192.1";
  const ips = await resolve4(host);
  return ips[0] || "162.159.192.1";
}

export async function generateConfig(opts: GenerateOptions): Promise<GenerateResult> {
  const configType: ConfigType =
    opts.configType === "wireguard" ? "wireguard" : opts.configType === "clash" ? "clash" : "amnezia";
  const isAmnezia = configType === "amnezia";
  const licenseKey = (opts.licenseKey ?? "").trim();
  const endpointPort = opts.endpointPort || "2408";
  const endpointIp = opts.endpointIp || "auto";
  const dnsId = opts.dnsServer || DEFAULT_DNS_ID;
  const splitMode: SplitMode = opts.splitMode === "selective" ? "selective" : "full";
  const includeIpv6 = opts.includeIpv6 !== false;
  const mtu = Number.isFinite(opts.mtu) ? Math.floor(opts.mtu as number) : 1280;

  const normalizedSplitTargets = splitMode === "selective" ? normalizeSplitTargets(opts.splitTargets) : [];
  if (splitMode === "selective" && !normalizedSplitTargets.length) {
    throw new GenerateError("Включён split tunneling, но не выбраны сервисы.");
  }

  const rawDnsLine = dnsLine(dnsId);
  const finalDnsLine = includeIpv6 ? rawDnsLine : dnsLineIPv4Only(rawDnsLine);

  const awgVersion: AwgVersion = opts.awgVersion ?? DEFAULT_VERSION;
  // Architect mode generates the whole set (I1–I5 + H/S/junk) mimicking a protocol.
  const architect = opts.signature ? generateSignature(awgVersion, opts.signature) : null;
  const junk = architect?.junk ?? opts.customJunk ?? JUNK_PRESETS[opts.obfsProfile ?? "1"] ?? JUNK_PRESETS["1"];

  // Resolve the I1 mask (valid QUIC / capture / DNS / STUN…) before touching CF.
  // In Architect mode I1 comes from the generated signature chain instead.
  const i1 = !isAmnezia
    ? ""
    : (architect?.obfuscation.i1 ?? (await resolveI1(opts.i1Preset || DEFAULT_I1_KEY, opts.customI1Domain)));

  // 1. Keys + register a fresh Cloudflare device.
  const { priv, pub } = generateWireGuardKeys();
  const reg = await cfRequest("POST", "reg", null, {
    install_id: "",
    tos: new Date().toISOString(),
    key: pub,
    fcm_token: "",
    type: "ios",
    locale: "en_US",
  });
  if (reg.status !== 200 || !reg.body?.result?.id) {
    throw new GenerateError(`Cloudflare registration failed (HTTP ${reg.status})`);
  }
  const id = reg.body.result.id as string;
  const token = reg.body.result.token as string;

  // 2. Apply a WARP+ license if the user supplied one.
  let accountType = "free";
  let licenseError: string | null = null;
  if (licenseKey) {
    const lic = await cfRequest("PUT", `reg/${id}/account`, token, { license: licenseKey });
    const body = lic.body ?? {};
    const acType =
      body?.result?.account_type ||
      body?.result?.account?.account_type ||
      body?.result?.type ||
      (body?.result?.warp_plus ? "warp_plus" : null);

    if (acType === "warp_plus" || acType === "unlimited") {
      accountType = acType;
    } else {
      const rawErr = (body?.errors?.[0]?.message || body?.error || "").toLowerCase();
      if (rawErr.includes("too many connected devices") || rawErr.includes("too many devices")) {
        licenseError = "На этом ключе превышен лимит устройств (макс. 5).";
      } else if (rawErr.includes("invalid") || rawErr.includes("not found")) {
        licenseError = "Ключ WARP+ недействителен или не существует.";
      } else if (rawErr) {
        licenseError = body?.errors?.[0]?.message || body?.error;
      } else if (body?.success === true) {
        accountType = "warp_plus";
      } else {
        licenseError = "Ключ принят, но тип аккаунта не распознан.";
      }
    }
  }

  // 3. Enable WARP and pull the peer config.
  const warp = await cfRequest("PATCH", `reg/${id}`, token, { warp_enabled: true });
  if (warp.status !== 200 || !warp.body?.result?.config) {
    throw new GenerateError(`Failed to enable WARP (HTTP ${warp.status})`);
  }

  const cfg = warp.body.result.config;
  const peerPub = cfg.peers?.[0]?.public_key as string | undefined;
  const ipv4 = cfg.interface?.addresses?.v4 as string | undefined;
  const ipv6 = cfg.interface?.addresses?.v6 as string | undefined;

  let epIp: string;
  if (endpointIp === "auto") {
    const rawHost = (cfg.peers?.[0]?.endpoint?.host || "").split(":")[0];
    epIp = await resolveHost(rawHost);
  } else {
    epIp = endpointIp;
  }
  const endpoint = `${epIp}:${endpointPort}`;

  const addressParts = includeIpv6 ? [ipv4, ipv6] : [ipv4];
  const address = addressParts
    .map((a) => normalizeInterfaceAddress(a ?? ""))
    .filter(Boolean)
    .join(", ");
  if (!address) {
    throw new GenerateError("Cloudflare не вернул корректный адрес интерфейса.");
  }

  // Clash uses routing rules (not AllowedIPs) — emit YAML and return early.
  if (configType === "clash") {
    const config = clashFromWarp(
      {
        server: epIp,
        port: Number(endpointPort) || 2408,
        address: ipv4 || "172.16.0.2/32",
        privateKey: priv,
        publicKey: peerPub || WARP_PUBLIC_KEY,
        reserved: decodeReserved(cfg.client_id),
      },
      { dnsNameservers: dnsId === "malw_link" ? ["https://dns.malw.link/dns-query"] : undefined },
    );
    return {
      config,
      accountType,
      endpoint,
      licenseError,
      splitTunnel: { mode: "full", selectedTargets: [], resolvedAllowedIps: 0, unresolvedDomains: [] },
      configType,
    };
  }

  // 4. AllowedIPs — full tunnel or resolved split routes.
  let allowedIpsLine = includeIpv6 ? "0.0.0.0/0, ::/0" : "0.0.0.0/0";
  const splitTunnel: SplitTunnelInfo = {
    mode: "full",
    selectedTargets: [],
    resolvedAllowedIps: includeIpv6 ? 2 : 1,
    unresolvedDomains: [],
  };

  if (splitMode === "selective") {
    const resolved = await resolveSplitAllowedIPs(normalizedSplitTargets);
    if (!resolved.allowedIps.length) {
      throw new GenerateError("Не удалось получить IP для выбранных сервисов.");
    }
    const set = new Set(resolved.allowedIps);
    for (const cidr of dnsLineToCidrs(finalDnsLine)) set.add(cidr);
    const finalAllowedIps = [...set].sort((a, b) => a.localeCompare(b));
    if (finalAllowedIps.length > 512) {
      throw new GenerateError(
        `Слишком много маршрутов для split tunneling (${finalAllowedIps.length}). Уменьшите количество выбранных сервисов.`,
      );
    }
    allowedIpsLine = finalAllowedIps.join(", ");
    splitTunnel.mode = "selective";
    splitTunnel.selectedTargets = normalizedSplitTargets;
    splitTunnel.resolvedAllowedIps = finalAllowedIps.length;
    splitTunnel.unresolvedDomains = resolved.unresolvedDomains;
    splitTunnel.sourceDomains = resolved.sourceDomains;
  }

  // 5. Assemble the config text.
  const interfaceLines: string[] = ["[Interface]", `PrivateKey = ${priv}`];
  if (isAmnezia) {
    interfaceLines.push(
      ...buildObfuscationLines({ ...architect?.obfuscation, ...opts.obfuscation, version: awgVersion, junk, i1 }),
    );
  }
  interfaceLines.push(`MTU = ${mtu}`, `Address = ${address}`, `DNS = ${finalDnsLine}`);

  const peerLines = ["[Peer]", `PublicKey = ${peerPub}`, `AllowedIPs = ${allowedIpsLine}`, `Endpoint = ${endpoint}`];
  const keepalive = normalizeKeepalive(opts.persistentKeepalive);
  if (keepalive !== undefined) peerLines.push(`PersistentKeepalive = ${keepalive}`);

  const config = [...interfaceLines, "", ...peerLines].join("\n");

  return { config, accountType, endpoint, licenseError, splitTunnel, configType };
}

/** Cloudflare `client_id` (base64, 3 bytes) → the Clash `reserved` triple. */
function decodeReserved(clientId: unknown): number[] | null {
  if (typeof clientId !== "string" || !clientId) return null;
  try {
    const bin = atob(clientId);
    const bytes = Array.from(bin, (c) => c.charCodeAt(0));
    return bytes.length >= 3 ? bytes.slice(0, 3) : null;
  } catch {
    return null;
  }
}

/** Positive integer keepalive, or 25 by default; pass null to omit entirely. */
function normalizeKeepalive(value: number | null | undefined): number | undefined {
  if (value === null) return undefined;
  if (value === undefined) return 25;
  const n = Math.floor(value);
  if (!Number.isFinite(n) || n <= 0 || n > 65535) return 25;
  return n;
}
