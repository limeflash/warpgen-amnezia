/**
 * Wrapper over the vendored AmneziaWG Architect generator (see
 * `vendor/awg-architect.ts`). Produces a complete obfuscation parameter set —
 * the CPS chain I1–I5 plus H1–H4 / S1–S4 / junk — that mimics a real protocol.
 *
 * This is a much stronger option than a single hand-built I1: the whole
 * handshake sequence looks like QUIC / TLS / HTTP3 / DTLS / SIP / DNS traffic.
 */

import { genCfg, PROFILE_LABELS, type GeneratorInput, type MimicProfile, type Intensity } from "./vendor/awg-architect.ts";
import type { AwgVersion, ObfuscationOptions, JunkParams } from "./obfuscation.ts";

export type { MimicProfile, Intensity };
export { PROFILE_LABELS };

/** Mimicry profiles offered in the UI, in a sensible order. */
export const MIMIC_PROFILES: MimicProfile[] = [
  "quic_initial",
  "quic_0rtt",
  "tls_client_hello",
  "http3",
  "dtls",
  "sip",
  "dns_query",
  "wireguard_noise",
  "tls_to_quic",
  "quic_burst",
  "random",
];

export interface SignatureOptions {
  profile?: MimicProfile;
  intensity?: Intensity;
  /** Force a specific SNI/host instead of the profile's host pool. */
  customHost?: string;
  mtu?: number;
  /** Junk volume 0–10 (Architect scale). */
  junkLevel?: number;
  /** Mimic a real browser's fingerprint (Chrome/Edge/Firefox/Safari/Yandex). */
  browserProfile?: GeneratorInput["browserProfile"];
  /** Low-power devices: keep the noise minimal. */
  routerMode?: boolean;
}

/** Architect targets AWG ≤2.0; our 3.0 profile reuses the 2.0 parameter set. */
function architectVersion(v: AwgVersion): "1.0" | "1.5" | "2.0" {
  return v === "3.0" ? "2.0" : v;
}

function buildInput(version: AwgVersion, o: SignatureOptions): GeneratorInput {
  return {
    version: architectVersion(version),
    intensity: o.intensity ?? "medium",
    profile: o.profile ?? "quic_initial",
    customHost: o.customHost ?? "",
    mimicAll: false,
    // <c> breaks older AmneziaVPN clients (ErrorCode 1000) — off, as upstream.
    useTagC: false,
    useTagT: true,
    useTagR: true,
    useTagRC: true,
    useTagRD: true,
    useBrowserFp: !!o.browserProfile,
    browserProfile: o.browserProfile ?? "",
    mtu: o.mtu ?? 1280,
    junkLevel: o.junkLevel ?? 5,
    iterCount: 0,
    routerMode: o.routerMode ?? false,
    useExtremeMax: false,
  };
}

export interface GeneratedSignature {
  /** Junk parameters to feed into the config. */
  junk: JunkParams;
  /** Obfuscation overrides (S1–S4, H1–H4, I1–I5) ready for buildObfuscationLines. */
  obfuscation: Omit<ObfuscationOptions, "version" | "junk">;
  profile: MimicProfile;
}

/**
 * Generates a full obfuscation parameter set mimicking `profile`.
 * H1–H4 come as ranges on 2.0+ and as single values on 1.x, matching the
 * capabilities of each AmneziaWG generation.
 */
export function generateSignature(version: AwgVersion, opts: SignatureOptions = {}): GeneratedSignature {
  const cfg = genCfg(buildInput(version, opts));
  const is20plus = version === "2.0" || version === "3.0";

  const h: [string, string, string, string] = is20plus
    ? [cfg.h1, cfg.h2, cfg.h3, cfg.h4]
    : [String(cfg.h1s), String(cfg.h2s), String(cfg.h3s), String(cfg.h4s)];

  return {
    junk: { jc: cfg.jc, jmin: cfg.jmin, jmax: cfg.jmax },
    profile: cfg.profile,
    obfuscation: {
      s1: cfg.s1,
      s2: cfg.s2,
      s3: cfg.s3,
      s4: cfg.s4,
      h,
      i1: cfg.i1,
      // The I2–I5 chain only applies from 1.5 on (CPS).
      ...(version === "1.0" ? {} : { i2: cfg.i2, i3: cfg.i3, i4: cfg.i4, i5: cfg.i5 }),
    },
  };
}

/** Just the CPS chain, for callers that only want I1–I5. */
export function generateSignaturePackets(
  profile: MimicProfile = "quic_initial",
  mtu = 1280,
): { i1: string; i2: string; i3: string; i4: string; i5: string } {
  const cfg = genCfg(buildInput("2.0", { profile, mtu }));
  return { i1: cfg.i1, i2: cfg.i2, i3: cfg.i3, i4: cfg.i4, i5: cfg.i5 };
}
