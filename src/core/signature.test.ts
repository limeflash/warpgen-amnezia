// Self-check: node --experimental-strip-types src/core/signature.test.ts
// Generates obfuscation sets with the Architect generator and verifies them
// through our own analyzer (protocol mimicry, CPS chain, profile version).
import assert from "node:assert/strict";
import { generateSignature, generateSignaturePackets, MIMIC_PROFILES } from "./signature.ts";
import { buildObfuscationLines } from "./obfuscation.ts";
import { analyzeConfig, parseI1 } from "./analyzer.ts";

const PEER = "\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 162.159.192.1:2408\n";
const KEY = "aFmZzZ0m3q0Yy9m5o0xJ0m6bJ2W1oG1p2mS8kC3xV1c=";
const conf = (lines: string[]) => `[Interface]\nPrivateKey = ${KEY}\n${lines.join("\n")}\nAddress = 172.16.0.2/32\n${PEER}`;

// ── every profile produces a valid, parseable CPS chain ──
for (const profile of MIMIC_PROFILES) {
  const sig = generateSignature("2.0", { profile });
  const o = sig.obfuscation;

  assert.ok(o.i1 && o.i1.length > 0, `${profile}: I1 must be generated`);
  const p = parseI1(o.i1!);
  assert.equal(p.startsWithB, true, `${profile}: I1 must start with <b …>`);
  assert.deepEqual(p.errors, [], `${profile}: I1 must have no validation errors: ${p.errors.join("; ")}`);

  // junk + padding sanity
  assert.ok(sig.junk.jc > 0, `${profile}: Jc must be > 0`);
  assert.ok(sig.junk.jmin <= sig.junk.jmax, `${profile}: Jmin ≤ Jmax`);
  assert.notEqual(o.s1! + 56, o.s2, `${profile}: AWG rule S1+56 ≠ S2`);

  // H1–H4 ranges on 2.0, non-default
  assert.ok(o.h!.every((h) => h.includes("-")), `${profile}: H must be ranges on 2.0`);

  // full config must analyze as AWG 2.0 with no default-header failure
  const a = analyzeConfig(conf(buildObfuscationLines({ ...o, version: "2.0", junk: sig.junk })));
  assert.equal(a.version.ver, "AWG 2.0", `${profile}: expected AWG 2.0, got ${a.version.ver}`);
  assert.equal(
    a.checks.some((c) => c.title === "H1–H4" && c.status === "fail"),
    false,
    `${profile}: H must not be flagged as default`,
  );
}

// ── mimicry is actually recognisable ──
const expectProto: Array<[Parameters<typeof generateSignature>[1] extends never ? never : any, string]> = [
  ["quic_initial", "QUIC"],
  ["tls_client_hello", "TLS"],
  ["dns_query", "DNS"],
];
for (const [profile, proto] of expectProto) {
  const { obfuscation } = generateSignature("2.0", { profile });
  assert.equal(parseI1(obfuscation.i1!).protocol, proto, `${profile} must mimic ${proto}`);
}

// ── CPS chain: 1.5+ emits I2–I5, 1.0 does not ──
const s15 = generateSignature("1.5", { profile: "quic_initial" });
assert.ok(s15.obfuscation.i2 && s15.obfuscation.i5, "1.5 must produce the I2–I5 chain");
const s10 = generateSignature("1.0", { profile: "quic_initial" });
assert.equal(s10.obfuscation.i2, undefined, "1.0 must not carry the CPS chain");
assert.ok(!s10.obfuscation.h!.some((h) => h.includes("-")), "1.x must use single H values, not ranges");

// packets-only helper
const pk = generateSignaturePackets("http3");
assert.ok(pk.i1 && pk.i2 && pk.i3 && pk.i4 && pk.i5, "packets helper must return the full chain");

// two runs differ (randomised) — no static fingerprint
const a1 = generateSignature("2.0", { profile: "quic_initial" }).obfuscation.i1;
const a2 = generateSignature("2.0", { profile: "quic_initial" }).obfuscation.i1;
assert.notEqual(a1, a2, "signatures must be randomised per generation");

console.log(`signature: all checks passed ✓ (${MIMIC_PROFILES.length} profiles)`);
