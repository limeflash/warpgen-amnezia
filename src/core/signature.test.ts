// Self-check: node --experimental-strip-types src/core/signature.test.ts
// Generates obfuscation sets with the Architect generator and verifies them
// through our own analyzer (protocol mimicry, CPS chain, profile version).
import assert from "node:assert/strict";
import { generateSignature, generateSignaturePackets, MIMIC_PROFILES } from "./signature.ts";
import { buildObfuscationLines } from "./obfuscation.ts";
import { analyzeConfig, parseI1 } from "./analyzer.ts";
import { calcByteSize, calcChainSize, validateChainSize, CPS_MAX_BYTES, PROTOCOL_INFO } from "./awg-meta.ts";

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

// ── CPS chain size: every generated chain must fit AmneziaWG's 4096-byte limit ──
for (const profile of MIMIC_PROFILES) {
  const o = generateSignature("2.0", { profile }).obfuscation;
  const check = validateChainSize(o);
  assert.equal(check.ok, true, `${profile}: chain ${check.bytes}B exceeds ${CPS_MAX_BYTES}B`);
  assert.ok(check.bytes > 0, `${profile}: chain size must be counted`);
}

// size accounting: <b> hex/2 + <r|rc|rd> N + 4 per <c>/<t>
assert.equal(calcByteSize("<b 0xdeadbeef>"), 4);
assert.equal(calcByteSize("<b 0xdeadbeef><r 100>"), 104);
assert.equal(calcByteSize("<b 0xaabb><t>"), 6);
assert.equal(calcByteSize(""), 0);
assert.equal(calcChainSize({ i1: "<r 10>", i2: "<r 20>", i3: "<r 30>" }), 60);

// over-limit chain is rejected with a message
const over = validateChainSize({ i1: `<r 999>`, i2: `<r 999>`, i3: `<r 999>`, i4: `<r 999>`, i5: `<r 999>` });
assert.equal(over.bytes, 4995);
assert.equal(over.ok, false);
assert.match(over.message!, /превышает лимит/);

// analyzer flags an over-limit chain in a real config
const bigChain = analyzeConfig(
  conf(["Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 0", "S2 = 1", "H1 = 5", "H2 = 6", "H3 = 7", "H4 = 8",
    // 1003 + 4×999 = 4999 B > 4096 B limit
    "I1 = <b 0xc0000000><r 999>", "I2 = <r 999>", "I3 = <r 999>", "I4 = <r 999>", "I5 = <r 999>"]),
);
assert.ok(
  bigChain.checks.some((c) => c.title === "Размер цепочки I1–I5" && c.status === "fail"),
  "analyzer must flag an over-limit CPS chain",
);

// every UI profile has a label/description
for (const p of MIMIC_PROFILES) assert.ok(PROTOCOL_INFO[p]?.name, `${p}: missing label`);

console.log(`signature: all checks passed ✓ (${MIMIC_PROFILES.length} profiles)`);
