// Self-check for the config analyzer: node --experimental-strip-types src/core/analyzer.test.ts
// Asserts version detection, I1 CPS parsing/mimicry and the scoring direction.
import assert from "node:assert/strict";
import { analyzeConfig, parseI1, detectI1ProtocolFromHex } from "./analyzer.ts";

const PEER = `
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = 162.159.192.1:2408
`;
const KEY = "aFmZzZ0m3q0Yy9m5o0xJ0m6bJ2W1oG1p2mS8kC3xV1c=";

const plainWg = `[Interface]\nPrivateKey = ${KEY}\nAddress = 172.16.0.2/32\nMTU = 1420\n${PEER}`;

const awg10 = `[Interface]\nPrivateKey = ${KEY}\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 11\nH2 = 22\nH3 = 33\nH4 = 44\nMTU = 1280\n${PEER}`;

// Our generator's output shape (Jc/S/H + a QUIC I1) → AWG 1.5, QUIC mimicry.
const awg15 = `[Interface]\nPrivateKey = ${KEY}\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nI1 = <b 0xc00000000108abcdef0102030405>\nMTU = 1280\n${PEER}`;

const awg20 = `[Interface]\nPrivateKey = ${KEY}\nJc = 6\nJmin = 50\nJmax = 1000\nS1 = 10\nS2 = 20\nS3 = 15\nS4 = 25\nH1 = 5-60000\nH2 = 60001-120000\nH3 = 120001-180000\nH4 = 180001-240000\nI1 = <b 0x160303001234><r 100><t>\nMTU = 1320\n${PEER}`;

const awg30 = `[Interface]\nPrivateKey = ${KEY}\nJc = 6\nJmin = 50\nJmax = 1000\nS1 = 10\nS2 = 20\nHeaderProtectionKey = ${KEY}\nMTU = 1280\n${PEER}`;

// ── version detection ──
assert.equal(analyzeConfig(plainWg).version.ver, "WireGuard");
assert.equal(analyzeConfig(awg10).version.ver, "AWG 1.0");
assert.equal(analyzeConfig(awg15).version.ver, "AWG 1.5");
assert.equal(analyzeConfig(awg20).version.ver, "AWG 2.0");
assert.equal(analyzeConfig(awg30).version.ver, "AWG 3.0");

// ── mimicry ──
assert.equal(analyzeConfig(awg15).version.protocol, "QUIC");
assert.equal(analyzeConfig(awg15).camouflage, "HIGH");
assert.equal(analyzeConfig(awg20).version.protocol, "TLS");
assert.equal(analyzeConfig(plainWg).camouflage, "LOW");
assert.equal(detectI1ProtocolFromHex("16fefd0102"), "DTLS");
assert.equal(detectI1ProtocolFromHex("0001abcd2112a442"), "STUN");

// ── I1 CPS parsing ──
const cps = parseI1("<b 0xc0000000010203><r 100><t>");
assert.equal(cps.startsWithB, true);
assert.equal(cps.protocol, "QUIC");
assert.equal(cps.totalRBytes, 100);
assert.equal(cps.hasT, true);
assert.deepEqual(cps.errors, []);

// bad: must start with <b>, <r> too big, deprecated <c>
const bad = parseI1("<r 1500><b 0xc000000001><c>");
assert.equal(bad.startsWithB, false);
assert.equal(bad.errors.length, 3, `expected 3 errors, got ${bad.errors.length}`);

// ── scoring: stronger profile ⇒ lower DPI detectability ──
const sPlain = analyzeConfig(plainWg).scores;
const s15 = analyzeConfig(awg15).scores;
const s20 = analyzeConfig(awg20).scores;
const s30 = analyzeConfig(awg30).scores;
assert.ok(sPlain.dpi > s15.dpi && s15.dpi > s20.dpi && s20.dpi > s30.dpi, "dpi must fall as the profile strengthens");
assert.ok(s20.stealth > sPlain.stealth, "stealth must rise with a stronger profile");
assert.ok(s20.total > sPlain.total, `total must rise (${sPlain.total} → ${s20.total})`);

// default H1-4 must be flagged on our own 1.5 output
assert.ok(
  analyzeConfig(awg15).checks.some((c) => c.title === "H1–H4" && c.status === "fail"),
  "default H1=1..H4=4 must be flagged",
);
// S1+56 == S2 conflict rule
assert.ok(
  analyzeConfig(`[Interface]\nPrivateKey = ${KEY}\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 10\nS2 = 66\nH1 = 5\nH2 = 6\nH3 = 7\nH4 = 8\n${PEER}`)
    .checks.some((c) => c.title.includes("S1+56")),
  "S1+56=S2 conflict must be reported",
);

console.log("analyzer: all checks passed ✓");
