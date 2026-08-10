// Self-check: node --experimental-strip-types src/core/obfuscation.test.ts
// Verifies each AWG profile emits the right parameter set, and round-trips the
// generated config through the analyzer (it must detect the same version back).
import assert from "node:assert/strict";
import { buildObfuscationLines, randomHRanges, recommendedMtu, generateHeaderProtectionKey } from "./obfuscation.ts";
import { analyzeConfig } from "./analyzer.ts";

const I1 = "<b 0xc00000000108abcdef0102030405>";
const has = (lines: string[], key: string) => lines.some((l) => l.startsWith(`${key} = `));
const val = (lines: string[], key: string) => lines.find((l) => l.startsWith(`${key} = `))?.slice(key.length + 3);

// ── 1.0: junk + S1/S2 + H, no CPS ──
const v10 = buildObfuscationLines({ version: "1.0", i1: I1 });
assert.ok(has(v10, "Jc") && has(v10, "S1") && has(v10, "H1"));
assert.equal(has(v10, "I1"), false, "1.0 must not emit I1");
assert.equal(has(v10, "S3"), false, "1.0 must not emit S3");

// ── 1.5: adds I1 ──
const v15 = buildObfuscationLines({ version: "1.5", i1: I1 });
assert.equal(has(v15, "I1"), true);
assert.equal(has(v15, "S3"), false, "1.5 must not emit S3/S4");

// ── 2.0: adds S3/S4 + H ranges + I2–I5 ──
const v20 = buildObfuscationLines({ version: "2.0", i1: I1, i2: "<r 100>" });
assert.ok(has(v20, "S3") && has(v20, "S4"), "2.0 must emit S3/S4");
assert.ok(val(v20, "H1")!.includes("-"), "2.0 must use H ranges by default");
assert.equal(val(v20, "I2"), "<r 100>");

// ── 3.0: adds header protection ──
const key = generateHeaderProtectionKey();
const v30 = buildObfuscationLines({ version: "3.0", i1: I1, headerProtectionKey: key, contentPaddingAddition: 32 });
assert.equal(val(v30, "HeaderProtectionKey"), key);
assert.equal(val(v30, "ContentPaddingAddition"), "32");
assert.match(key, /^[A-Za-z0-9+/]{43}=$/, "header key must be base64 32 bytes");

// ── AWG rule: S1 + 56 ≠ S2 (auto-corrected) ──
const conflict = buildObfuscationLines({ version: "1.5", s1: 10, s2: 66, i1: I1 });
assert.notEqual(val(conflict, "S2"), "66", "S1+56 == S2 must be nudged");

// H ranges are non-overlapping and ascending
const hs = randomHRanges().map((r) => r.split("-").map(Number));
for (let i = 1; i < hs.length; i++) assert.ok(hs[i][0] > hs[i - 1][1], "H ranges must not overlap");

// MTU advice tightens as obfuscation grows
assert.ok(recommendedMtu("1.0") > recommendedMtu("1.5"));
assert.ok(recommendedMtu("1.5") > recommendedMtu("2.0"));
assert.ok(recommendedMtu("2.0") > recommendedMtu("3.0"));

// ── round-trip: generated config → analyzer detects the same generation ──
const PEER = "\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 162.159.192.1:2408\n";
const KEY = "aFmZzZ0m3q0Yy9m5o0xJ0m6bJ2W1oG1p2mS8kC3xV1c=";
const conf = (lines: string[]) => `[Interface]\nPrivateKey = ${KEY}\n${lines.join("\n")}\nAddress = 172.16.0.2/32\n${PEER}`;

assert.equal(analyzeConfig(conf(v15)).version.ver, "AWG 1.5");
assert.equal(analyzeConfig(conf(v20)).version.ver, "AWG 2.0");
assert.equal(analyzeConfig(conf(v30)).version.ver, "AWG 3.0");
assert.equal(analyzeConfig(conf(v15)).version.protocol, "QUIC");

// stronger profile ⇒ lower DPI detectability, end to end
const d15 = analyzeConfig(conf(v15)).scores.dpi;
const d20 = analyzeConfig(conf(v20)).scores.dpi;
const d30 = analyzeConfig(conf(v30)).scores.dpi;
assert.ok(d15 > d20 && d20 > d30, `dpi must fall 1.5→2.0→3.0 (${d15}/${d20}/${d30})`);

// 2.0 uses H ranges ⇒ no "default headers" failure
assert.equal(
  analyzeConfig(conf(v20)).checks.some((c) => c.title === "H1–H4" && c.status === "fail"),
  false,
  "2.0 H ranges must not be flagged as default",
);

console.log("obfuscation: all checks passed ✓");
