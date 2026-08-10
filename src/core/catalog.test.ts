// Self-check: node --experimental-strip-types src/core/catalog.test.ts
// Validates the service catalog and its wiring into split targets / Clash rules.
import assert from "node:assert/strict";
import { SERVICE_CATALOG, catalogByCategory, domainsForServices, CATEGORY_LABELS } from "./service-catalog.ts";
import { normalizeSplitTargets, catalogTargetGroups } from "./split.ts";

// ── catalog integrity ──
assert.ok(SERVICE_CATALOG.length >= 70, `expected 70+ services, got ${SERVICE_CATALOG.length}`);
const ids = new Set<string>();
for (const s of SERVICE_CATALOG) {
  assert.ok(s.id && s.name && s.category, `malformed entry: ${JSON.stringify(s).slice(0, 80)}`);
  assert.ok(s.domains.length > 0, `${s.id}: must carry domains`);
  assert.equal(ids.has(s.id), false, `duplicate id: ${s.id}`);
  ids.add(s.id);
  for (const d of s.domains) {
    assert.equal(d, d.toLowerCase().trim(), `${s.id}: domain not normalised: ${d}`);
    assert.ok(!d.includes("/") && !d.includes(" "), `${s.id}: bad domain: ${d}`);
  }
}

// well-known services present
for (const id of ["openai", "anthropic", "youtube", "discord", "telegram", "steam", "github"]) {
  assert.ok(ids.has(id), `catalog must include ${id}`);
}

// ── grouping ──
const groups = catalogByCategory();
assert.ok(groups.length >= 5, "expected several categories");
assert.equal(
  groups.reduce((n, g) => n + g.services.length, 0),
  SERVICE_CATALOG.length,
  "grouping must cover every service",
);
for (const g of groups) assert.ok(g.label && g.label !== g.category || CATEGORY_LABELS[g.category] === undefined);

// ── merged domains ──
const merged = domainsForServices(["openai", "anthropic"]);
const expected = new Set([
  ...SERVICE_CATALOG.find((s) => s.id === "openai")!.domains,
  ...SERVICE_CATALOG.find((s) => s.id === "anthropic")!.domains,
]);
assert.equal(merged.length, expected.size, "merged list must be de-duplicated");
assert.deepEqual(merged, [...merged].sort(), "merged list must be sorted");
assert.deepEqual(domainsForServices([]), [], "no services → no domains");
assert.deepEqual(domainsForServices(["does-not-exist"]), [], "unknown id → no domains");

// ── split-target wiring (cat: prefix) ──
const picked = normalizeSplitTargets(["cat:openai", "discord", "cat:nope", "bogus", "cat:openai"]);
assert.deepEqual(picked.sort(), ["cat:openai", "discord"], `unexpected: ${picked.join(",")}`);

const catGroups = catalogTargetGroups();
assert.ok(catGroups.length >= 5, "catalog target groups must be exposed");
assert.ok(
  catGroups.every((g) => g.targets.every((t) => t.key.startsWith("cat:"))),
  "catalog targets must be prefixed",
);

console.log(`catalog: all checks passed ✓ (${SERVICE_CATALOG.length} services, ${SERVICE_CATALOG.reduce((n, s) => n + s.domains.length, 0)} domains)`);
