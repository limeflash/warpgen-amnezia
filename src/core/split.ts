import { isIP } from "./ip.ts";
import { resolve4, resolve6 } from "./dns.ts";
import { SPLIT_TUNNEL_TARGETS } from "./split-targets.ts";
import { SERVICE_CATALOG, catalogByCategory } from "./service-catalog.ts";

export { SPLIT_TUNNEL_TARGETS };
export type { SplitTarget } from "./split-targets.ts";

// Catalog services are addressable as split targets too, under a `cat:` prefix
// so they can't collide with the hand-curated ones (which also carry CIDRs).
const CATALOG_PREFIX = "cat:";
const catalogById = new Map(SERVICE_CATALOG.map((s) => [s.id, s]));

/** Keeps only known target keys (curated or `cat:<id>`), de-duplicated. */
export function normalizeSplitTargets(list: unknown): string[] {
  if (!Array.isArray(list)) return [];
  const uniq = new Set<string>();
  for (const raw of list) {
    if (typeof raw !== "string") continue;
    const key = raw.trim();
    if (!key) continue;
    if (SPLIT_TUNNEL_TARGETS[key]) uniq.add(key);
    else if (key.startsWith(CATALOG_PREFIX) && catalogById.has(key.slice(CATALOG_PREFIX.length))) uniq.add(key);
  }
  return [...uniq];
}

/** [{ key, label }] for the curated targets (they carry CIDRs / processes). */
export function splitTargetList(): Array<{ key: string; label: string }> {
  return Object.entries(SPLIT_TUNNEL_TARGETS).map(([key, t]) => ({ key, label: t.label }));
}

/** The full catalog grouped by category, keys prefixed for split-target use. */
export function catalogTargetGroups(): Array<{ label: string; targets: Array<{ key: string; label: string }> }> {
  return catalogByCategory().map((g) => ({
    label: g.label,
    targets: g.services.map((s) => ({ key: `${CATALOG_PREFIX}${s.id}`, label: s.name })),
  }));
}

export interface SplitResolution {
  allowedIps: string[];
  unresolvedDomains: string[];
  sourceDomains: number;
}

/** Resolves every selected service's domains (via DoH) + static CIDRs into host routes. */
export async function resolveSplitAllowedIPs(keys: string[]): Promise<SplitResolution> {
  const cidrs = new Set<string>();
  const domains = new Set<string>();

  for (const key of keys) {
    // Catalog service (`cat:<id>`) — domains only.
    if (key.startsWith(CATALOG_PREFIX)) {
      for (const domain of catalogById.get(key.slice(CATALOG_PREFIX.length))?.domains ?? []) {
        const clean = domain.trim().toLowerCase();
        if (clean) domains.add(clean);
      }
      continue;
    }
    const target = SPLIT_TUNNEL_TARGETS[key];
    if (!target) continue;
    for (const domain of target.domains ?? []) {
      const clean = domain.trim().toLowerCase();
      if (clean) domains.add(clean);
    }
    for (const cidr of target.cidrs ?? []) {
      if (cidr.trim()) cidrs.add(cidr.trim());
    }
  }

  const unresolved: string[] = [];

  await Promise.all(
    [...domains].map(async (domain) => {
      const t = isIP(domain);
      if (t === 4) {
        cidrs.add(`${domain}/32`);
        return;
      }
      if (t === 6) {
        cidrs.add(`${domain}/128`);
        return;
      }
      const [a4, a6] = await Promise.all([resolve4(domain), resolve6(domain)]);
      let resolved = false;
      for (const ip of a4) {
        cidrs.add(`${ip}/32`);
        resolved = true;
      }
      for (const ip of a6) {
        cidrs.add(`${ip}/128`);
        resolved = true;
      }
      if (!resolved) unresolved.push(domain);
    }),
  );

  return {
    allowedIps: [...cidrs].sort((a, b) => a.localeCompare(b)),
    unresolvedDomains: unresolved.sort((a, b) => a.localeCompare(b)),
    sourceDomains: domains.size,
  };
}
