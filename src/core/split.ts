import { isIP } from "./ip";
import { resolve4, resolve6 } from "./dns";
import { SPLIT_TUNNEL_TARGETS } from "./split-targets";

export { SPLIT_TUNNEL_TARGETS };
export type { SplitTarget } from "./split-targets";

/** Keeps only known target keys, de-duplicated. */
export function normalizeSplitTargets(list: unknown): string[] {
  if (!Array.isArray(list)) return [];
  const uniq = new Set<string>();
  for (const raw of list) {
    if (typeof raw !== "string") continue;
    const key = raw.trim();
    if (key && SPLIT_TUNNEL_TARGETS[key]) uniq.add(key);
  }
  return [...uniq];
}

/** [{ key, label }] for rendering the service picker. */
export function splitTargetList(): Array<{ key: string; label: string }> {
  return Object.entries(SPLIT_TUNNEL_TARGETS).map(([key, t]) => ({ key, label: t.label }));
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
