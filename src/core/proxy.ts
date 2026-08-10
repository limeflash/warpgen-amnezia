import { httpFetch } from "./http";
import { checkWarpKey } from "./license";

export function parseProxy(proxyStr: string): string | null {
  if (!proxyStr || !proxyStr.trim()) return null;
  let s = proxyStr.trim();

  // Optional user:pass@ prefix.
  const authMatch = s.match(/^([^@]+)@(.+)$/);
  let auth: string | null = null;
  if (authMatch) {
    auth = authMatch[1];
    s = authMatch[2];
  }

  if (!/^(https?|socks[45]):\/\//.test(s)) s = `http://${s}`;

  if (auth) {
    try {
      const url = new URL(s);
      url.username = auth.split(":")[0] || "";
      url.password = auth.split(":")[1] || "";
      return url.toString();
    } catch {
      return s;
    }
  }
  return s;
}

/** True if the proxy passes traffic to Cloudflare's connectivity-check host. */
export async function checkProxy(proxyUrl: string): Promise<boolean> {
  try {
    const res = await httpFetch("http://cp.cloudflare.com/", {
      method: "GET",
      headers: { "User-Agent": "curl/7.88" },
      proxy: { all: proxyUrl },
      connectTimeout: 4000,
      maxRedirections: 0,
    });
    return res.status >= 200 && res.status < 400;
  } catch {
    return false;
  }
}

export interface ProxyCheckProgress {
  checked: number;
  valid: number;
  total: number;
}

export interface ProxyCheckOptions {
  concurrency?: number;
  signal?: AbortSignal;
  onProgress?: (p: ProxyCheckProgress) => void;
  onValid?: (proxy: string) => void;
}

/** Runs a worker pool over the proxies, returns the ones that passed. */
export async function runProxyCheck(rawProxies: string[], opts: ProxyCheckOptions = {}): Promise<string[]> {
  const proxies = rawProxies
    .map(parseProxy)
    .filter((p): p is string => !!p)
    .slice(0, 20000);
  const concurrency = Math.min(Math.max(opts.concurrency ?? 100, 1), 500);
  const total = proxies.length;
  let checked = 0;
  let valid = 0;
  const validList: string[] = [];
  const queue = [...proxies];

  const worker = async () => {
    while (queue.length && !opts.signal?.aborted) {
      const proxy = queue.shift();
      if (!proxy) break;
      const ok = await checkProxy(proxy);
      checked++;
      if (ok) {
        valid++;
        validList.push(proxy);
        opts.onValid?.(proxy);
      }
      opts.onProgress?.({ checked, valid, total });
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, total || 1) }, worker));
  return validList;
}

export interface BruteforceEvent {
  type: "valid" | "invalid";
  key: string;
  accountType?: string;
  error?: string | null;
  checked: number;
  total: number;
  found: number;
  aliveCount: number;
}

export interface BruteforceOptions {
  concurrency?: number;
  signal?: AbortSignal;
  onEvent?: (e: BruteforceEvent) => void;
}

const PROXY_FAIL_THRESHOLD = 2;
const PROXY_ERRORS = ["ETIMEDOUT", "ECONNRESET", "ECONNREFUSED", "TLS", "timeout", "SSL", "socket disconnect", "error sending request"];

function isProxyError(msg: string | null | undefined): boolean {
  if (!msg) return false;
  return PROXY_ERRORS.some((e) => msg.includes(e));
}

/** Registers+checks each key through a rotating pool of proxies (with blacklist). */
export async function runBruteforce(
  keys: string[],
  rawProxies: string[],
  opts: BruteforceOptions = {},
): Promise<string[]> {
  const proxies = rawProxies.map(parseProxy).filter((p): p is string => !!p);
  const concurrency = Math.min(Math.max(opts.concurrency ?? 20, 1), 200);
  const failCount = new Map<string, number>();

  const aliveProxies = () => proxies.filter((p) => (failCount.get(p) ?? 0) < PROXY_FAIL_THRESHOLD);
  const nextProxy = (): string | undefined => {
    if (!proxies.length) return undefined;
    const alive = aliveProxies();
    const pool = alive.length ? alive : proxies;
    return pool[Math.floor(Math.random() * pool.length)];
  };

  const total = keys.length;
  let checked = 0;
  let found = 0;
  const validKeys: string[] = [];
  const queue = [...keys];

  const worker = async () => {
    while (queue.length && !opts.signal?.aborted) {
      const key = queue.shift();
      if (!key) break;
      const proxy = nextProxy();
      const result = await checkWarpKey(key, proxy);
      checked++;

      if (proxy && isProxyError(result.error)) {
        failCount.set(proxy, (failCount.get(proxy) ?? 0) + 1);
      }
      const aliveCount = proxies.length ? aliveProxies().length : 0;

      if (result.valid) {
        found++;
        validKeys.push(key);
        opts.onEvent?.({ type: "valid", key, accountType: result.accountType, checked, total, found, aliveCount });
      } else {
        opts.onEvent?.({ type: "invalid", key, error: result.error, checked, total, found, aliveCount });
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, total || 1) }, worker));
  return validKeys;
}
