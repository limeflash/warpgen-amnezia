// Drives the bundled `warpscout` Go binary (a Tauri sidecar). warpscout does
// the actual userspace WireGuard/AmneziaWG/MASQUE handshakes to find working
// Cloudflare endpoints — something we can't do from the webview — and prints
// the best `ip:port` (or a full config) to stdout.

import { Command } from "@tauri-apps/plugin-shell";
import { appDataDir, join } from "@tauri-apps/api/path";
import { exists, mkdir } from "@tauri-apps/plugin-fs";

const SIDECAR = "binaries/warpscout";
const IP_PORT = /(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})/g;

export type Proto = "wg" | "awg" | "masque" | "masque-h2";
export type LineSink = (line: string, stream: "out" | "err") => void;

let cachedAccountPath: string | null = null;

async function accountPath(): Promise<string> {
  if (cachedAccountPath) return cachedAccountPath;
  const dir = await appDataDir();
  if (!(await exists(dir))) await mkdir(dir, { recursive: true });
  cachedAccountPath = await join(dir, "warpscout-account.json");
  return cachedAccountPath;
}

interface RunResult {
  code: number | null;
  stdout: string;
}

function runSidecar(args: string[], onLine?: LineSink, signal?: AbortSignal): Promise<RunResult> {
  const cmd = Command.sidecar(SIDECAR, args);
  let stdout = "";

  return new Promise<RunResult>((resolve, reject) => {
    cmd.stdout.on("data", (line: string) => {
      stdout += line + "\n";
      onLine?.(line, "out");
    });
    cmd.stderr.on("data", (line: string) => onLine?.(line, "err"));
    cmd.on("error", (err) => reject(new Error(String(err))));
    cmd.on("close", (data: { code: number | null }) => resolve({ code: data.code, stdout }));

    cmd
      .spawn()
      .then((child) => {
        if (!signal) return;
        if (signal.aborted) void child.kill();
        else signal.addEventListener("abort", () => void child.kill().catch(() => {}), { once: true });
      })
      .catch(reject);
  });
}

/** Returns the warpscout version string, or throws if the sidecar is missing. */
export async function warpscoutVersion(): Promise<string> {
  const { stdout } = await runSidecar(["version"]);
  return stdout.trim();
}

export async function isWarpscoutAvailable(): Promise<boolean> {
  try {
    await warpscoutVersion();
    return true;
  } catch {
    return false;
  }
}

/** Registers a WARP account into the app-data dir if one isn't there yet. */
async function ensureAccount(onLine?: LineSink): Promise<string> {
  const path = await accountPath();
  if (await exists(path)) return path;
  onLine?.("Регистрация WARP-аккаунта для warpscout…", "out");
  const { code } = await runSidecar(["register", "-a", path], onLine);
  if (code !== 0 && !(await exists(path))) {
    throw new Error("warpscout register failed");
  }
  return path;
}

function lastEndpoint(text: string): string | null {
  const matches = text.match(IP_PORT);
  return matches && matches.length ? matches[matches.length - 1] : null;
}

export interface ScanParams {
  proto?: Proto;
  country?: string;
  node?: string;
  excludeNode?: string;
  speed?: boolean;
  tunPing?: boolean;
  onLine?: LineSink;
  signal?: AbortSignal;
}

/** Scans and returns the single best `ip:port`. */
export async function scanBest(params: ScanParams = {}): Promise<{ endpoint: string; raw: string }> {
  const path = await ensureAccount(params.onLine);
  const args = ["scan", "-p", params.proto ?? "awg", "-best", "-no-report", "-plain", "-a", path];
  if (params.country) args.push("-country", params.country);
  if (params.node) args.push("-node", params.node);
  if (params.excludeNode) args.push("-exclude-node", params.excludeNode);
  if (params.speed) args.push("-speed"); // download-test each endpoint (SPEED column)
  if (params.tunPing) args.push("-P"); // TUN PING + LOSS columns

  const { stdout, code } = await runSidecar(args, params.onLine, params.signal);
  const endpoint = lastEndpoint(stdout);
  if (!endpoint) {
    throw new Error(code === 0 ? "warpscout не нашёл рабочий endpoint" : `warpscout scan завершился с кодом ${code}`);
  }
  return { endpoint, raw: stdout };
}

/** Scans and returns a ready-to-use config (`scan -best -conf -`). */
export async function importConfig(params: ScanParams = {}): Promise<{ config: string; endpoint: string | null }> {
  const path = await ensureAccount(params.onLine);
  const args = ["scan", "-p", params.proto ?? "awg", "-best", "-no-report", "-conf", "-", "-a", path];
  if (params.country) args.push("-country", params.country);
  if (params.node) args.push("-node", params.node);

  const { stdout, code } = await runSidecar(args, params.onLine, params.signal);
  const config = stdout.trim();
  if (!config.includes("[Interface]")) {
    throw new Error(code === 0 ? "warpscout не вернул конфиг" : `warpscout scan завершился с кодом ${code}`);
  }
  const endpointMatch = config.match(/Endpoint\s*=\s*(\S+)/);
  return { config, endpoint: endpointMatch ? endpointMatch[1] : null };
}

export interface FinderParams {
  proto?: Proto;
  genI1?: string;
  onLine?: LineSink;
  signal?: AbortSignal;
}

/** Searches for AmneziaWG junk/I1 settings that pass the current filter. */
export async function findJunk(params: FinderParams = {}): Promise<string> {
  const path = await ensureAccount(params.onLine);
  const args = ["find-junk", "-gen-i1", params.genI1 ?? "random", "-a", path];
  const { stdout } = await runSidecar(args, params.onLine, params.signal);
  return stdout.trim();
}

/** Searches for a MASQUE SNI that passes the current filter. */
export async function findSni(params: FinderParams = {}): Promise<string> {
  const path = await ensureAccount(params.onLine);
  const args = ["find-sni", "-a", path];
  if (params.proto) args.push("-p", params.proto);
  const { stdout } = await runSidecar(args, params.onLine, params.signal);
  return stdout.trim();
}
