// Native DPI bypass for the WARP UDP handshake via zapret2's winws2 (Windows).
//
// Ported from the web app's zapret2 strategy: filter WARP UDP ports both ways,
// match the WireGuard L7 + payloads, and inject Lua "fake" desync packets with
// a tuned fake-TTL. winws2 uses the WinDivert kernel driver and therefore needs
// Administrator rights — we elevate just the winws2 process via UAC.
//
// The zapret2 binaries (winws2.exe + WinDivert.dll + WinDivert64.sys + two Lua
// scripts) are fetched on demand into the app-data dir the first time the user
// starts the bypass — nothing is bundled into the app or committed to git.

import { Command } from "@tauri-apps/plugin-shell";
import { appDataDir, join } from "@tauri-apps/api/path";
import { exists, mkdir, writeFile } from "@tauri-apps/plugin-fs";
import { httpFetch } from "./http";

const RAW = "https://raw.githubusercontent.com/bol-van/zapret-win-bundle/master/blockcheck/zapret2";
const FILES = [
  { url: `${RAW}/nfq2/winws2.exe`, name: "winws2.exe" },
  { url: `${RAW}/nfq2/WinDivert.dll`, name: "WinDivert.dll" },
  { url: `${RAW}/nfq2/WinDivert64.sys`, name: "WinDivert64.sys" },
  { url: `${RAW}/lua/zapret-lib.lua`, name: "lua/zapret-lib.lua" },
  { url: `${RAW}/lua/zapret-antidpi.lua`, name: "lua/zapret-antidpi.lua" },
];

/** Default WARP UDP ports the desync filter applies to. */
export const DEFAULT_WARP_PORTS = "2408,500,4500,1701,4443,8443,8095,443";

export type LineSink = (line: string) => void;

async function winwsDir(): Promise<string> {
  return join(await appDataDir(), "winws");
}

/** Downloads the zapret2 winws2 runtime into app-data on first use. */
export async function ensureZapret(onLine?: LineSink): Promise<string> {
  const base = await winwsDir();
  const winws = await join(base, "winws2.exe");
  if (await exists(winws)) return base;

  await mkdir(await join(base, "lua"), { recursive: true });
  for (const f of FILES) {
    onLine?.(`Загрузка ${f.name}…`);
    const res = await httpFetch(f.url, { connectTimeout: 30000 });
    if (!res.ok) throw new Error(`Не удалось скачать ${f.name} (HTTP ${res.status})`);
    await writeFile(await join(base, f.name), new Uint8Array(await res.arrayBuffer()));
  }
  onLine?.("Runtime zapret2 готов.");
  return base;
}

export interface WinwsProfile {
  ports?: string;
  fakeTtl?: number;
  quic?: boolean;
}

function psQuote(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

async function buildArgs(base: string, p: WinwsProfile): Promise<string[]> {
  const ports = p.ports?.trim() || DEFAULT_WARP_PORTS;
  const lib = await join(base, "lua/zapret-lib.lua");
  const anti = await join(base, "lua/zapret-antidpi.lua");
  const payload = p.quic
    ? "wireguard_initiation,wireguard_response,wireguard_cookie,wireguard_keepalive,wireguard_data,quic_initial"
    : "wireguard_initiation,wireguard_response,wireguard_cookie,wireguard_keepalive,wireguard_data";
  const args = [
    `--wf-udp-in=${ports}`,
    `--wf-udp-out=${ports}`,
    "--wf-l3=ipv4",
    "--filter-l7=wireguard",
    `--payload=${payload}`,
    `--lua-init=@${lib}`,
    `--lua-init=@${anti}`,
    "--lua-desync=fake:repeats=2",
  ];
  if (p.fakeTtl && p.fakeTtl > 0) args.push(`--fake-ttl=${p.fakeTtl}`);
  return args;
}

async function powershell(command: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const out = await Command.create("powershell", ["-NoProfile", "-NonInteractive", "-Command", command]).execute();
  return { code: out.code, stdout: out.stdout, stderr: out.stderr };
}

/** Starts winws2 elevated (UAC prompt) with the WARP desync profile. */
export async function startWinws(p: WinwsProfile = {}, onLine?: LineSink): Promise<void> {
  const base = await ensureZapret(onLine);
  const winws = await join(base, "winws2.exe");
  const args = await buildArgs(base, p);
  onLine?.(`winws2 ${args.join(" ")}`);
  const argList = args.map(psQuote).join(",");
  const ps = `Start-Process -FilePath ${psQuote(winws)} -ArgumentList ${argList} -Verb RunAs -WindowStyle Hidden`;
  const res = await powershell(ps);
  if (res.code !== 0) throw new Error(`Не удалось запустить winws2 (${res.stderr.trim() || res.code})`);
  onLine?.("winws2 запущен (elevated). DPI-обход активен, пока не нажмёте «Стоп».");
}

/** Stops the elevated winws2 process. */
export async function stopWinws(onLine?: LineSink): Promise<void> {
  await powershell("Start-Process taskkill -ArgumentList '/F','/IM','winws2.exe' -Verb RunAs -WindowStyle Hidden");
  onLine?.("winws2 остановлен.");
}

export async function winwsRunning(): Promise<boolean> {
  try {
    const res = await powershell("[bool](Get-Process winws2 -ErrorAction SilentlyContinue)");
    return /true/i.test(res.stdout);
  } catch {
    return false;
  }
}
