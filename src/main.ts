import { generateConfig } from "./core/generate.ts";
import { I1_GROUPS, DEFAULT_I1_KEY } from "./core/i1.ts";
import { splitTargetList, catalogTargetGroups } from "./core/split.ts";
import { DNS_SERVERS } from "./core/dns.ts";
import { checkLicense, generateTestLicense, generateWarpKey } from "./core/license.ts";
import { runProxyCheck, runBruteforce } from "./core/proxy.ts";
import { httpFetch } from "./core/http.ts";
import * as ws from "./core/warpscout.ts";
import { qrDataUrl } from "./core/qr.ts";
import { clashFromNode, parseImportedConf, normalizeImportedConfig } from "./core/clash.ts";
import { clientList, downloadUrl, currentOs } from "./core/client-downloads.ts";
import * as winws from "./core/winws.ts";
import { loadJson, saveJson, addHistory, loadHistory, deleteHistory, clearHistory, updateHistoryTag } from "./core/store.ts";
import { generateSignature, MIMIC_PROFILES, type GeneratedSignature } from "./core/signature.ts";
import { PROTOCOL_INFO, calcChainSize, CPS_MAX_BYTES } from "./core/awg-meta.ts";
import { type AwgVersion } from "./core/obfuscation.ts";
import { analyzeConfig, type AnalysisResult } from "./core/analyzer.ts";
import { open as shellOpen } from "@tauri-apps/plugin-shell";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { downloadDir, join } from "@tauri-apps/api/path";
import {
  $, must, setText, show, esc, bindGroup, groupValue, setGroup, fillSelect, bindSelect, selectValue,
  setSelect, addSelectOption, bindToggle, toggleValue, onClick, inputValue, setInput,
  setBusy,
} from "./ui.ts";

type ConfigKind = "amnezia" | "wireguard" | "clash";

let lastConfigType: ConfigKind = "amnezia";
let lastConfig = "";
let architect: GeneratedSignature | null = null;

// ─────────────── window chrome ───────────────
// The window is frameless (decorations: false) so the design's own titlebar is
// the only one — its buttons and drag region have to be wired up here.
async function initWindowChrome(): Promise<void> {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  const win = getCurrentWindow();

  const bar = document.querySelector<HTMLElement>('[style*="flex: 0 0 46px"]');
  bar?.setAttribute("data-tauri-drag-region", "");

  const buttons = document.querySelectorAll<HTMLElement>('[style*="width: 30px"][style*="height: 26px"]');
  const actions: Array<() => Promise<void>> = [
    () => win.minimize(),
    () => win.toggleMaximize(),
    () => win.close(),
  ];
  buttons.forEach((b, i) => {
    const act = actions[i];
    if (act) b.addEventListener("click", () => void act());
  });
}

// ─────────────── theme ───────────────
function applyTheme(dark: boolean): void {
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  setText("themeLabel", dark ? "Тёмная тема" : "Светлая тема");
  saveJson("warpgen.theme", dark ? "dark" : "light");

  // The design draws the switch statically — move its knob to match the theme.
  const pill = $("themeToggle")?.querySelector<HTMLElement>('[style*="width: 38px"]');
  const knob = pill?.querySelector<HTMLElement>('[style*="width: 14px"]');
  if (pill) pill.style.background = dark ? "var(--accent)" : "var(--line-2)";
  if (knob) {
    knob.style.transition = "transform .2s";
    knob.style.transform = dark ? "translateX(19px)" : "translateX(0)";
  }
}

// ─────────────── views ───────────────
function showView(name: string): void {
  document.querySelectorAll<HTMLElement>(".view").forEach((v) => v.classList.toggle("active", v.dataset.view === name));
  document.querySelectorAll<HTMLElement>(".nav-item").forEach((n) => {
    const on = n.dataset.view === name;
    n.style.background = on ? "var(--sel)" : "transparent";
    n.style.color = on ? "var(--accent)" : "var(--text-2)";
  });
  document.querySelector<HTMLElement>('[style*="overflow: hidden auto"]')?.scrollTo({ top: 0 });
}

// ─────────────── dynamic containers the mockup only sketches ───────────────
function ensureBox(id: string, parent: HTMLElement, html = ""): HTMLElement {
  let el = $(id);
  if (!el) {
    el = document.createElement("div");
    el.id = id;
    el.innerHTML = html;
    parent.appendChild(el);
  }
  return el;
}

function screenEl(view: string): HTMLElement {
  return document.querySelector<HTMLElement>(`.view[data-view="${view}"]`)!;
}

/**
 * A couple of ids landed on wrappers rather than the control itself when the
 * design was captured; move them onto the right element before binding.
 */
function repairHooks(): void {
  // #wsSpeed sat on the row holding both toggles — take its first toggle child.
  const speed = $("wsSpeed");
  if (speed?.querySelector("[data-toggle]")) {
    const first = speed.firstElementChild as HTMLElement | null;
    speed.removeAttribute("id");
    delete speed.dataset.toggle;
    if (first) {
      first.id = "wsSpeed";
      first.dataset.toggle = "off";
    }
  }

  // The Architect protocol tiles lost their group during capture — rebind them
  // to the grid that actually holds "QUIC Initial".
  const gen = screenEl("generate");
  // Bind the tiles by their protocol caption — the design's grid holds an extra
  // cell, so positional binding lands one off.
  const BY_NAME: Record<string, string> = {
    "QUIC Initial": "quic_initial", "QUIC 0-RTT": "quic_0rtt", "TLS ClientHello": "tls_client_hello",
    "HTTP/3": "http3", "DTLS 1.3": "dtls", SIP: "sip", "DNS query": "dns_query",
    "WireGuard Noise": "wireguard_noise", "TLS → QUIC": "tls_to_quic", "QUIC burst": "quic_burst",
    "Случайный": "random",
  };
  for (const stale of gen.querySelectorAll<HTMLElement>('[data-group="archProfile"]')) {
    delete stale.dataset.group;
    delete stale.dataset.value;
  }
  const tiles: HTMLElement[] = [];
  for (const [name, value] of Object.entries(BY_NAME)) {
    const label = [...gen.querySelectorAll<HTMLElement>("*")].find(
      (e) => e.textContent?.trim() === name && e.children.length === 0,
    );
    // the tile is a near ancestor — walking further lands on the section wrapper
    let tile: HTMLElement | null = null;
    let n: HTMLElement | null = label ?? null;
    for (let i = 0; i < 3 && n; i++) {
      n = n.parentElement;
      const s = n?.getAttribute("style") ?? "";
      if (/cursor: pointer/.test(s) && /border-radius/.test(s)) {
        tile = n;
        break;
      }
    }
    if (!tile || tiles.includes(tile)) continue;
    tile.dataset.group = "archProfile";
    tile.dataset.value = value;
    tiles.push(tile);
  }
  const on = tiles.find((t) => /var\(--accent\)/.test(t.getAttribute("style") ?? ""));
  const off = tiles.find((t) => !/var\(--accent\)/.test(t.getAttribute("style") ?? ""));
  for (const t of tiles) {
    t.dataset.on = on?.getAttribute("style") ?? "";
    t.dataset.off = off?.getAttribute("style") ?? "";
  }

  // #historyList must be the rows container inside the history screen.
  const hist = screenEl("history");
  const header = [...hist.querySelectorAll<HTMLElement>("*")].find(
    (e) => e.textContent?.trim() === "ENDPOINT" && e.children.length === 0,
  );
  const rows = header?.parentElement?.parentElement;
  if (rows) {
    $("historyList")?.removeAttribute("id");
    rows.id = "historyList";
    rows.dataset.headerKeep = String([...rows.children].indexOf(header!.parentElement!));
  }
}

/** The design's card container around a control (panel background + radius). */
function cardOf(el: HTMLElement | null): HTMLElement | null {
  let n: HTMLElement | null = el;
  for (let i = 0; i < 8 && n; i++) {
    n = n.parentElement;
    const s = n?.getAttribute("style") ?? "";
    if (/background:\s*var\(--panel\)/.test(s) && /border-radius/.test(s)) return n;
  }
  return null;
}

// ─────────────── generator ───────────────
const DNS_LABELS: Record<string, string> = {
  malw_link: "dns.malw.link — разблокировка сайтов",
  cloudflare: "Cloudflare 1.1.1.1", cloudflare_mal: "Cloudflare 1.1.1.2 — малварь",
  google: "Google 8.8.8.8", adguard: "AdGuard — реклама и трекеры", adguard_family: "AdGuard Family",
  adguard_nofilter: "AdGuard — без фильтрации", yandex: "Яндекс 77.88.8.8", yandex_safe: "Яндекс Safe",
  yandex_family: "Яндекс Family", quad9: "Quad9 9.9.9.9", quad9_ecs: "Quad9 ECS",
  quad9_nofilter: "Quad9 — без фильтрации", opendns: "OpenDNS", opendns_family: "OpenDNS Family Shield",
  gcore: "G-Core", dnssb: "DNS.SB", dns0eu: "dns0.eu", nextdns: "NextDNS", mullvad: "Mullvad",
};

const ENDPOINTS: Array<{ value: string; label: string; group?: string }> = [
  { value: "auto", label: "Авто (из API Cloudflare)" },
  ...["162.159.193.1", "162.159.193.2", "162.159.193.5", "162.159.193.10"].map((v) => ({ value: v, label: v, group: "Официальный ingress" })),
  ...["162.159.192.1", "162.159.192.2", "162.159.192.5"].map((v) => ({ value: v, label: v, group: "Consumer WARP" })),
  ...["162.159.195.1", "162.159.195.4", "188.114.96.1", "188.114.98.1"].map((v) => ({ value: v, label: v, group: "Community" })),
];

function buildControls(): void {
  // The design captions DNS as "name · first IP" — keep that shape.
  fillSelect(
    "dnsServer",
    Object.entries(DNS_SERVERS).map(([k, servers]) => ({
      value: k,
      label: `${(DNS_LABELS[k] ?? k).split(" —")[0]} · ${servers.split(",")[0].trim()}`,
    })),
    "malw_link",
  );
  fillSelect("endpointIp", ENDPOINTS, "auto");
  fillSelect(
    "i1Preset",
    I1_GROUPS.flatMap((g) => g.options.map((o) => ({ value: o.key, label: o.label, group: g.label }))),
    DEFAULT_I1_KEY,
  );
  fillSelect("archBrowser", [
    { value: "", label: "не задавать" }, { value: "chrome", label: "Chrome" }, { value: "edge", label: "Edge" },
    { value: "firefox", label: "Firefox" }, { value: "safari", label: "Safari" }, { value: "yandex_desktop", label: "Яндекс" },
  ], "");
}

// Split-tunnel service picker — appended to the routing card when needed.
function buildSplitPicker(): void {
  const card = cardOf(document.querySelector<HTMLElement>(`[data-group="splitMode"]`));
  if (!card || $("splitBox")) return;

  const box = document.createElement("div");
  box.id = "splitBox";
  box.className = "hidden";
  box.style.cssText = "margin-top:14px";
  box.innerHTML =
    `<div style="display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:9px">` +
    `<div style="font-size:12.5px;font-weight:600">Сервисы</div><div style="font-size:11px;color:var(--text-3)" id="splitCount">выбрано 0</div></div>` +
    `<input id="catalogSearch" placeholder="Поиск сервиса…" style="width:100%;max-width:430px;padding:8px 12px;border-radius:9px;border:1px solid var(--line-2);background:var(--panel-2);color:var(--text);font-size:12.5px;outline:none" />` +
    `<div id="splitPresets" style="display:flex;gap:6px;flex-wrap:wrap;margin:9px 0"></div>` +
    `<div id="splitGrid" style="max-height:300px;overflow-y:auto;display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:6px"></div>`;
  card.appendChild(box);

  const presets: Array<[string, string[]]> = [
    ["Часто нужно", ["discord", "youtube", "x_com", "instagram", "twitch", "telegram", "whatsapp", "tiktok"]],
    ["Игры", ["steam", "faceit", "apex_legends", "ea_app", "battle_net", "cs2", "pubg"]],
    ["AI", ["cat:openai", "cat:anthropic", "cat:gemini", "cat:grok", "cat:copilot", "cat:perplexity"]],
    ["Очистить", []],
  ];
  const pbox = must("splitPresets");
  for (const [label, keys] of presets) {
    const b = document.createElement("div");
    b.textContent = label;
    b.style.cssText = "padding:5px 10px;border:1px solid var(--line-2);border-radius:8px;background:var(--panel-2);font-size:11.5px;color:var(--text-2);cursor:pointer";
    b.addEventListener("click", () => setSplit(keys));
    pbox.appendChild(b);
  }

  const grid = must("splitGrid");
  const add = (key: string, label: string) => {
    const row = document.createElement("label");
    row.dataset.name = label.toLowerCase();
    row.style.cssText = "display:flex;align-items:center;gap:8px;padding:7px 10px;border:1px solid var(--line);border-radius:9px;background:var(--panel-2);font-size:12px;cursor:pointer";
    row.innerHTML = `<input type="checkbox" data-split="${esc(key)}" style="accent-color:var(--accent)" /><span>${esc(label)}</span>`;
    grid.appendChild(row);
  };
  for (const t of splitTargetList()) add(t.key, t.label);
  for (const g of catalogTargetGroups()) for (const t of g.targets) add(t.key, t.label);
  grid.addEventListener("change", updateSplitCount);

  must("catalogSearch").addEventListener("input", (e) => {
    const q = (e.target as HTMLInputElement).value.trim().toLowerCase();
    grid.querySelectorAll<HTMLElement>("label").forEach((l) => {
      l.style.display = !q || (l.dataset.name ?? "").includes(q) ? "" : "none";
    });
  });
}

const splitBoxes = () => Array.from(document.querySelectorAll<HTMLInputElement>("input[data-split]"));
const selectedSplit = () => splitBoxes().filter((c) => c.checked).map((c) => c.dataset.split!);
function setSplit(keys: string[]): void {
  const set = new Set(keys);
  for (const c of splitBoxes()) c.checked = set.has(c.dataset.split!);
  updateSplitCount();
}
const updateSplitCount = () => setText("splitCount", `выбрано ${selectedSplit().length}`);

function updateVisibility(): void {
  const type = groupValue("configType");
  // Amnezia-only cards: obfuscation profile, I1 mask, Architect
  for (const group of ["obfsProfile", "archProfile", "archIntensity"]) {
    show(cardOf(document.querySelector<HTMLElement>(`[data-group="${group}"]`)), type === "amnezia");
  }
  show(cardOf($("i1Preset")), type === "amnezia");
  show($("splitBox"), groupValue("splitMode") === "selective");
  updateChainSize();
}

function updateChainSize(): void {
  if (!architect) return setText("chainSize", `0 / ${CPS_MAX_BYTES} Б`);
  const bytes = calcChainSize(architect.obfuscation);
  setText("chainSize", `${bytes} / ${CPS_MAX_BYTES} Б`);
  const el = $("chainSize");
  if (el) el.style.color = bytes < CPS_MAX_BYTES ? "var(--ok)" : "var(--err)";
}

function onArchGenerate(): void {
  architect = generateSignature("2.0", {
    profile: groupValue("archProfile") as (typeof MIMIC_PROFILES)[number],
    intensity: (groupValue("archIntensity") || "medium") as "low" | "medium" | "high",
    junkLevel: parseInt(inputValue("archJunk"), 10) || 5,
    customHost: inputValue("archHost").trim() || undefined,
    browserProfile: (selectValue("archBrowser") || "") as never,
    routerMode: toggleValue("archRouter"),
    mtu: 1280,
  });
  updateChainSize();
  const p = PROTOCOL_INFO[architect.profile]?.name ?? architect.profile;
  status("generate", `Обфускация собрана: ${p} · Jc ${architect.junk.jc} · цепочка ${calcChainSize(architect.obfuscation)} Б`);
}

/** The design's first card on a screen — dynamic content goes in its column. */
function hostCard(view: string): HTMLElement {
  const sec = screenEl(view);
  return sec.querySelector<HTMLElement>('[style*="background: var(--panel)"][style*="border-radius"]') ?? sec;
}

/** Places `el` right after the screen's card, inside the same padded column. */
function placeAfterCard(view: string, el: HTMLElement): void {
  const card = hostCard(view);
  const parent = card.parentElement ?? screenEl(view);
  if (el.parentElement !== parent) parent.insertBefore(el, card.nextSibling);
}

/** Status line under a screen's content. */
function status(view: string, text: string, kind: "info" | "err" | "ok" = "info"): void {
  const box = ensureBox(`status-${view}`, hostCard(view).parentElement ?? screenEl(view));
  placeAfterCard(view, box);
  box.style.cssText = "margin:12px 2px;font-size:12px;line-height:1.5";
  box.style.color = kind === "err" ? "var(--err)" : kind === "ok" ? "var(--ok)" : "var(--text-2)";
  box.innerHTML = text;
}

// ─────────────── generate ───────────────
function fileName(): string {
  const base = (inputValue("configName").trim() || "WARP").replace(/[^\w.-]+/g, "_");
  return lastConfigType === "clash" ? `${base}.yaml` : `${base}.conf`;
}

function setResult(config: string, type: ConfigKind, meta: string): void {
  lastConfig = config;
  lastConfigType = type;
  show($("resultEmpty"), false);

  const view = screenEl("result");
  const box = ensureBox("resultBox", view);
  box.style.cssText = "margin-bottom:14px";
  box.innerHTML =
    `<div style="background:var(--code-bg);border:1px solid var(--code-line);border-radius:14px;overflow:hidden">` +
    `<div style="display:flex;align-items:center;justify-content:space-between;padding:9px 14px;background:var(--code-head);border-bottom:1px solid var(--code-line);font-family:ui-monospace,monospace;font-size:11px;color:var(--code-dim)">` +
    `<span>${esc(fileName())}</span><span>${esc(meta)}</span></div>` +
    `<textarea id="configOutput" readonly spellcheck="false" style="width:100%;min-height:320px;border:0;background:transparent;color:var(--code-fg);font-family:ui-monospace,monospace;font-size:12px;line-height:1.6;padding:14px;outline:none;resize:vertical"></textarea></div>` +
    `<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">` +
    ["Скачать", "Копировать", "QR-код", "Анализировать"]
      .map((t, i) => `<div id="res${i}" style="padding:9px 15px;border-radius:9px;font-size:12.5px;font-weight:600;cursor:pointer;${i === 0 ? "background:var(--accent);color:var(--on-accent)" : "background:var(--panel-2);border:1px solid var(--line);color:var(--text)"}">${t}</div>`)
      .join("") +
    `</div><div id="qrWrap" class="hidden" style="text-align:center;margin-top:14px"><img id="qrImg" alt="QR" style="width:250px;height:250px;image-rendering:pixelated;background:#fff;border-radius:12px;padding:10px" /></div>`;
  (must("configOutput") as HTMLTextAreaElement).value = config;

  onClick("res0", () => void downloadConfig());
  onClick("res1", () => void copyText(config, "res1", "Скопировано", "Копировать"));
  onClick("res2", toggleQr);
  onClick("res3", () => {
    setInput("analyzerInput", lastConfig);
    showView("analyzer");
    onAnalyze();
  });
  showView("result");
}

async function onGenerate(): Promise<void> {
  setBusy("generateBtn", true, "Генерируем…");
  status("generate", "");
  try {
    const type = groupValue("configType") as ConfigKind;
    const result = await generateConfig({
      licenseKey: inputValue("licenseKey"),
      configType: type,
      obfsProfile: groupValue("obfsProfile") || "1",
      endpointPort: groupValue("endpointPort") || "2408",
      endpointIp: selectValue("endpointIp") || "auto",
      i1Preset: selectValue("i1Preset") || DEFAULT_I1_KEY,
      dnsServer: selectValue("dnsServer") || "malw_link",
      splitMode: groupValue("splitMode") === "selective" ? "selective" : "full",
      splitTargets: selectedSplit(),
      awgVersion: "1.5" as AwgVersion,
      ...(architect ? { customJunk: architect.junk, obfuscation: architect.obfuscation } : {}),
    });

    const plus = result.accountType === "warp_plus" || result.accountType === "unlimited";
    setText("accountBadge", plus ? "WARP+" : "Free");
    setText("accountNote", plus ? "Аккаунт WARP+" : "Бесплатный аккаунт Cloudflare");

    let meta = result.endpoint;
    if (result.splitTunnel.mode === "selective") meta += ` · ${result.splitTunnel.resolvedAllowedIps} маршрутов`;
    setResult(result.config, result.configType, meta);
    pushHistory(result.configType, result.endpoint, result.config);
    if (result.licenseError) status("result", `⚠ Ключ: ${esc(result.licenseError)}`, "err");
  } catch (err) {
    status("generate", `⚠ ${esc(err instanceof Error ? err.message : String(err))}`, "err");
  } finally {
    setBusy("generateBtn", false, undefined, "Сгенерировать конфиг");
  }
}

function resetDefaults(): void {
  setInput("licenseKey", "");
  setInput("configName", "");
  setGroup("configType", "amnezia");
  setGroup("obfsProfile", "1");
  setGroup("endpointPort", "2408");
  setGroup("splitMode", "full");
  setSelect("endpointIp", "auto");
  setSelect("dnsServer", "malw_link");
  setSelect("i1Preset", DEFAULT_I1_KEY);
  setSplit([]);
  architect = null;
  updateVisibility();
  status("generate", "");
}

async function downloadConfig(): Promise<void> {
  try {
    const path = await join(await downloadDir(), fileName());
    await writeTextFile(path, lastConfig);
    status("result", `Сохранено: ${esc(path)}`, "ok");
  } catch {
    const url = URL.createObjectURL(new Blob([lastConfig], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName();
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

async function copyText(text: string, id: string, done: string, normal: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    setText(id, done);
    setTimeout(() => setText(id, normal), 1800);
  } catch {
    setText(id, "Ошибка");
  }
}

function toggleQr(): void {
  const wrap = $("qrWrap");
  if (!wrap || !lastConfig) return;
  if (!wrap.classList.contains("hidden")) {
    show(wrap, false);
    return;
  }
  try {
    ($("qrImg") as HTMLImageElement).src = qrDataUrl(lastConfig);
    show(wrap, true);
  } catch {
    status("result", "Конфиг слишком большой для QR — используйте «Скачать».", "err");
  }
}

// ─────────────── warpscout ───────────────
let wsAbort: AbortController | null = null;

// ── scan progress card (design: title + percent + bar + three step chips) ──
type ScanStep = "ports" | "tunnels" | "speed";
const STEP_INFO: Array<[ScanStep, string, string]> = [
  ["ports", "Порты", "reachable"],
  ["tunnels", "Туннели", "handshake"],
  ["speed", "Скорость", "download"],
];

function scanProgress(title: string, percent: number, active: ScanStep | null, note?: Partial<Record<ScanStep, string>>): void {
  const box = ensureBox("wsProgress", hostCard("scan").parentElement ?? screenEl("scan"));
  placeAfterCard("scan", box);
  box.style.cssText = "background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:16px 18px;margin-bottom:14px";
  const done = (s: ScanStep) => STEP_INFO.findIndex(([k]) => k === s) < STEP_INFO.findIndex(([k]) => k === active);
  box.innerHTML =
    `<div style="display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:10px">` +
    `<b style="font-size:13px">${esc(title)}</b>` +
    `<span style="font-size:11.5px;color:var(--text-3);font-family:ui-monospace,monospace">${percent}%</span></div>` +
    `<div style="height:7px;border-radius:99px;background:var(--panel-3);overflow:hidden;margin-bottom:12px">` +
    `<div style="height:100%;width:${percent}%;border-radius:99px;background:var(--accent);transition:width .3s"></div></div>` +
    `<div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px">` +
    STEP_INFO.map(([key, label, sub]) => {
      const on = key === active || done(key);
      return `<div style="padding:9px 12px;border-radius:11px;border:1px solid ${on ? "var(--accent)" : "var(--line)"};background:${on ? "var(--sel)" : "var(--panel-2)"}">` +
        `<div style="font-size:12.5px;font-weight:600;color:${on ? "var(--accent)" : "var(--text-3)"}">${esc(label)}</div>` +
        `<div style="font-size:10.5px;color:var(--text-3);margin-top:1px">${esc(note?.[key] ?? sub)}</div></div>`;
    }).join("") +
    `</div>`;
}

function wsStatus(text: string, spin = false): void {
  status("scan", spin ? `<span class="spinner"></span> ${esc(text)}` : esc(text));
}

/** Country code → Russian name, as the design spells them out. */
const COUNTRY: Record<string, string> = {
  NL: "Нидерланды", DE: "Германия", FI: "Финляндия", SE: "Швеция", PL: "Польша", FR: "Франция",
  GB: "Великобритания", US: "США", TR: "Турция", LV: "Латвия", LT: "Литва", EE: "Эстония",
  RU: "Россия", UA: "Украина", CZ: "Чехия", AT: "Австрия", CH: "Швейцария", ES: "Испания",
  IT: "Италия", NO: "Норвегия", DK: "Дания", IE: "Ирландия", BE: "Бельгия", CA: "Канада",
  JP: "Япония", SG: "Сингапур", HK: "Гонконг", AE: "ОАЭ", IL: "Израиль", KZ: "Казахстан",
};

function applyEndpoint(endpoint: string): void {
  const m = endpoint.match(/^(.+):(\d+)$/);
  if (!m) return;
  addSelectOption("endpointIp", m[1], `${m[1]} — warpscout`);
  setGroup("endpointPort", m[2]);
}

/** find-junk result card: the measured junk parameters, as the design shows them. */
function renderJunkResult(
  junk: { jc: number; jmin: number; jmax: number },
  handshakeMs?: string,
  packets?: string,
  attempts?: string,
): void {
  const box = ensureBox("wsJunkResult", hostCard("scan").parentElement ?? screenEl("scan"));
  placeAfterCard("scan", box);
  box.style.cssText = "background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:16px 18px;margin-bottom:14px";
  const tile = (label: string, value: string) =>
    `<div style="padding:11px 14px;border:1px solid var(--line);border-radius:12px;background:var(--panel-2)">` +
    `<div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-3)">${esc(label)}</div>` +
    `<div style="font-size:15px;font-weight:650;margin-top:2px">${esc(value)}</div></div>`;

  box.innerHTML =
    `<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px">` +
    `<b style="font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-3)">find-junk · параметры обфускации</b>` +
    `<span style="display:flex;align-items:center;gap:7px;font-size:11.5px;color:var(--text-2)">` +
    `<i style="width:6px;height:6px;border-radius:99px;background:var(--ok)"></i>подставлено в Architect</span></div>` +
    `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:9px">` +
    tile("Jc", String(junk.jc)) + tile("Jmin", String(junk.jmin)) + tile("Jmax", String(junk.jmax)) +
    tile("Handshake", handshakeMs ? `${handshakeMs} ms` : "—") +
    `</div>` +
    `<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:14px;padding-top:13px;border-top:1px solid var(--line)">` +
    `<span style="font-size:11.5px;color:var(--text-3)">Профиль обфускации переключён на Custom${packets ? ` · ${packets} пакетов` : ""}${attempts ? `, ${attempts} попытки` : ""}</span>` +
    `<div id="openArchitect" style="padding:9px 15px;border-radius:9px;background:var(--accent);color:var(--on-accent);font-size:12.5px;font-weight:600;cursor:pointer">Открыть в Architect →</div></div>`;

  onClick("openArchitect", () => {
    showView("generate");
    document.querySelector('[data-group="archProfile"]')?.scrollIntoView({ behavior: "smooth", block: "center" });
  });
}

function renderScanRows(rows: ws.ScanRow[]): void {
  const box = ensureBox("wsResults", hostCard("scan").parentElement ?? screenEl("scan"));
  const cols = "minmax(0,1.5fr) 76px minmax(0,1fr) 70px minmax(0,1fr)";
  box.style.cssText = "background:var(--panel);border:1px solid var(--line);border-radius:15px;overflow:hidden;margin-bottom:14px";
  box.innerHTML =
    `<div style="display:flex;align-items:baseline;justify-content:space-between;gap:12px;padding:14px 18px 12px">` +
    `<b style="font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-3)">Результаты</b>` +
    `<span style="font-size:11px;color:var(--text-3)">клик по строке — подставить endpoint в генератор</span></div>` +
    `<div style="display:grid;grid-template-columns:${cols};gap:12px;padding:9px 18px;background:var(--panel-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line);font-size:10.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--text-3)">` +
    `<span>Endpoint</span><span>Ping</span><span>Страна</span><span>Нода</span><span>Локация</span></div>` +
    `<div id="wsRows" style="max-height:340px;overflow-y:auto"></div>`;

  const list = must("wsRows");
  const rowStyle = (sel: boolean) =>
    `display:grid;grid-template-columns:${cols};gap:12px;align-items:center;padding:11px 18px;border-bottom:1px solid var(--line);font-size:12.5px;cursor:pointer;background:${sel ? "var(--sel)" : "transparent"}`;

  rows.forEach((r, i) => {
    const tier = r.ping < 30 ? "var(--ok)" : r.ping < 70 ? "var(--accent)" : "var(--warn)";
    const row = document.createElement("div");
    row.style.cssText = rowStyle(i === 0);
    row.innerHTML =
      `<span style="display:flex;align-items:center;gap:8px;min-width:0">` +
      `<i style="width:6px;height:6px;border-radius:99px;background:${tier};flex:0 0 6px"></i>` +
      `<span style="font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis">${esc(r.endpoint)}</span></span>` +
      `<span style="font-family:ui-monospace,monospace;font-weight:600;color:${r.ping < 70 ? "var(--ok)" : "var(--text)"}">${r.ping} ms</span>` +
      `<span>${esc(COUNTRY[r.country] ?? r.country)}</span>` +
      `<span style="font-family:ui-monospace,monospace;font-size:11.5px;color:var(--text-2)">${esc(r.node)}</span>` +
      `<span style="color:var(--text-3);overflow:hidden;text-overflow:ellipsis">${esc(r.location.split(",")[0])}</span>`;
    row.addEventListener("click", () => {
      [...list.children].forEach((d, j) => ((d as HTMLElement).style.cssText = rowStyle(false) + (j === rows.length - 1 ? ";border-bottom:0" : "")));
      row.style.cssText = rowStyle(true);
      applyEndpoint(r.endpoint);
    });
    list.appendChild(row);
  });
  (list.lastElementChild as HTMLElement | null)?.style.setProperty("border-bottom", "0");
  placeAfterCard("scan", box);
}

const wsFilters = () => {
  const f = inputValue("wsFilter").trim();
  if (!f) return {};
  return /^[A-Za-z]{2}(,[A-Za-z]{2})*$/.test(f) ? { country: f.toUpperCase() } : { node: f.toUpperCase() };
};

async function onScan(): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  $("wsResults")?.remove();
  status("scan", "");
  scanProgress("Проверка доступных портов…", 8, "ports");
  const note: Partial<Record<ScanStep, string>> = {};
  try {
    const { rows } = await ws.scanEndpoints({
      proto: (groupValue("wsProto") || "awg") as ws.Proto,
      ...wsFilters(),
      speed: toggleValue("wsSpeed"),
      tunPing: toggleValue("wsTunPing"),
      onLine: (l) => {
        const ports = l.match(/reachable ports \[([^\]]+)\]/)?.[1];
        if (ports) note.ports = `${ports.trim().split(/\s+/).length} порта`;
        const n = l.match(/(\d+)\s*\.\.\./)?.[1];
        if (/probing reachable|reachable ports/i.test(l)) scanProgress("Проверка доступных портов…", 20, "ports", note);
        else if (/verifying tunnels/i.test(l)) {
          if (n) note.tunnels = `${n} проверено`;
          scanProgress("Проверка туннелей…", 66, "tunnels", note);
        } else if (/speedtest|measuring/i.test(l)) {
          if (n) note.speed = `${n} замерено`;
          scanProgress("Замер скорости…", 85, "speed", note);
        }
      },
      signal: wsAbort.signal,
    });
    if (!rows.length) {
      scanProgress("Рабочих endpoint'ов не найдено", 100, null, note);
      return;
    }
    scanProgress(`Найдено ${rows.length} рабочих endpoint · быстрейший подставлен в генератор`, 100, null, note);
    renderScanRows(rows);
    applyEndpoint(rows[0].endpoint);
  } catch (err) {
    $("wsProgress")?.remove();
    wsStatus(wsAbort?.signal.aborted ? "Остановлено." : `⚠ ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    wsAbort = null;
  }
}

async function wsRun(kind: "import" | "junk" | "sni"): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  wsStatus(kind === "import" ? "Импорт конфига…" : kind === "junk" ? "Подбор junk-параметров…" : "Поиск SNI…", true);
  const proto = (groupValue("wsProto") || "awg") as ws.Proto;
  try {
    if (kind === "import") {
      const { config, endpoint } = await ws.importConfig({ proto, ...wsFilters(), signal: wsAbort.signal });
      setResult(config, proto === "wg" ? "wireguard" : "amnezia", `warpscout${endpoint ? ` · ${endpoint}` : ""}`);
      pushHistory(lastConfigType, endpoint ?? "", config);
    } else if (kind === "junk") {
      const out = await ws.findJunk({ proto, signal: wsAbort.signal });
      const m = out.match(/jc\s*=?\s*(\d+).*?jmin\s*=?\s*(\d+).*?jmax\s*=?\s*(\d+)/is);
      if (m) {
        architect = { junk: { jc: +m[1], jmin: +m[2], jmax: +m[3] }, profile: architect?.profile ?? "quic_initial", obfuscation: architect?.obfuscation ?? {} };
        renderJunkResult(
          { jc: +m[1], jmin: +m[2], jmax: +m[3] },
          out.match(/(\d+(?:\.\d+)?)\s*ms/i)?.[1],
          out.match(/(\d+)\s*(?:packets|пакет)/i)?.[1],
          out.match(/(\d+)\s*(?:attempts?|попыт)/i)?.[1],
        );
        status("scan", "");
      } else wsStatus("find-junk завершён.");
    } else {
      const out = await ws.findSni({ proto, signal: wsAbort.signal });
      const host = out.match(/\b([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b/i)?.[1];
      if (host) {
        setInput("archHost", host);
        wsStatus(`find-sni: ${host} — подставлен в Architect.`);
      } else wsStatus("find-sni завершён.");
    }
  } catch (err) {
    wsStatus(wsAbort?.signal.aborted ? "Остановлено." : `⚠ ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    wsAbort = null;
  }
}

// ─────────────── DPI ───────────────
async function dpiStart(): Promise<void> {
  setText("dpiState", "Запуск…");
  status("dpi", "Подтвердите UAC…");
  try {
    await winws.startWinws(
      { ports: inputValue("dpiPorts"), fakeTtl: parseInt(inputValue("dpiTtl"), 10) || 0, quic: toggleValue("dpiQuic") },
      (l) => status("dpi", esc(l)),
    );
    setText("dpiState", "Работает");
    status("dpi", "DPI-обход активен.", "ok");
  } catch (err) {
    setText("dpiState", "Выключен");
    status("dpi", `⚠ ${esc(err instanceof Error ? err.message : String(err))}`, "err");
  }
}

// ─────────────── import ───────────────
async function onImport(toClash: boolean): Promise<void> {
  const input = inputValue("importInput").trim();
  if (!input) return;
  try {
    const raw = await normalizeImportedConfig(input);
    const output = toClash ? clashFromNode(parseImportedConf(raw)) : raw;
    const type: ConfigKind = toClash ? "clash" : /(\bJc\s*=|\bI1\s*=)/.test(raw) ? "amnezia" : "wireguard";
    setResult(output, type, toClash ? "импорт → Clash" : "импорт");
    pushHistory(type, "", output);
  } catch (err) {
    status("import", `⚠ ${esc(err instanceof Error ? err.message : String(err))}`, "err");
  }
}

// ─────────────── history ───────────────
function renderHistory(): void {
  const list = loadHistory();
  setText("historyCount", String(list.length));
  const box = $("historyList");
  if (!box) return;
  // keep the design's header row, drop the rest (mock rows / previous render)
  for (const row of [...box.children]) {
    if (!row.textContent?.includes("ENDPOINT")) row.remove();
  }
  if (!list.length) {
    box.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text-3);font-size:12.5px">История пуста</div>`;
    return;
  }
  for (const e of list) {
    const d = new Date(e.ts);
    const date = `${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")} · ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    const row = document.createElement("div");
    row.style.cssText = "display:grid;grid-template-columns:120px 1fr 110px 100px auto;gap:12px;align-items:center;padding:11px 15px;border-bottom:1px solid var(--line);font-size:12.5px";
    row.innerHTML =
      `<b>${esc(e.configType === "clash" ? "Clash" : e.configType === "wireguard" ? "WireGuard" : "AmneziaWG")}</b>` +
      `<span style="font-family:ui-monospace,monospace;color:var(--text-3)">${esc(e.endpoint || "—")}</span>` +
      `<span style="color:var(--text-3)">${esc(date)}</span>`;
    const tag = document.createElement("input");
    tag.value = e.tag;
    tag.placeholder = "тег";
    tag.style.cssText = "padding:5px 8px;font-size:11.5px;border:1px solid var(--line);border-radius:7px;background:var(--panel-2);color:var(--text);outline:none";
    tag.addEventListener("change", () => updateHistoryTag(e.id, tag.value));
    const acts = document.createElement("div");
    acts.style.cssText = "display:flex;gap:6px";
    for (const [label, fn] of [
      ["Открыть", () => setResult(e.config, e.configType as ConfigKind, "из истории")],
      ["✕", () => { deleteHistory(e.id); renderHistory(); }],
    ] as Array<[string, () => void]>) {
      const b = document.createElement("div");
      b.textContent = label;
      b.style.cssText = "padding:5px 10px;border:1px solid var(--line);border-radius:8px;background:var(--panel-2);font-size:11.5px;cursor:pointer";
      b.addEventListener("click", fn);
      acts.appendChild(b);
    }
    row.append(tag, acts);
    box.appendChild(row);
  }
}

function pushHistory(configType: string, endpoint: string, config: string): void {
  addHistory({ configType, endpoint, config });
  renderHistory();
}

// ─────────────── analyzer ───────────────
const AWG_SCALE = ["WireGuard", "1.0", "1.5", "2.0", "3.0"];

/** Analyzer report — the design's right-hand column. */
function renderAnalysis(a: AnalysisResult): void {
  const box = must("analyzerReport");
  box.removeAttribute("style");
  const camoColor = a.camouflage === "HIGH" ? "var(--ok)" : a.camouflage === "MEDIUM" ? "var(--warn)" : "var(--err)";
  const verKey = a.version.ver === "WireGuard" ? "WireGuard" : a.version.ver.replace("AWG ", "");
  const chain = ["i1", "i2", "i3", "i4", "i5"].map((k) => a.parsed.iface[k]).filter(Boolean);
  const counts = {
    fail: a.checks.filter((c) => c.status === "fail").length,
    warn: a.checks.filter((c) => c.status === "warn").length,
    pass: a.checks.filter((c) => c.status === "pass").length,
  };

  // circular gauge
  const R = 34, C = 2 * Math.PI * R;
  const gauge =
    `<svg width="86" height="86" viewBox="0 0 86 86" style="flex:0 0 86px">` +
    `<circle cx="43" cy="43" r="${R}" fill="none" stroke="var(--hero-line)" stroke-width="7"/>` +
    `<circle cx="43" cy="43" r="${R}" fill="none" stroke="${camoColor}" stroke-width="7" stroke-linecap="round"` +
    ` stroke-dasharray="${(a.scores.total / 100) * C} ${C}" transform="rotate(-90 43 43)"/>` +
    `<text x="43" y="41" text-anchor="middle" fill="var(--on-hero)" font-size="21" font-weight="700">${a.scores.total}</text>` +
    `<text x="43" y="55" text-anchor="middle" fill="${camoColor}" font-size="8.5" font-weight="700" letter-spacing="1">${a.camouflage}</text></svg>`;

  const scale = AWG_SCALE.map((s) => {
    const on = s === verKey;
    return `<div style="flex:1"><div style="height:3px;border-radius:99px;background:${on ? "var(--on-hero)" : "var(--hero-line)"}"></div>` +
      `<div style="font-size:9.5px;margin-top:5px;text-align:center;color:${on ? "var(--on-hero)" : "rgba(243,246,255,.45)"}">${esc(s)}</div></div>`;
  }).join("");

  const metric = (label: string, value: number) =>
    `<div style="flex:1;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:13px 15px">` +
    `<div style="display:flex;justify-content:space-between;align-items:baseline"><span style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-3)">${esc(label)}</span>` +
    `<b style="font-size:12.5px;color:var(--accent)">${value}%</b></div>` +
    `<div style="height:4px;border-radius:99px;background:var(--panel-3);margin-top:9px;overflow:hidden"><div style="height:100%;width:${value}%;background:var(--accent);border-radius:99px"></div></div></div>`;

  const card = (title: string, right: string, inner: string) =>
    `<div style="background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:13px 15px;margin-bottom:11px">` +
    `<div style="display:flex;justify-content:space-between;align-items:baseline;gap:10px;margin-bottom:9px">` +
    `<span style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-3)">${esc(title)}</span>` +
    `<span style="font-size:10.5px;color:var(--text-3)">${right}</span></div>${inner}</div>`;

  const badge = (n: number, label: string, color: string) =>
    `<span style="display:inline-flex;align-items:center;gap:5px;font-size:10.5px;color:var(--text-2)">` +
    `<i style="width:5px;height:5px;border-radius:99px;background:${color}"></i>${n} ${esc(label)}</span>`;

  const marks: Record<string, [string, string]> = {
    pass: ["✓", "var(--ok)"], warn: ["!", "var(--warn)"], fail: ["✕", "var(--err)"], info: ["·", "var(--text-3)"],
  };

  box.innerHTML =
    `<div style="background:var(--hero-bg);border-radius:16px;padding:18px;margin-bottom:11px;color:var(--on-hero)">` +
    `<div style="display:flex;gap:16px;align-items:center">${gauge}` +
    `<div style="min-width:0"><div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:rgba(243,246,255,.5)">Профиль</div>` +
    `<div style="font-size:22px;font-weight:700;letter-spacing:-.02em;margin:1px 0 5px">${esc(a.version.ver)}</div>` +
    `<div style="font-size:11.5px;line-height:1.45;color:rgba(243,246,255,.68)">${esc(a.version.desc)}</div></div></div>` +
    `<div style="display:flex;gap:6px;margin-top:16px">${scale}</div></div>` +
    `<div style="display:flex;gap:11px;margin-bottom:11px">${metric("DPI-стойкость", 100 - a.scores.dpi)}${metric("Stealth", a.scores.stealth)}</div>` +
    card("Мимикрия I1", "", `<b style="font-size:14px">${esc(a.version.protocol ?? "—")}</b>`) +
    card(
      "Цепочка CPS",
      `${chain.length} тег(ов) · порядок важен`,
      chain.length
        ? chain.map((c) => `<div style="display:flex;align-items:center;gap:8px;padding:8px 11px;border:1px solid var(--line);border-radius:9px;background:var(--panel-2);margin-bottom:6px">` +
            `<i style="width:5px;height:5px;border-radius:99px;background:var(--ok);flex:0 0 5px"></i>` +
            `<span style="font-family:ui-monospace,monospace;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c)}</span></div>`).join("")
        : `<span style="font-size:12px;color:var(--text-3)">I1 не задан</span>`,
    ) +
    card(
      "Проверки",
      `${badge(counts.fail, "ошибок", "var(--err)")} &nbsp; ${badge(counts.warn, "предупр.", "var(--warn)")} &nbsp; ${badge(counts.pass, "ок", "var(--ok)")}`,
      a.checks
        .map((c) => {
          const [m, col] = marks[c.status];
          return `<div style="display:grid;grid-template-columns:20px 1fr;gap:9px;padding:9px 11px;border:1px solid var(--line);border-radius:10px;background:var(--panel-2);margin-bottom:6px">` +
            `<span style="color:${col};font-weight:700">${m}</span>` +
            `<span><b style="font-size:12.5px">${esc(c.title)}</b>` +
            `<div style="font-size:11px;color:var(--text-3);line-height:1.45;margin-top:2px">${esc(c.detail)}</div></span></div>`;
        })
        .join(""),
    ) +
    (a.hints.length
      ? card("Как усилить", "", a.hints.map((h) => `<div style="font-size:11.5px;color:var(--text-2);padding:5px 0">→ ${esc(h)}</div>`).join(""))
      : "");

  // header subtitle mirrors the verdict, as in the design
  const sub = [...screenEl("analyzer").querySelectorAll<HTMLElement>("*")].find(
    (e) => e.children.length === 0 && /вставьте \.conf|AWG|маскировка/.test(e.textContent ?? ""),
  );
  if (sub) sub.textContent = `${a.version.ver} · маскировка ${a.camouflage}`;
}

function onAnalyze(): void {
  const raw = inputValue("analyzerInput").trim();
  if (!raw) return status("analyzer", "Вставьте конфиг.", "err");
  try {
    renderAnalysis(analyzeConfig(raw));
    status("analyzer", "");
  } catch (err) {
    status("analyzer", `⚠ ${esc(err instanceof Error ? err.message : String(err))}`, "err");
  }
}

// ─────────────── tools ───────────────
async function onCheckKey(): Promise<void> {
  const key = inputValue("secretKey").trim();
  if (!key) return status("tools", "Введите ключ.", "err");
  setBusy("checkKeyBtn", true, "Проверяем…");
  try {
    const r = await checkLicense(key);
    status("tools", `${r.valid ? "✓ валидный" : "✕ невалидный"} · ${esc(r.accountType)} · ${esc(r.message)}`, r.valid ? "ok" : "err");
  } catch (err) {
    status("tools", `⚠ ${esc(err instanceof Error ? err.message : String(err))}`, "err");
  } finally {
    setBusy("checkKeyBtn", false, undefined, "Проверить ключ");
  }
}

const PROXY_SOURCES: Record<string, { url: string; prefix: string }> = {
  pxsrc0: { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", prefix: "" },
  pxsrc1: { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", prefix: "socks5://" },
  pxsrc2: { url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", prefix: "socks4://" },
};

async function loadProxies(key: string): Promise<void> {
  const keys = key === "pxsrc3" ? Object.keys(PROXY_SOURCES) : [key];
  status("tools", "Загружаем прокси…");
  const all: string[] = [];
  for (const k of keys) {
    const src = PROXY_SOURCES[k];
    if (!src) continue;
    try {
      const res = await httpFetch(src.url, { method: "GET", connectTimeout: 12000 });
      if (!res.ok) continue;
      all.push(
        ...(await res.text()).trim().split("\n").map((l) => l.trim())
          .filter((l) => /^\d+\.\d+\.\d+\.\d+:\d+/.test(l.replace(/^socks[45]:\/\//, "")))
          .map((l) => (src.prefix && !l.startsWith("socks") ? src.prefix + l : l)),
      );
    } catch { /* skip source */ }
  }
  const uniq = [...new Set(all)];
  setInput("bfProxies", uniq.join("\n"));
  status("tools", `Загружено ${uniq.length} прокси.`);
}

let proxyAbort: AbortController | null = null;
async function onCheckProxies(): Promise<void> {
  const proxies = inputValue("bfProxies").trim().split("\n").map((l) => l.trim()).filter(Boolean);
  if (!proxies.length) return;
  proxyAbort = new AbortController();
  const valid = await runProxyCheck(proxies, {
    concurrency: 200,
    signal: proxyAbort.signal,
    onProgress: ({ checked, valid, total }) => status("tools", `Проверено ${checked}/${total} · рабочих ${valid}`),
  });
  setInput("bfProxies", valid.join("\n"));
  status("tools", `Готово: ${valid.length} рабочих прокси.`, "ok");
  proxyAbort = null;
}

let bfAbort: AbortController | null = null;
async function onBruteforce(): Promise<void> {
  const count = Math.min(Math.max(parseInt(inputValue("bfCount"), 10) || 100, 1), 10000);
  const keys = Array.from({ length: count }, generateWarpKey);
  const proxies = inputValue("bfProxies").trim().split("\n").map((l) => l.trim()).filter(Boolean);
  bfAbort = new AbortController();
  setBusy("bfStartBtn", true, "Проверяем…");
  const found: string[] = [];
  await runBruteforce(keys, proxies, {
    concurrency: parseInt(inputValue("bfThreads"), 10) || 30,
    signal: bfAbort.signal,
    onEvent: (e) => {
      if (e.type === "valid") found.push(e.key);
      status("tools", `Проверено ${e.checked}/${e.total} · найдено ${e.found}${found.length ? `<br><b style="color:var(--ok)">${found.map(esc).join("<br>")}</b>` : ""}`);
    },
  });
  setBusy("bfStartBtn", false, undefined, "Сгенерировать и проверить");
  bfAbort = null;
}

// ─────────────── settings ───────────────
const SETTINGS_KEY = "warpgen.settings";
function saveSettings(): void {
  saveJson(SETTINGS_KEY, {
    configType: groupValue("configType"), obfsProfile: groupValue("obfsProfile"),
    endpointPort: groupValue("endpointPort"), splitMode: groupValue("splitMode"),
    archProfile: groupValue("archProfile"), archIntensity: groupValue("archIntensity"),
    endpointIp: selectValue("endpointIp"), dnsServer: selectValue("dnsServer"),
    i1Preset: selectValue("i1Preset"), archBrowser: selectValue("archBrowser"),
    configName: inputValue("configName"), archHost: inputValue("archHost"),
    splitTargets: selectedSplit(),
  });
}

function loadSettings(): void {
  const s = loadJson<Record<string, unknown>>(SETTINGS_KEY, {});
  for (const g of ["configType", "obfsProfile", "endpointPort", "splitMode", "archProfile", "archIntensity"]) {
    if (typeof s[g] === "string") setGroup(g, s[g] as string);
  }
  for (const id of ["endpointIp", "dnsServer", "i1Preset", "archBrowser"]) {
    if (typeof s[id] === "string") setSelect(id, s[id] as string);
  }
  if (typeof s.configName === "string") setInput("configName", s.configName);
  if (typeof s.archHost === "string") setInput("archHost", s.archHost);
  if (Array.isArray(s.splitTargets)) setSplit(s.splitTargets as string[]);
}

// ─────────────── init ───────────────
function init(): void {
  repairHooks();
  buildControls();
  buildSplitPicker();

  applyTheme(loadJson<string>("warpgen.theme", "dark") === "dark");
  setText("siteVersion", `v${__APP_VERSION__}`);
  setText("platformChip", currentOs() === "windows" ? "Windows" : currentOs() === "macos" ? "macOS" : "Linux");

  for (const g of ["configType", "obfsProfile", "endpointPort", "splitMode", "archProfile", "archIntensity", "wsProto"]) {
    bindGroup(g, () => {
      updateVisibility();
      saveSettings();
    });
  }
  for (const s of ["endpointIp", "dnsServer", "i1Preset", "archBrowser"]) bindSelect(s, saveSettings);
  for (const t of ["archRouter", "wsSpeed", "wsTunPing", "dpiQuic"]) bindToggle(t);

  document.querySelectorAll<HTMLElement>(".nav-item").forEach((n) =>
    n.addEventListener("click", () => showView(n.dataset.view!)),
  );
  onClick("themeToggle", () => applyTheme(document.documentElement.dataset.theme !== "dark"));

  onClick("generateBtn", () => void onGenerate());
  onClick("resetBtn", resetDefaults);
  onClick("archGenBtn", onArchGenerate);
  onClick("genJunkBtn", () => void wsRun("junk"));
  onClick("genSniBtn", () => void wsRun("sni"));

  onClick("wsScanBtn", () => void onScan());
  onClick("wsImportBtn", () => void wsRun("import"));
  onClick("wsJunkBtn", () => void wsRun("junk"));
  onClick("wsSniBtn", () => void wsRun("sni"));
  onClick("wsStopBtn", () => wsAbort?.abort());

  onClick("dpiStartBtn", () => void dpiStart());
  onClick("dpiStopBtn", async () => {
    await winws.stopWinws().catch(() => {});
    setText("dpiState", "Выключен");
  });

  onClick("importClashBtn", () => void onImport(true));
  onClick("importRawBtn", () => void onImport(false));
  onClick("analyzerBtn", onAnalyze);
  onClick("analyzerFromResult", () => {
    setInput("analyzerInput", lastConfig);
    onAnalyze();
  });

  onClick("goGenerate", () => showView("generate"));
  onClick("goImport", () => showView("import"));
  onClick("goHistory", () => showView("history"));

  onClick("checkKeyBtn", () => void onCheckKey());
  onClick("genTestBtn", async () => {
    try {
      const r = await generateTestLicense();
      setInput("secretKey", r.license);
      await onCheckKey();
    } catch (err) {
      status("tools", `⚠ ${esc(err instanceof Error ? err.message : String(err))}`, "err");
    }
  });
  onClick("proxyCheckBtn", () => void onCheckProxies());
  onClick("proxyClearBtn", () => setInput("bfProxies", ""));
  onClick("bfStartBtn", () => void onBruteforce());
  onClick("bfStopBtn", () => bfAbort?.abort());
  for (const id of ["pxsrc0", "pxsrc1", "pxsrc2", "pxsrc3"]) onClick(id, () => void loadProxies(id));
  onClick("historyClearBtn", () => {
    clearHistory();
    renderHistory();
  });

  document.querySelectorAll<HTMLElement>("[data-client]").forEach((el, i) => {
    const key = clientList()[i]?.key;
    el.addEventListener("click", () => {
      const url = key && downloadUrl(key);
      if (url) void shellOpen(url);
    });
  });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") void onGenerate();
  });

  loadSettings();
  renderHistory();
  updateVisibility();
  updateSplitCount();

  const dpiNav = document.querySelector<HTMLElement>('.nav-item[data-view="dpi"]');
  if (currentOs() !== "windows") show(dpiNav, false);
  else void winws.winwsRunning().then((on) => setText("dpiState", on ? "Работает" : "Выключен"));

  void ws.warpscoutVersion().catch((err) => status("scan", `warpscout недоступен: ${esc(String(err))}`, "err"));
  showView("generate");
  void initWindowChrome();
}

init();
