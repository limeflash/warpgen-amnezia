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
  setBusy, panel, sectionTitle,
} from "./ui.ts";

type ConfigKind = "amnezia" | "wireguard" | "clash";

let lastConfigType: ConfigKind = "amnezia";
let lastConfig = "";
let architect: GeneratedSignature | null = null;

// ─────────────── theme ───────────────
function applyTheme(dark: boolean): void {
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  setText("themeLabel", dark ? "Тёмная тема" : "Светлая тема");
  saveJson("warpgen.theme", dark ? "dark" : "light");
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
  fillSelect("dnsServer", Object.keys(DNS_SERVERS).map((k) => ({ value: k, label: DNS_LABELS[k] ?? k })), "malw_link");
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

/** Status line under a screen's content. */
function status(view: string, text: string, kind: "info" | "err" | "ok" = "info"): void {
  const box = ensureBox(`status-${view}`, screenEl(view));
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

function wsStatus(text: string, spin = false): void {
  status("scan", spin ? `<span class="spinner"></span> ${esc(text)}` : esc(text));
}

function applyEndpoint(endpoint: string): void {
  const m = endpoint.match(/^(.+):(\d+)$/);
  if (!m) return;
  addSelectOption("endpointIp", m[1], `${m[1]} — warpscout`);
  setGroup("endpointPort", m[2]);
}

function renderScanRows(rows: ws.ScanRow[]): void {
  const box = ensureBox("wsResults", screenEl("scan"));
  const cols = "1.4fr 74px 62px 58px 1fr";
  box.style.cssText = "border:1px solid var(--line);border-radius:14px;overflow:hidden;margin-bottom:14px";
  box.innerHTML =
    `<div style="display:grid;grid-template-columns:${cols};gap:12px;padding:11px 15px;background:var(--panel-2);border-bottom:1px solid var(--line);font-size:10.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--text-3)">` +
    `<span>Endpoint</span><span style="text-align:right">Ping</span><span>Страна</span><span>Нода</span><span>Локация</span></div>` +
    `<div id="wsRows" style="max-height:360px;overflow-y:auto"></div>`;
  const list = must("wsRows");
  rows.forEach((r, i) => {
    const row = document.createElement("div");
    const color = r.ping < 60 ? "var(--ok)" : r.ping < 150 ? "var(--warn)" : "var(--err)";
    row.style.cssText = `display:grid;grid-template-columns:${cols};gap:12px;align-items:center;padding:10px 15px;border-bottom:1px solid var(--line);font-size:12.5px;cursor:pointer${i === 0 ? ";background:var(--sel);box-shadow:inset 3px 0 0 var(--accent)" : ""}`;
    row.innerHTML =
      `<span style="font-family:ui-monospace,monospace">${esc(r.endpoint)}</span>` +
      `<span style="text-align:right;font-weight:700;color:${color}">${r.ping} ms</span>` +
      `<span>${esc(r.country)}</span><span>${esc(r.node)}</span><span style="color:var(--text-3)">${esc(r.location)}</span>`;
    row.addEventListener("click", () => {
      list.querySelectorAll<HTMLElement>("div").forEach((d) => {
        d.style.background = "";
        d.style.boxShadow = "";
      });
      row.style.background = "var(--sel)";
      row.style.boxShadow = "inset 3px 0 0 var(--accent)";
      applyEndpoint(r.endpoint);
      wsStatus(`Выбран ${r.endpoint} · ${r.ping} ms · ${r.location} — подставлен в «Генератор».`);
    });
    list.appendChild(row);
  });
  screenEl("scan").insertBefore(box, screenEl("scan").firstChild!.nextSibling);
}

const scanPhase = (line: string): string | null => {
  const n = line.match(/(\d+)\s*\.\.\./)?.[1];
  const t = n ? ` — ${n}` : "";
  if (/reachable ports|probing reachable/i.test(line)) return "Проверка доступных портов…";
  if (/verifying tunnels/i.test(line)) return `Проверка туннелей…${t}`;
  if (/speedtest|measuring/i.test(line)) return `Замер скорости…${t}`;
  return null;
};

const wsFilters = () => {
  const f = inputValue("wsFilter").trim();
  if (!f) return {};
  return /^[A-Za-z]{2}(,[A-Za-z]{2})*$/.test(f) ? { country: f.toUpperCase() } : { node: f.toUpperCase() };
};

async function onScan(): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  $("wsResults")?.remove();
  wsStatus("Сканирование сети…", true);
  try {
    const { rows } = await ws.scanEndpoints({
      proto: (groupValue("wsProto") || "awg") as ws.Proto,
      ...wsFilters(),
      speed: toggleValue("wsSpeed"),
      tunPing: toggleValue("wsTunPing"),
      onLine: (l) => {
        const p = scanPhase(l);
        if (p) wsStatus(p, true);
      },
      signal: wsAbort.signal,
    });
    if (!rows.length) return wsStatus("Рабочих endpoint'ов не найдено.");
    renderScanRows(rows);
    applyEndpoint(rows[0].endpoint);
    wsStatus(`Найдено ${rows.length}. Быстрейший ${rows[0].endpoint} (${rows[0].ping} ms) подставлен в «Генератор».`);
  } catch (err) {
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
        wsStatus(`find-junk: Jc ${m[1]} · Jmin ${m[2]} · Jmax ${m[3]} — применено к генератору.`);
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
  box.textContent = "";
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
function renderAnalysis(a: AnalysisResult): void {
  const camo = a.camouflage === "HIGH" ? "var(--ok)" : a.camouflage === "MEDIUM" ? "var(--warn)" : "var(--err)";
  const mark: Record<string, [string, string]> = {
    pass: ["✓", "var(--ok)"], warn: ["!", "var(--warn)"], fail: ["✕", "var(--err)"], info: ["·", "var(--text-3)"],
  };
  const cell = (label: string, value: string, color = "var(--text)") =>
    `<div style="background:var(--panel-2);padding:11px 13px"><span style="display:block;font-size:10px;letter-spacing:.07em;text-transform:uppercase;color:var(--text-3)">${esc(label)}</span><b style="font-size:13px;color:${color}">${esc(value)}</b></div>`;

  const box = must("analyzerReport");
  box.removeAttribute("style");
  box.innerHTML =
    panel(
      sectionTitle(`Профиль · ${a.version.ver}`) +
        `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:1px;background:var(--line);border-radius:12px;overflow:hidden;margin-bottom:12px">` +
        cell("Версия", a.version.ver) + cell("Маскировка", a.camouflage, camo) +
        cell("DPI-детект", `${a.scores.dpi}%`) + cell("Stealth", `${a.scores.stealth}%`) +
        cell("Оценка", `${a.scores.total}/100`) + `</div>` +
        `<div style="font-size:11.5px;color:var(--text-3);line-height:1.5;margin-bottom:10px">${esc(a.version.desc)}</div>` +
        a.summary.map((r) => `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--line);font-size:12.5px"><span style="color:var(--text-3)">${esc(r.label)}</span><b>${esc(r.value)}</b></div>`).join(""),
    ) +
    panel(
      sectionTitle(`Проверки · ${a.checks.length}`) +
        a.checks
          .map((c) => {
            const [m, col] = mark[c.status];
            return `<div style="display:grid;grid-template-columns:20px 1fr auto;gap:10px;padding:8px 0;border-bottom:1px solid var(--line);font-size:12.5px">` +
              `<span style="color:${col};font-weight:700">${m}</span>` +
              `<span><b>${esc(c.title)}</b><div style="color:var(--text-3);font-size:11.5px">${esc(c.detail)}</div></span>` +
              `<span style="font-family:ui-monospace,monospace;color:var(--text-3)">${esc(c.value)}</span></div>`;
          })
          .join(""),
    ) +
    (a.hints.length
      ? panel(sectionTitle("Как усилить") + a.hints.map((h) => `<div style="padding:6px 0;font-size:12.5px;color:var(--text-2)">→ ${esc(h)}</div>`).join(""))
      : "");
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
}

init();
