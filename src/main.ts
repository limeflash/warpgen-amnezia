import { generateConfig } from "./core/generate.ts";
import { I1_GROUPS, DEFAULT_I1_KEY } from "./core/i1.ts";
import { splitTargetList, catalogTargetGroups } from "./core/split.ts";
import { DNS_SERVERS, DOH_PRESETS } from "./core/dns.ts";
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
import { PROTOCOL_INFO, calcChainSize, CPS_MAX_BYTES, AWG_PARAM_HINTS } from "./core/awg-meta.ts";
import { compatWarning, recommendedMtu, type AwgVersion } from "./core/obfuscation.ts";
import { analyzeConfig, type AnalysisResult } from "./core/analyzer.ts";
import { open as shellOpen } from "@tauri-apps/plugin-shell";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { downloadDir, join } from "@tauri-apps/api/path";

// ─────────────── DOM helpers ───────────────
function $<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} missing`);
  return el as T;
}
const val = (id: string) => $<HTMLInputElement>(id).value;
const setText = (id: string, text: string): void => {
  $(id).textContent = text;
};
const show = (el: HTMLElement, on: boolean) => el.classList.toggle("hidden", !on);
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
const radio = (name: string) => (document.querySelector(`input[name="${name}"]:checked`) as HTMLInputElement | null)?.value ?? "";
function setRadio(name: string, value: string): void {
  const el = document.querySelector<HTMLInputElement>(`input[name="${name}"][value="${value}"]`);
  if (el) el.checked = true;
}

let lastConfigType: "amnezia" | "wireguard" | "clash" = "amnezia";
let lastConfig = "";
/** Obfuscation set produced by Architect / find-junk, applied on the next generate. */
let architect: GeneratedSignature | null = null;

// ─────────────── Theme ───────────────
function applyTheme(dark: boolean): void {
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  setText("themeLabel", dark ? "Тёмная тема" : "Светлая тема");
  saveJson("warpgen.theme", dark ? "dark" : "light");
}

// ─────────────── Views ───────────────
const VIEW_META: Record<string, { title: string; sub: string }> = {
  generate: { title: "Генератор", sub: "Cloudflare WARP · AmneziaWG, WireGuard, Clash" },
  result: { title: "Результат", sub: "ничего ещё не сгенерировано" },
  scan: { title: "Поиск endpoint", sub: "warpscout · сканер endpoint'ов" },
  dpi: { title: "DPI-обход", sub: "winws2 / zapret2 · Windows" },
  import: { title: "Импорт", sub: "WireGuard / AmneziaWG / vpn://" },
  clients: { title: "Клиенты", sub: "загрузки под вашу ОС" },
  history: { title: "История", sub: "локально · до 20 записей" },
  tools: { title: "Инструменты", sub: "ключи WARP+ и прокси" },
  analyzer: { title: "Анализатор", sub: "вставьте .conf для диагностики" },
};

function showView(name: string): void {
  document.querySelectorAll<HTMLElement>(".view").forEach((v) => v.classList.toggle("active", v.dataset.view === name));
  document.querySelectorAll<HTMLElement>(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === name));
  const meta = VIEW_META[name];
  if (meta) {
    setText("viewTitle", meta.title);
    setText("viewSub", name === "result" && lastConfig ? resultSubtitle() : meta.sub);
  }
  renderTopActions(name);
  document.querySelector(".scroll")?.scrollTo({ top: 0 });
}

function renderTopActions(view: string): void {
  const box = $("topActions");
  box.textContent = "";
  const add = (label: string, cls: string, fn: () => void) => {
    const b = document.createElement("button");
    b.className = `btn ${cls}`;
    b.textContent = label;
    b.addEventListener("click", fn);
    box.appendChild(b);
  };
  if (view === "generate") {
    add("Сброс", "ghost", resetDefaults);
    add("Сгенерировать конфиг", "", onGenerate);
  } else if (view === "history" && loadHistory().length) {
    add("Очистить всё", "ghost", () => {
      clearHistory();
      renderHistory();
    });
  }
}

// ─────────────── Static control builders ───────────────
const DNS_LABELS: Record<string, string> = {
  malw_link: "dns.malw.link — разблокировка сайтов",
  cloudflare: "Cloudflare 1.1.1.1",
  cloudflare_mal: "Cloudflare 1.1.1.2 — малварь",
  google: "Google 8.8.8.8",
  adguard: "AdGuard — реклама и трекеры",
  adguard_family: "AdGuard Family",
  adguard_nofilter: "AdGuard — без фильтрации",
  yandex: "Яндекс 77.88.8.8",
  yandex_safe: "Яндекс Safe",
  yandex_family: "Яндекс Family",
  quad9: "Quad9 9.9.9.9",
  quad9_ecs: "Quad9 ECS",
  quad9_nofilter: "Quad9 — без фильтрации",
  opendns: "OpenDNS",
  opendns_family: "OpenDNS Family Shield",
  gcore: "G-Core",
  dnssb: "DNS.SB",
  dns0eu: "dns0.eu",
  nextdns: "NextDNS",
  mullvad: "Mullvad",
};

function buildSelects(): void {
  const dns = $<HTMLSelectElement>("dnsServer");
  for (const key of Object.keys(DNS_SERVERS)) {
    dns.add(new Option(DNS_LABELS[key] ?? key, key));
  }
  dns.value = "malw_link";

  const doh = $<HTMLSelectElement>("dohPreset");
  for (const p of DOH_PRESETS) doh.add(new Option(`${p.label} — ${p.sni}`, p.id));

  const i1 = $<HTMLSelectElement>("i1Preset");
  for (const group of I1_GROUPS) {
    const og = document.createElement("optgroup");
    og.label = group.label;
    for (const o of group.options) og.appendChild(new Option(o.label, o.key));
    i1.appendChild(og);
  }
  i1.value = DEFAULT_I1_KEY;
}

function buildArchTiles(): void {
  const box = $("archProfiles");
  for (const p of MIMIC_PROFILES) {
    const info = PROTOCOL_INFO[p];
    const l = document.createElement("label");
    l.className = "opt";
    l.innerHTML =
      `<input type="radio" name="archProfile" value="${p}"${p === "quic_initial" ? " checked" : ""} />` +
      `<b>${esc(info?.name ?? p)}</b><i>${esc(info?.description ?? "")}</i>`;
    box.appendChild(l);
  }
}

function buildSplitGrid(): void {
  const box = $("splitGrid");
  const mk = (key: string, label: string) => {
    const l = document.createElement("label");
    l.className = "toggle";
    l.style.marginBottom = "6px";
    l.dataset.name = label.toLowerCase();
    l.innerHTML = `<input type="checkbox" data-split="${esc(key)}" /> <span>${esc(label)}</span>`;
    return l;
  };
  const heading = (text: string) => {
    const h = document.createElement("div");
    h.className = "card-head";
    h.style.cssText = "background:transparent;border:0;padding:10px 2px 5px";
    h.innerHTML = `<b>${esc(text)}</b>`;
    return h;
  };

  box.appendChild(heading("Основные (с подсетями)"));
  for (const t of splitTargetList()) box.appendChild(mk(t.key, t.label));
  for (const g of catalogTargetGroups()) {
    box.appendChild(heading(g.label));
    for (const t of g.targets) box.appendChild(mk(t.key, t.label));
  }
  box.addEventListener("change", updateSplitCount);
}

function buildClientRows(): void {
  const box = $("clientBtns");
  const os = currentOs();
  const desc: Record<string, string> = {
    wireguard: "Официальный клиент · vanilla конфиг",
    amnezia: "Поддержка AmneziaWG и обфускации",
    clash_verge: "Правила роутинга, .yaml профили",
    wiresock: "Split tunnel на Windows",
  };
  for (const { key, title } of clientList()) {
    const row = document.createElement("div");
    row.className = "row";
    row.style.gridTemplateColumns = "1fr auto";
    row.innerHTML = `<div><b>${esc(title)}</b><div class="muted" style="font-size:11.5px">${esc(desc[key] ?? "")}</div></div>`;
    const btn = document.createElement("button");
    btn.className = "btn ghost";
    btn.textContent = "Скачать →";
    btn.addEventListener("click", () => {
      const url = downloadUrl(key, os);
      if (url) void shellOpen(url);
    });
    row.appendChild(btn);
    box.appendChild(row);
  }
}

// ─────────────── Split targets ───────────────
const SPLIT_PRESETS: Record<string, string[]> = {
  social: ["discord", "youtube", "x_com", "instagram", "twitch", "telegram", "whatsapp", "tiktok"],
  gaming: ["steam", "faceit", "apex_legends", "ea_app", "battle_net", "cs2", "pubg"],
  ai: ["chatgpt", "claude_ai", "gemini", "grok", "cat:openai", "cat:anthropic", "cat:gemini", "cat:grok"],
};
const splitBoxes = () => Array.from(document.querySelectorAll<HTMLInputElement>("input[data-split]"));
const selectedSplitTargets = () => splitBoxes().filter((c) => c.checked).map((c) => c.dataset.split!);
function setSplitTargets(keys: string[]): void {
  const set = new Set(keys);
  for (const c of splitBoxes()) c.checked = set.has(c.dataset.split!);
  updateSplitCount();
}
function updateSplitCount(): void {
  setText("splitCount", `выбрано ${selectedSplitTargets().length}`);
}

// ─────────────── Reactive UI state ───────────────
function updateVisibility(): void {
  const type = radio("configType");
  document.querySelectorAll<HTMLElement>(".amnezia-only").forEach((el) => show(el, type === "amnezia"));
  document.querySelectorAll<HTMLElement>(".clash-only").forEach((el) => show(el, type === "clash"));
  show($("splitBox"), radio("splitMode") === "selective");
  show($("customI1Domain"), val("i1Preset") === "custom");

  const v = (radio("awgVersion") || "1.5") as AwgVersion;
  const warn = compatWarning(v);
  show($("awgWarn"), !!warn);
  if (warn) setText("awgWarnText", warn);
  setText("awgVerMeta", `AWG ${v}`);
  setText("mtuHint", `рекомендуется ${recommendedMtu(v)}`);
  updateSummary();
}

function updateSummary(): void {
  const type = radio("configType");
  const typeName = type === "clash" ? "Clash / Mihomo" : type === "wireguard" ? "WireGuard" : "AmneziaWG";
  const ip = val("endpointIp");
  const port = val("endpointPort");
  const selective = radio("splitMode") === "selective";
  const ka = parseInt(val("keepalive"), 10) || 0;

  setText("sumType", typeName);
  setText("sumPort", port);
  setText("sumDns", (DNS_LABELS[val("dnsServer")] ?? val("dnsServer")).split(" —")[0]);
  setText("sumMtu", val("mtu"));
  setText("sumI1", architect ? `Architect · ${PROTOCOL_INFO[architect.profile]?.name ?? architect.profile}` : ($<HTMLSelectElement>("i1Preset").selectedOptions[0]?.text ?? "—"));
  setText("sumRoute", selective ? `Split · ${selectedSplitTargets().length}` : "Full Tunnel");
  setText("sumKa", ka > 0 ? `${ka} c` : "выключен");
  setText("sumIpv6", $<HTMLInputElement>("includeIpv6").checked ? "включён" : "выключен");
  setText("sumMeta", `${ip === "auto" ? "auto" : ip}:${port} · ${selective ? "split" : "full"} tunnel`);
  setText("advMeta", `MTU ${val("mtu")} · KA ${ka || "off"}`);
  setText("routeMeta", selective ? "выбранные сервисы" : "весь трафик через WARP");
  setText("acctMeta", val("licenseKey").trim() ? "WARP+" : "Free");
}

// ─────────────── Architect ───────────────
function updateChainSize(): void {
  if (!architect) {
    setText("chainSize", `— / ${CPS_MAX_BYTES} Б`);
    return;
  }
  const bytes = calcChainSize(architect.obfuscation);
  setText("chainSize", `${bytes} / ${CPS_MAX_BYTES} Б`);
  $("chainSize").style.color = bytes < CPS_MAX_BYTES ? "var(--ok)" : "var(--err)";
}

function onArchGenerate(): void {
  const version = (radio("awgVersion") || "1.5") as AwgVersion;
  architect = generateSignature(version, {
    profile: radio("archProfile") as (typeof MIMIC_PROFILES)[number],
    intensity: radio("archIntensity") as "low" | "medium" | "high",
    junkLevel: parseInt(val("archJunk"), 10),
    customHost: val("archHost").trim() || undefined,
    browserProfile: (val("archBrowser") || "") as never,
    routerMode: $<HTMLInputElement>("archRouter").checked,
    mtu: parseInt(val("mtu"), 10) || 1280,
  });
  const o = architect.obfuscation;
  setText(
    "archStatus",
    `✓ ${PROTOCOL_INFO[architect.profile]?.name ?? architect.profile} · Jc ${architect.junk.jc} · ` +
      `S ${o.s1}/${o.s2}${o.s3 !== undefined ? `/${o.s3}/${o.s4}` : ""} · H ${o.h?.[0]} …`,
  );
  updateChainSize();
  updateSummary();
}

function clearArchitect(): void {
  architect = null;
  setText("archStatus", "");
  updateChainSize();
  updateSummary();
}

// ─────────────── Generate ───────────────
function resultSubtitle(): string {
  return `${lastConfigType === "clash" ? "Clash / Mihomo" : lastConfigType === "wireguard" ? "WireGuard" : "AmneziaWG"} · готов`;
}

function fileName(): string {
  const base = (val("configName").trim() || "WARP").replace(/[^\w.-]+/g, "_");
  return lastConfigType === "clash" ? `${base}.yaml` : `${base}.conf`;
}

function setResult(config: string, type: typeof lastConfigType, meta: string): void {
  lastConfig = config;
  lastConfigType = type;
  $<HTMLTextAreaElement>("configOutput").value = config;
  setText("resultFile", fileName());
  setText("resultMeta", meta);
  show($("resultEmpty"), false);
  show($("resultBox"), true);
  show($("qrWrap"), false);
  showView("result");
}

async function onGenerate(): Promise<void> {
  const errBox = $("errorBox");
  errBox.style.display = "none";
  const btn = document.querySelector<HTMLButtonElement>("#topActions .btn:last-child");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Генерируем…';
  }
  try {
    const ka = parseInt(val("keepalive"), 10);
    const type = radio("configType") as typeof lastConfigType;
    const result = await generateConfig({
      licenseKey: val("licenseKey"),
      configType: type,
      obfsProfile: radio("obfsProfile"),
      endpointPort: val("endpointPort"),
      endpointIp: val("endpointIp"),
      i1Preset: val("i1Preset"),
      customI1Domain: val("customI1Domain"),
      dnsServer: val("dnsServer"),
      splitMode: radio("splitMode") === "selective" ? "selective" : "full",
      splitTargets: selectedSplitTargets(),
      mtu: parseInt(val("mtu"), 10) || 1280,
      persistentKeepalive: ka === 0 ? null : ka,
      includeIpv6: $<HTMLInputElement>("includeIpv6").checked,
      awgVersion: (radio("awgVersion") || "1.5") as AwgVersion,
      ...(architect ? { signature: {} , customJunk: architect.junk, obfuscation: architect.obfuscation } : {}),
    });

    const plus = result.accountType === "warp_plus" || result.accountType === "unlimited";
    $("accountBadge").textContent = plus ? "WARP+" : "Free";
    $("accountBadge").className = `tag${plus ? " plus" : ""}`;
    setText("accountNote", plus ? "Аккаунт WARP+" : "Бесплатный аккаунт Cloudflare");

    let meta = result.endpoint;
    if (result.splitTunnel.mode === "selective") meta += ` · ${result.splitTunnel.resolvedAllowedIps} маршрутов`;
    setResult(result.config, result.configType, meta);
    setText("resultStatus", result.licenseError ? `⚠ Ключ: ${result.licenseError}` : "");
    pushHistory(result.configType, result.endpoint, result.config);
  } catch (err) {
    errBox.textContent = "⚠ " + (err instanceof Error ? err.message : String(err));
    errBox.style.display = "block";
    showView("generate");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Сгенерировать конфиг";
    }
  }
}

function resetDefaults(): void {
  $<HTMLInputElement>("licenseKey").value = "";
  $<HTMLInputElement>("configName").value = "";
  setRadio("configType", "amnezia");
  setRadio("obfsProfile", "1");
  setRadio("splitMode", "full");
  setRadio("awgVersion", "1.5");
  $<HTMLSelectElement>("endpointPort").value = "2408";
  $<HTMLSelectElement>("endpointIp").value = "auto";
  $<HTMLSelectElement>("dnsServer").value = "malw_link";
  $<HTMLSelectElement>("i1Preset").value = DEFAULT_I1_KEY;
  $<HTMLInputElement>("mtu").value = "1280";
  $<HTMLInputElement>("keepalive").value = "25";
  $<HTMLInputElement>("includeIpv6").checked = true;
  setSplitTargets([]);
  clearArchitect();
  updateVisibility();
}

async function downloadConfig(): Promise<void> {
  try {
    const path = await join(await downloadDir(), fileName());
    await writeTextFile(path, lastConfig);
    setText("resultStatus", `Сохранено: ${path}`);
  } catch {
    const url = URL.createObjectURL(new Blob([lastConfig], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName();
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

async function copyText(text: string, btn: HTMLButtonElement, done: string, normal: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = done;
    setTimeout(() => (btn.textContent = normal), 1800);
  } catch {
    btn.textContent = "Ошибка";
  }
}

function toggleQr(): void {
  if (!lastConfig) return;
  const wrap = $("qrWrap");
  if (!wrap.classList.contains("hidden")) {
    show(wrap, false);
    return;
  }
  try {
    $<HTMLImageElement>("qrImg").src = qrDataUrl(lastConfig);
    show(wrap, true);
  } catch {
    setText("resultStatus", "Конфиг слишком большой для QR — используйте «Скачать».");
  }
}

// ─────────────── Import ───────────────
async function onImport(toClash: boolean): Promise<void> {
  const input = val("importInput").trim();
  if (!input) return;
  const btn = $<HTMLButtonElement>(toClash ? "importClashBtn" : "importRawBtn");
  btn.disabled = true;
  try {
    const raw = await normalizeImportedConfig(input);
    const output = toClash ? clashFromNode(parseImportedConf(raw)) : raw;
    const type = toClash ? "clash" : /(\bJc\s*=|\bI1\s*=)/.test(raw) ? "amnezia" : "wireguard";
    setResult(output, type, toClash ? "импорт → Clash" : "импорт");
    setText("importStatus", "✓ Готово.");
    pushHistory(type, "", output);
  } catch (err) {
    setText("importStatus", `Ошибка: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    btn.disabled = false;
  }
}

// ─────────────── warpscout ───────────────
let wsAbort: AbortController | null = null;

function wsBusy(on: boolean): void {
  for (const id of ["wsScanBtn", "wsImportBtn", "wsJunkBtn", "wsSniBtn"]) $<HTMLButtonElement>(id).disabled = on;
  $<HTMLButtonElement>("wsStopBtn").disabled = !on;
}
function wsProgress(text: string): void {
  $("wsStatus").innerHTML = `<span class="spinner" style="border-color:var(--line-2);border-top-color:var(--accent);vertical-align:middle;margin-right:7px"></span>${esc(text)}`;
}
function scanPhase(line: string): string | null {
  const n = line.match(/(\d+)\s*\.\.\./)?.[1];
  const tail = n ? ` — ${n}` : "";
  if (/reachable ports|probing reachable/i.test(line)) return "Проверка доступных портов…";
  if (/verifying tunnels/i.test(line)) return `Проверка туннелей…${tail}`;
  if (/speedtest|measuring/i.test(line)) return `Замер скорости…${tail}`;
  return null;
}
function wsFilters(): { country?: string; node?: string } {
  const f = val("wsFilter").trim();
  if (!f) return {};
  return /^[A-Za-z]{2}(,[A-Za-z]{2})*$/.test(f) ? { country: f.toUpperCase() } : { node: f.toUpperCase() };
}
function applyEndpoint(endpoint: string): void {
  const m = endpoint.match(/^(.+):(\d+)$/);
  if (!m) return;
  const [, ip, port] = m;
  const ipSel = $<HTMLSelectElement>("endpointIp");
  if (![...ipSel.options].some((o) => o.value === ip)) ipSel.add(new Option(`${ip} — warpscout`, ip));
  ipSel.value = ip;
  const portSel = $<HTMLSelectElement>("endpointPort");
  if (![...portSel.options].some((o) => o.value === port)) portSel.add(new Option(port, port));
  portSel.value = port;
  updateSummary();
}

function renderScanRows(rows: ws.ScanRow[]): void {
  const box = $("wsResults");
  box.textContent = "";
  show(box, rows.length > 0);
  if (!rows.length) return;
  const cols = "1.4fr 70px 60px 56px 1fr";
  const head = document.createElement("div");
  head.className = "row head";
  head.style.gridTemplateColumns = cols;
  head.innerHTML = "<span>Endpoint</span><span style='text-align:right'>Ping</span><span>Страна</span><span>Нода</span><span>Локация</span>";
  const scroll = document.createElement("div");
  scroll.className = "scroll-box";
  rows.forEach((r, i) => {
    const b = document.createElement("button");
    b.className = "row pick" + (i === 0 ? " sel" : "");
    b.style.gridTemplateColumns = cols;
    const color = r.ping < 60 ? "var(--ok)" : r.ping < 150 ? "var(--warn)" : "var(--err)";
    b.innerHTML =
      `<span class="mono">${esc(r.endpoint)}</span>` +
      `<span style="text-align:right;font-weight:700;color:${color}">${r.ping} ms</span>` +
      `<span>${esc(r.country)}</span><span>${esc(r.node)}</span>` +
      `<span class="muted">${esc(r.location)}</span>`;
    b.addEventListener("click", () => {
      scroll.querySelectorAll(".row").forEach((el) => el.classList.remove("sel"));
      b.classList.add("sel");
      applyEndpoint(r.endpoint);
      setText("wsStatus", `✓ ${r.endpoint} · ${r.ping} ms · ${r.location} — подставлен в «Генератор».`);
    });
    scroll.appendChild(b);
  });
  box.append(head, scroll);
}

async function onScan(): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  wsBusy(true);
  show($("wsResults"), false);
  show($("wsLog"), false);
  wsProgress("Сканирование сети…");
  try {
    const { rows } = await ws.scanEndpoints({
      proto: val("wsProto") as ws.Proto,
      ...wsFilters(),
      speed: $<HTMLInputElement>("wsSpeed").checked,
      tunPing: $<HTMLInputElement>("wsTunPing").checked,
      onLine: (line) => {
        const p = scanPhase(line);
        if (p) wsProgress(p);
      },
      signal: wsAbort.signal,
    });
    if (!rows.length) return setText("wsStatus", "Рабочих endpoint'ов не найдено.");
    renderScanRows(rows);
    applyEndpoint(rows[0].endpoint);
    setText("wsStatus", `✓ Найдено ${rows.length}. Быстрейший ${rows[0].endpoint} (${rows[0].ping} ms) подставлен.`);
  } catch (err) {
    setText("wsStatus", wsAbort?.signal.aborted ? "Остановлено." : `⚠ ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    wsBusy(false);
    wsAbort = null;
  }
}

function wsLog(line: string): void {
  const log = $("wsLog");
  show(log, true);
  log.textContent += line + "\n";
  log.scrollTop = log.scrollHeight;
}

async function wsRun(kind: "import" | "junk" | "sni"): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  wsBusy(true);
  wsProgress(kind === "import" ? "Импорт конфига…" : kind === "junk" ? "Подбор junk-параметров…" : "Поиск SNI…");
  const proto = val("wsProto") as ws.Proto;
  try {
    if (kind === "import") {
      const { config, endpoint } = await ws.importConfig({ proto, ...wsFilters(), onLine: wsLog, signal: wsAbort.signal });
      setResult(config, proto === "wg" ? "wireguard" : "amnezia", `warpscout${endpoint ? ` · ${endpoint}` : ""}`);
      pushHistory(lastConfigType, endpoint ?? "", config);
      setText("wsStatus", "✓ Конфиг импортирован.");
    } else if (kind === "junk") {
      const out = await ws.findJunk({ proto, onLine: wsLog, signal: wsAbort.signal });
      const m = out.match(/jc\s*=?\s*(\d+).*?jmin\s*=?\s*(\d+).*?jmax\s*=?\s*(\d+)/is);
      if (m) {
        architect = {
          junk: { jc: +m[1], jmin: +m[2], jmax: +m[3] },
          profile: architect?.profile ?? "quic_initial",
          obfuscation: architect?.obfuscation ?? {},
        };
        setText("wsStatus", `✓ find-junk: Jc ${m[1]} · Jmin ${m[2]} · Jmax ${m[3]} — применено к генератору.`);
        updateSummary();
      } else {
        setText("wsStatus", "find-junk завершён — параметры в логе.");
      }
    } else {
      const out = await ws.findSni({ proto, onLine: wsLog, signal: wsAbort.signal });
      const host = out.match(/\b([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b/i)?.[1];
      if (host) {
        $<HTMLInputElement>("archHost").value = host;
        setText("wsStatus", `✓ find-sni: ${host} — подставлен в Architect (свой хост).`);
      } else {
        setText("wsStatus", "find-sni завершён — результат в логе.");
      }
    }
  } catch (err) {
    setText("wsStatus", wsAbort?.signal.aborted ? "Остановлено." : `⚠ ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    wsBusy(false);
    wsAbort = null;
  }
}

async function checkWarpscout(): Promise<void> {
  try {
    const v = await ws.warpscoutVersion();
    setText("wsStatus", `warpscout ${v} готов.`);
    $("wsMissing").style.display = "none";
  } catch (err) {
    const box = $("wsMissing");
    box.style.display = "block";
    box.textContent = `warpscout недоступен: ${err instanceof Error ? err.message : String(err)}`;
  }
}

// ─────────────── DPI ───────────────
function dpiLog(line: string): void {
  const l = $("dpiLog");
  show(l, true);
  l.textContent += line + "\n";
  l.scrollTop = l.scrollHeight;
}
function dpiSetRunning(on: boolean): void {
  $<HTMLButtonElement>("dpiStartBtn").disabled = on;
  $<HTMLButtonElement>("dpiStopBtn").disabled = !on;
  setText("dpiState", on ? "Работает" : "Выключен");
  setText("dpiStatus", on ? "🟢 DPI-обход активен." : "");
}
async function dpiStart(): Promise<void> {
  $<HTMLButtonElement>("dpiStartBtn").disabled = true;
  setText("dpiStatus", "Запуск… подтвердите UAC.");
  try {
    await winws.startWinws(
      { ports: val("dpiPorts"), fakeTtl: parseInt(val("dpiTtl"), 10) || 0, quic: $<HTMLInputElement>("dpiQuic").checked },
      dpiLog,
    );
    dpiSetRunning(true);
  } catch (err) {
    setText("dpiStatus", `⚠ ${err instanceof Error ? err.message : String(err)}`);
    $<HTMLButtonElement>("dpiStartBtn").disabled = false;
  }
}

// ─────────────── History ───────────────
function renderHistory(): void {
  const list = loadHistory();
  const box = $("historyList");
  box.textContent = "";
  show(box, list.length > 0);
  show($("historyEmpty"), list.length === 0);
  setText("historyCount", String(list.length));
  if (!list.length) return renderTopActions("history");

  const cols = "110px 1fr 108px 96px auto";
  const head = document.createElement("div");
  head.className = "row head";
  head.style.gridTemplateColumns = cols;
  head.innerHTML = "<span>Тип</span><span>Endpoint</span><span>Дата</span><span>Тег</span><span></span>";
  box.appendChild(head);

  for (const e of list) {
    const row = document.createElement("div");
    row.className = "row";
    row.style.gridTemplateColumns = cols;
    const d = new Date(e.ts);
    const date = `${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")} · ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    row.innerHTML =
      `<b>${esc(e.configType === "clash" ? "Clash" : e.configType === "wireguard" ? "WireGuard" : "AmneziaWG")}</b>` +
      `<span class="mono muted">${esc(e.endpoint || "—")}</span><span class="muted">${esc(date)}</span>`;

    const tag = document.createElement("input");
    tag.type = "text";
    tag.value = e.tag;
    tag.placeholder = "тег";
    tag.style.cssText = "padding:5px 8px;font-size:11.5px";
    tag.addEventListener("change", () => updateHistoryTag(e.id, tag.value));

    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:6px";
    const open = document.createElement("button");
    open.className = "chip-btn";
    open.textContent = "Открыть";
    open.addEventListener("click", () => setResult(e.config, e.configType as typeof lastConfigType, "из истории"));
    const del = document.createElement("button");
    del.className = "chip-btn";
    del.textContent = "✕";
    del.addEventListener("click", () => {
      deleteHistory(e.id);
      renderHistory();
    });
    actions.append(open, del);
    row.append(tag, actions);
    box.appendChild(row);
  }
  renderTopActions("history");
}

function pushHistory(configType: string, endpoint: string, config: string): void {
  addHistory({ configType, endpoint, config });
  renderHistory();
}

// ─────────────── Analyzer ───────────────
function renderAnalysis(a: AnalysisResult): void {
  const box = $("analyzerReport");
  const camoColor = a.camouflage === "HIGH" ? "var(--ok)" : a.camouflage === "MEDIUM" ? "var(--warn)" : "var(--err)";
  const statusColor: Record<string, string> = { pass: "var(--ok)", warn: "var(--warn)", fail: "var(--err)", info: "var(--text-3)" };
  const statusMark: Record<string, string> = { pass: "✓", warn: "!", fail: "✕", info: "·" };

  const checks = a.checks
    .map(
      (c) =>
        `<div class="row" style="grid-template-columns:20px 1fr auto">` +
        `<span style="color:${statusColor[c.status]};font-weight:700">${statusMark[c.status]}</span>` +
        `<span><b>${esc(c.title)}</b><div class="muted" style="font-size:11.5px">${esc(c.detail)}</div></span>` +
        `<span class="mono muted">${esc(c.value)}</span></div>`,
    )
    .join("");

  const hints = a.hints.length
    ? `<div class="card"><div class="card-head"><b>Как усилить</b></div><div class="card-body">${a.hints
        .map((h) => `<div class="kv"><span>→</span><b style="font-weight:500;text-align:right">${esc(h)}</b></div>`)
        .join("")}</div></div>`
    : "";

  box.innerHTML =
    `<div class="card"><div class="card-head"><b>Профиль</b><span class="meta">${esc(a.version.ver)}</span></div><div class="card-body">` +
    `<div class="sum" style="margin-bottom:13px">` +
    `<div><span>Версия</span><b>${esc(a.version.ver)}</b></div>` +
    `<div><span>Маскировка</span><b style="color:${camoColor}">${a.camouflage}</b></div>` +
    `<div><span>DPI-детект</span><b>${a.scores.dpi}%</b></div>` +
    `<div><span>Stealth</span><b>${a.scores.stealth}%</b></div>` +
    `<div><span>Оценка</span><b>${a.scores.total}/100</b></div></div>` +
    `<div class="hint" style="margin-top:0">${esc(a.version.desc)}</div>` +
    a.summary.map((r) => `<div class="kv"><span>${esc(r.label)}</span><b>${esc(r.value)}</b></div>`).join("") +
    `</div></div>` +
    `<div class="card"><div class="card-head"><b>Проверки</b><span class="meta">${a.checks.length}</span></div>` +
    `<div class="rows" style="border:0;border-radius:0">${checks}</div></div>` +
    hints;
}

function onAnalyze(): void {
  const raw = val("analyzerInput").trim();
  if (!raw) return setText("analyzerStatus", "Вставьте конфиг.");
  try {
    renderAnalysis(analyzeConfig(raw));
    setText("analyzerStatus", "");
  } catch (err) {
    setText("analyzerStatus", `Ошибка: ${err instanceof Error ? err.message : String(err)}`);
  }
}

// ─────────────── Tools: license / proxy / bruteforce ───────────────
async function onCheckKey(): Promise<void> {
  const key = val("secretKey").trim();
  const btn = $<HTMLButtonElement>("checkKeyBtn");
  if (!key) return setText("secretStatus", "Введите ключ.");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Проверяем…';
  try {
    const r = await checkLicense(key);
    setText("secretStatus", `${r.valid ? "✓ валидный" : "✕ невалидный"} · ${r.accountType}${r.referralCount !== null ? ` · referrals ${r.referralCount}` : ""} · ${r.message}`);
  } catch (err) {
    setText("secretStatus", `Ошибка: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Проверить ключ";
  }
}

async function onGenTest(): Promise<void> {
  const btn = $<HTMLButtonElement>("genTestBtn");
  btn.disabled = true;
  try {
    const r = await generateTestLicense();
    $<HTMLInputElement>("secretKey").value = r.license;
    setText("secretStatus", `TEST ключ · ${r.accountType} · проверяем…`);
    await onCheckKey();
  } catch (err) {
    setText("secretStatus", `Ошибка: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Сген. TEST";
  }
}

const PROXY_SOURCES: Record<string, { url: string; prefix: string }> = {
  mono_http: { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", prefix: "" },
  mono_socks5: { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", prefix: "socks5://" },
  speedx_http: { url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", prefix: "" },
  speedx_socks4: { url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", prefix: "socks4://" },
  speedx_socks5: { url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", prefix: "socks5://" },
};

async function fetchProxySource(key: string): Promise<string[]> {
  const src = PROXY_SOURCES[key];
  if (!src) return [];
  try {
    const res = await httpFetch(src.url, { method: "GET", connectTimeout: 12000 });
    if (!res.ok) return [];
    return (await res.text())
      .trim()
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => /^\d+\.\d+\.\d+\.\d+:\d+/.test(l.replace(/^socks[45]:\/\//, "")))
      .map((l) => (src.prefix && !l.startsWith("socks") ? src.prefix + l : l));
  } catch {
    return [];
  }
}

async function loadProxies(which: string): Promise<void> {
  setText("proxyLoadStatus", "загрузка…");
  const ta = $<HTMLTextAreaElement>("bfProxies");
  let lines: string[];
  if (which === "all") {
    const all = await Promise.all(Object.keys(PROXY_SOURCES).map(fetchProxySource));
    all.push(ta.value.split("\n"));
    lines = [...new Set(all.flat().map((s) => s.trim()).filter(Boolean))];
  } else {
    lines = await fetchProxySource(which);
  }
  if (!lines.length) return setText("proxyLoadStatus", "ошибка загрузки");
  ta.value = lines.join("\n");
  setText("proxyLoadStatus", `${lines.length} прокси`);
}

let proxyAbort: AbortController | null = null;
async function onCheckProxies(): Promise<void> {
  const ta = $<HTMLTextAreaElement>("bfProxies");
  const proxies = ta.value.trim().split("\n").map((l) => l.trim()).filter(Boolean);
  if (!proxies.length) return;
  proxyAbort = new AbortController();
  const btn = $<HTMLButtonElement>("proxyCheckBtn");
  const bar = $("proxyProgress");
  btn.disabled = true;
  $<HTMLButtonElement>("proxyStopBtn").disabled = false;
  show(bar, true);
  const valid = await runProxyCheck(proxies, {
    concurrency: 200,
    signal: proxyAbort.signal,
    onProgress: ({ checked, valid, total }) => {
      (bar.firstElementChild as HTMLElement).style.width = `${Math.round((checked / total) * 100)}%`;
      setText("proxyCheckStatus", `Проверено ${checked}/${total} · рабочих ${valid}`);
    },
  });
  ta.value = valid.join("\n");
  setText("proxyCheckStatus", `✓ Готово: ${valid.length} рабочих`);
  btn.disabled = false;
  $<HTMLButtonElement>("proxyStopBtn").disabled = true;
  proxyAbort = null;
}

let bfAbort: AbortController | null = null;
async function onBruteforce(): Promise<void> {
  const count = Math.min(Math.max(parseInt(val("bfCount"), 10) || 100, 1), 10000);
  const keys = Array.from({ length: count }, generateWarpKey);
  const proxies = val("bfProxies").trim().split("\n").map((l) => l.trim()).filter(Boolean);
  bfAbort = new AbortController();
  const start = $<HTMLButtonElement>("bfStartBtn");
  start.disabled = true;
  start.innerHTML = '<span class="spinner"></span>Проверяем…';
  $<HTMLButtonElement>("bfStopBtn").disabled = false;
  show($("bfProgress"), true);
  $("bfLog").textContent = "";
  show($("bfLog"), true);
  $<HTMLTextAreaElement>("bfValidKeys").value = "";
  show($("bfValidWrap"), false);

  const bar = $("bfProgress").firstElementChild as HTMLElement;
  const log = $("bfLog");
  const validKeys = await runBruteforce(keys, proxies, {
    concurrency: parseInt(val("bfThreads"), 10) || 30,
    signal: bfAbort.signal,
    onEvent: (e) => {
      bar.style.width = `${Math.round((e.checked / e.total) * 100)}%`;
      setText("bfCounters", `Проверено ${e.checked}/${e.total} · найдено ${e.found}${proxies.length ? ` · живых прокси ${e.aliveCount}` : ""}`);
      if (e.type === "valid") {
        log.insertAdjacentHTML("beforeend", `<span style="color:var(--ok)">✓ ${esc(e.key)} [${esc(e.accountType ?? "")}]</span>\n`);
        const ta = $<HTMLTextAreaElement>("bfValidKeys");
        ta.value = ta.value ? `${ta.value}\n${e.key}` : e.key;
        show($("bfValidWrap"), true);
      } else if (e.checked % 5 === 0) {
        log.insertAdjacentHTML("beforeend", `<span class="muted">✕ ${esc(e.key)}</span>\n`);
      }
      log.scrollTop = log.scrollHeight;
    },
  });
  setText("bfCounters", `Готово: найдено ${validKeys.length}`);
  start.disabled = false;
  start.textContent = "Сгенерировать и проверить";
  $<HTMLButtonElement>("bfStopBtn").disabled = true;
  bfAbort = null;
}

// ─────────────── Settings ───────────────
const SETTINGS_KEY = "warpgen.settings";
interface Settings {
  configType?: string; obfsProfile?: string; splitMode?: string; awgVersion?: string;
  endpointPort?: string; endpointIp?: string; dnsServer?: string; dohPreset?: string;
  i1Preset?: string; customI1Domain?: string; configName?: string;
  mtu?: string; keepalive?: string; includeIpv6?: boolean; splitTargets?: string[];
  archProfile?: string; archIntensity?: string; archJunk?: string; archHost?: string; archBrowser?: string;
}

function collectSettings(): Settings {
  return {
    configType: radio("configType"), obfsProfile: radio("obfsProfile"), splitMode: radio("splitMode"),
    awgVersion: radio("awgVersion"), endpointPort: val("endpointPort"), endpointIp: val("endpointIp"),
    dnsServer: val("dnsServer"), dohPreset: val("dohPreset"), i1Preset: val("i1Preset"),
    customI1Domain: val("customI1Domain"), configName: val("configName"),
    mtu: val("mtu"), keepalive: val("keepalive"), includeIpv6: $<HTMLInputElement>("includeIpv6").checked,
    splitTargets: selectedSplitTargets(),
    archProfile: radio("archProfile"), archIntensity: radio("archIntensity"),
    archJunk: val("archJunk"), archHost: val("archHost"), archBrowser: val("archBrowser"),
  };
}

function applySettings(s: Settings): void {
  const sel = (id: string, v?: string) => {
    if (v == null) return;
    const el = $<HTMLSelectElement>(id);
    if ([...el.options].some((o) => o.value === v)) el.value = v;
  };
  for (const [name, v] of [["configType", s.configType], ["obfsProfile", s.obfsProfile], ["splitMode", s.splitMode],
    ["awgVersion", s.awgVersion], ["archProfile", s.archProfile], ["archIntensity", s.archIntensity]] as const) {
    if (v) setRadio(name, v);
  }
  sel("endpointPort", s.endpointPort); sel("endpointIp", s.endpointIp); sel("dnsServer", s.dnsServer);
  sel("dohPreset", s.dohPreset); sel("i1Preset", s.i1Preset); sel("archBrowser", s.archBrowser);
  if (s.customI1Domain != null) $<HTMLInputElement>("customI1Domain").value = s.customI1Domain;
  if (s.configName != null) $<HTMLInputElement>("configName").value = s.configName;
  if (s.mtu) $<HTMLInputElement>("mtu").value = s.mtu;
  if (s.keepalive) $<HTMLInputElement>("keepalive").value = s.keepalive;
  if (s.archJunk) $<HTMLInputElement>("archJunk").value = s.archJunk;
  if (s.archHost != null) $<HTMLInputElement>("archHost").value = s.archHost;
  if (typeof s.includeIpv6 === "boolean") $<HTMLInputElement>("includeIpv6").checked = s.includeIpv6;
  if (Array.isArray(s.splitTargets)) setSplitTargets(s.splitTargets);
}

// ─────────────── Init ───────────────
function init(): void {
  buildSelects();
  buildArchTiles();
  buildSplitGrid();
  buildClientRows();
  applyTheme(loadJson<string>("warpgen.theme", "dark") === "dark");
  applySettings(loadJson<Settings>(SETTINGS_KEY, {}));
  setText("siteVersion", `v${__APP_VERSION__}`);
  setText("platformChip", currentOs() === "windows" ? "Windows" : currentOs() === "macos" ? "macOS" : "Linux");
  setText("archJunkVal", val("archJunk"));
  renderHistory();
  updateChainSize();
  updateVisibility();
  updateSplitCount();

  document.querySelectorAll<HTMLElement>(".nav-item").forEach((n) =>
    n.addEventListener("click", () => showView(n.dataset.view!)),
  );
  $("themeToggle").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme !== "dark"));

  // Generator reactivity
  for (const id of ["endpointPort", "endpointIp", "dnsServer", "i1Preset", "mtu", "keepalive", "licenseKey", "includeIpv6"]) {
    $(id).addEventListener("change", updateVisibility);
  }
  document.addEventListener("change", (e) => {
    const t = e.target as HTMLElement;
    if (t.matches('input[name="configType"], input[name="splitMode"], input[name="awgVersion"]')) updateVisibility();
    saveJson(SETTINGS_KEY, collectSettings());
  });
  $("archJunk").addEventListener("input", (e) => setText("archJunkVal", (e.target as HTMLInputElement).value));
  $("archGenBtn").addEventListener("click", onArchGenerate);
  $("archClearBtn").addEventListener("click", clearArchitect);

  // Split catalog search
  $("catalogSearch").addEventListener("input", (e) => {
    const q = (e.target as HTMLInputElement).value.trim().toLowerCase();
    $("splitGrid").querySelectorAll<HTMLElement>("label.toggle").forEach((l) => {
      l.style.display = !q || (l.dataset.name ?? "").includes(q) ? "" : "none";
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-preset]").forEach((b) =>
    b.addEventListener("click", () => {
      const kind = b.dataset.preset!;
      setSplitTargets(kind === "clear" ? [] : SPLIT_PRESETS[kind] ?? []);
    }),
  );

  // Result
  $("downloadBtn").addEventListener("click", downloadConfig);
  $("copyBtn").addEventListener("click", (e) => copyText(lastConfig, e.currentTarget as HTMLButtonElement, "Скопировано", "Копировать"));
  $("qrBtn").addEventListener("click", toggleQr);
  $("analyzeThisBtn").addEventListener("click", () => {
    $<HTMLTextAreaElement>("analyzerInput").value = lastConfig;
    showView("analyzer");
    onAnalyze();
  });

  // warpscout
  $("wsScanBtn").addEventListener("click", onScan);
  $("wsImportBtn").addEventListener("click", () => wsRun("import"));
  $("wsJunkBtn").addEventListener("click", () => wsRun("junk"));
  $("wsSniBtn").addEventListener("click", () => wsRun("sni"));
  $("wsStopBtn").addEventListener("click", () => wsAbort?.abort());

  // DPI
  $("dpiStartBtn").addEventListener("click", dpiStart);
  $("dpiStopBtn").addEventListener("click", async () => {
    await winws.stopWinws(dpiLog).catch(() => {});
    dpiSetRunning(false);
  });

  // Import / analyzer
  $("importClashBtn").addEventListener("click", () => onImport(true));
  $("importRawBtn").addEventListener("click", () => onImport(false));
  $("analyzerBtn").addEventListener("click", onAnalyze);
  $("analyzerFromResult").addEventListener("click", () => {
    $<HTMLTextAreaElement>("analyzerInput").value = lastConfig;
    onAnalyze();
  });

  // Tools
  $("checkKeyBtn").addEventListener("click", onCheckKey);
  $("genTestBtn").addEventListener("click", onGenTest);
  $("bfThreads").addEventListener("input", (e) => setText("bfThreadsVal", (e.target as HTMLInputElement).value));
  $("bfStartBtn").addEventListener("click", onBruteforce);
  $("bfStopBtn").addEventListener("click", () => bfAbort?.abort());
  $("proxyCheckBtn").addEventListener("click", onCheckProxies);
  $("proxyStopBtn").addEventListener("click", () => proxyAbort?.abort());
  $("proxyClearBtn").addEventListener("click", () => ($<HTMLTextAreaElement>("bfProxies").value = ""));
  document.querySelectorAll<HTMLButtonElement>("[data-proxy]").forEach((b) =>
    b.addEventListener("click", () => loadProxies(b.dataset.proxy!)),
  );
  $("copyBfBtn").addEventListener("click", (e) =>
    copyText($<HTMLTextAreaElement>("bfValidKeys").value, e.currentTarget as HTMLButtonElement, "Скопировано", "Копировать ключи"),
  );

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") void onGenerate();
  });

  if (currentOs() === "windows") {
    show($("navDpi"), true);
    void winws.winwsRunning().then(dpiSetRunning);
  }
  void checkWarpscout();
  showView("generate");
  // Hint text is data for the design; expose it for future inline help.
  void AWG_PARAM_HINTS;
}

init();
