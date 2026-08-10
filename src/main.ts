import { generateConfig } from "./core/generate";
import { I1_GROUPS, DEFAULT_I1_KEY } from "./core/i1";
import { splitTargetList } from "./core/split";
import { checkLicense, generateTestLicense, generateWarpKey } from "./core/license";
import { runProxyCheck, runBruteforce } from "./core/proxy";
import { httpFetch } from "./core/http";
import * as ws from "./core/warpscout";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { downloadDir, join } from "@tauri-apps/api/path";
import { qrDataUrl } from "./core/qr";
import { clashFromNode, parseImportedConf, normalizeImportedConfig } from "./core/clash";
import { clientList, downloadUrl, currentOs } from "./core/client-downloads";
import { open as shellOpen } from "@tauri-apps/plugin-shell";
import * as winws from "./core/winws";
import { loadJson, saveJson, addHistory, loadHistory, deleteHistory, clearHistory, updateHistoryTag } from "./core/store";

// ─────────────── DOM helpers ───────────────
function $<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} missing`);
  return el as T;
}
const val = (id: string) => ($<HTMLInputElement>(id)).value;
const setText = (id: string, text: string): void => {
  $(id).textContent = text;
};
const show = (el: HTMLElement, on: boolean) => el.classList.toggle("hidden", !on);
const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c] || c);

let lastConfigType: "amnezia" | "wireguard" | "clash" = "amnezia";

// ─────────────── View navigation ───────────────
function showView(name: string): void {
  document.querySelectorAll<HTMLElement>(".view").forEach((v) => v.classList.toggle("active", v.dataset.view === name));
  document.querySelectorAll<HTMLElement>(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === name));
  document.querySelector(".content")?.scrollTo({ top: 0 });
}

// ─────────────── Build dynamic controls ───────────────
function buildI1Select(): void {
  const sel = $<HTMLSelectElement>("i1Preset");
  for (const group of I1_GROUPS) {
    const og = document.createElement("optgroup");
    og.label = group.label;
    for (const opt of group.options) {
      const o = document.createElement("option");
      o.value = opt.key;
      o.textContent = opt.label;
      og.appendChild(o);
    }
    sel.appendChild(og);
  }
  sel.value = DEFAULT_I1_KEY;
}

function buildSplitGrid(): void {
  const grid = $("splitGrid");
  for (const { key, label } of splitTargetList()) {
    const l = document.createElement("label");
    l.className = "check";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.dataset.split = key;
    const span = document.createElement("span");
    span.textContent = label;
    l.append(cb, span);
    grid.appendChild(l);
  }
}

const SPLIT_PRESETS: Record<string, string[]> = {
  social: ["discord", "youtube", "x_com", "instagram", "twitch", "telegram", "whatsapp", "viber", "tiktok", "ipcheck_2ip", "speedtest", "fast_com", "whoer"],
  gaming: ["steam", "faceit", "apex_legends", "ea_app", "battle_net", "cs2", "hearthstone", "pubg"],
  ai: ["chatgpt", "claude_ai", "gemini", "grok"],
};

function buildClientButtons(): void {
  const box = $("clientBtns");
  for (const { key, title } of clientList()) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "chip";
    b.textContent = `⬇ ${title}`;
    b.addEventListener("click", () => {
      const url = downloadUrl(key);
      if (url) void shellOpen(url);
    });
    box.appendChild(b);
  }
}

function splitCheckboxes(): HTMLInputElement[] {
  return Array.from(document.querySelectorAll<HTMLInputElement>("input[data-split]"));
}
function selectedSplitTargets(): string[] {
  return splitCheckboxes().filter((c) => c.checked).map((c) => c.dataset.split!);
}
function setSplitTargets(keys: string[]): void {
  const set = new Set(keys);
  for (const c of splitCheckboxes()) c.checked = set.has(c.dataset.split!);
}

// ─────────────── Visibility toggles ───────────────
function updateConfigTypeVisibility(): void {
  const isAmnezia = val("configType") === "amnezia";
  document.querySelectorAll<HTMLElement>(".amnezia-only").forEach((el) => show(el, isAmnezia));
  $("connectionGrid").style.gridTemplateColumns = isAmnezia ? "" : "1fr";
}
function updateSplitVisibility(): void {
  show($("splitBox"), val("splitMode") === "selective");
}
function updateCustomI1Visibility(): void {
  show($("customI1Domain"), val("i1Preset") === "custom");
}

// ─────────────── Generate ───────────────
async function onGenerate(): Promise<void> {
  const btn = $<HTMLButtonElement>("generateBtn");
  const errBox = $("errorBox");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Генерируем…';
  errBox.style.display = "none";

  try {
    const keepaliveRaw = parseInt(val("keepalive"), 10);
    const result = await generateConfig({
      licenseKey: val("licenseKey"),
      configType: val("configType") === "wireguard" ? "wireguard" : "amnezia",
      obfsProfile: val("obfsProfile"),
      endpointPort: val("endpointPort"),
      endpointIp: val("endpointIp"),
      i1Preset: val("i1Preset"),
      customI1Domain: val("customI1Domain"),
      dnsServer: val("dnsServer"),
      splitMode: val("splitMode") === "selective" ? "selective" : "full",
      splitTargets: selectedSplitTargets(),
      mtu: parseInt(val("mtu"), 10) || 1280,
      persistentKeepalive: keepaliveRaw === 0 ? null : keepaliveRaw,
      includeIpv6: ($<HTMLInputElement>("includeIpv6")).checked,
    });

    $<HTMLTextAreaElement>("configOutput").value = result.config;
    lastConfigType = result.configType;

    const badge = $("accountBadge");
    const plus = result.accountType === "warp_plus" || result.accountType === "unlimited";
    badge.textContent = plus ? "WARP+" : "Free";
    badge.className = `badge ${plus ? "badge-plus" : "badge-free"}`;

    let status = `Endpoint: ${result.endpoint} · ${result.configType === "wireguard" ? "WireGuard" : "Amnezia"}`;
    if (result.licenseError) status += ` · ⚠ Ключ: ${result.licenseError}`;
    if (result.splitTunnel.mode === "selective") {
      status += ` · Split: ${result.splitTunnel.selectedTargets.length} сервисов / ${result.splitTunnel.resolvedAllowedIps} маршрутов`;
      if (result.splitTunnel.unresolvedDomains.length) status += ` · DNS miss: ${result.splitTunnel.unresolvedDomains.length}`;
    }
    setText("resultStatus", status);
    showView("result");
    pushHistory(result.configType, result.endpoint, result.config);
  } catch (err) {
    errBox.textContent = "⚠ " + (err instanceof Error ? err.message : String(err));
    errBox.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = "Сгенерировать конфиг";
  }
}

function resetDefaults(): void {
  $<HTMLInputElement>("licenseKey").value = "";
  $<HTMLSelectElement>("configType").value = "amnezia";
  $<HTMLSelectElement>("obfsProfile").value = "1";
  $<HTMLSelectElement>("endpointPort").value = "2408";
  $<HTMLSelectElement>("endpointIp").value = "auto";
  $<HTMLSelectElement>("dnsServer").value = "malw_link";
  $<HTMLSelectElement>("i1Preset").value = DEFAULT_I1_KEY;
  $<HTMLSelectElement>("splitMode").value = "full";
  $<HTMLInputElement>("mtu").value = "1280";
  $<HTMLInputElement>("keepalive").value = "25";
  $<HTMLInputElement>("includeIpv6").checked = true;
  setSplitTargets([]);
  updateConfigTypeVisibility();
  updateSplitVisibility();
  updateCustomI1Visibility();
}

async function downloadConfig(): Promise<void> {
  const text = $<HTMLTextAreaElement>("configOutput").value;
  const name =
    lastConfigType === "clash"
      ? "WARP_Clash.yaml"
      : lastConfigType === "wireguard"
        ? "WARP_WireGuard.conf"
        : "WARP_AmneziaWG.conf";
  // Write straight to Downloads via the fs plugin — reliable on every platform
  // (WKWebView on macOS doesn't honour <a download> for blobs).
  try {
    const path = await join(await downloadDir(), name);
    await writeTextFile(path, text);
    setText("resultStatus", `Сохранено: ${path}`);
    return;
  } catch {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

async function copyText(text: string, btn: HTMLButtonElement, done: string, normal: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = done;
    setTimeout(() => (btn.textContent = normal), 2000);
  } catch {
    btn.textContent = "Ошибка :(";
  }
}

function toggleQr(): void {
  const text = $<HTMLTextAreaElement>("configOutput").value;
  if (!text) return;
  const wrap = $("qrWrap");
  if (!wrap.classList.contains("hidden")) {
    show(wrap, false);
    return;
  }
  try {
    $<HTMLImageElement>("qrImg").src = qrDataUrl(text);
    show(wrap, true);
  } catch {
    setText("resultStatus", "Конфиг слишком большой для QR — используйте «Скачать».");
  }
}

// Import a .conf / vpn:// link — either convert to Clash YAML or just unpack it.
async function onImport(toClash: boolean): Promise<void> {
  const input = val("importInput").trim();
  if (!input) return;
  const btn = $<HTMLButtonElement>(toClash ? "importClashBtn" : "importRawBtn");
  btn.disabled = true;
  try {
    const raw = await normalizeImportedConfig(input);
    let output: string;
    if (toClash) {
      output = clashFromNode(parseImportedConf(raw));
      lastConfigType = "clash";
    } else {
      output = raw;
      lastConfigType = /(\bJc\s*=|\bI1\s*=)/.test(raw) ? "amnezia" : "wireguard";
    }
    $<HTMLTextAreaElement>("configOutput").value = output;
    $("accountBadge").textContent = "import";
    $("accountBadge").className = "badge badge-free";
    setText("resultStatus", toClash ? "Импортировано → Clash YAML" : "Распаковано в .conf");
    setText("importStatus", "✓ Готово.");
    show($("qrWrap"), false);
    showView("result");
    pushHistory(lastConfigType, "", output);
  } catch (err) {
    setText("importStatus", `Ошибка: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    btn.disabled = false;
  }
}

// ─────────────── warpscout ───────────────
let wsAbort: AbortController | null = null;

function wsLog(line: string): void {
  const log = $("wsLog");
  show(log, true);
  log.textContent += line + "\n";
  log.scrollTop = log.scrollHeight;
}
function wsBusy(on: boolean): void {
  for (const id of ["wsScanBtn", "wsImportBtn", "wsJunkBtn", "wsSniBtn"]) $<HTMLButtonElement>(id).disabled = on;
  $<HTMLButtonElement>("wsStopBtn").disabled = !on;
}
function wsFilters(): { country?: string; node?: string } {
  const f = val("wsFilter").trim();
  if (!f) return {};
  // Country codes are 2-letter; anything else we treat as a node code.
  return /^[A-Za-z]{2}(,[A-Za-z]{2})*$/.test(f) ? { country: f.toUpperCase() } : { node: f.toUpperCase() };
}

function applyEndpoint(endpoint: string): void {
  const m = endpoint.match(/^(.+):(\d+)$/);
  if (!m) return;
  const [, ip, port] = m;
  const ipSel = $<HTMLSelectElement>("endpointIp");
  if (![...ipSel.options].some((o) => o.value === ip)) ipSel.add(new Option(`${ip} (warpscout)`, ip));
  ipSel.value = ip;
  const portSel = $<HTMLSelectElement>("endpointPort");
  if (![...portSel.options].some((o) => o.value === port)) portSel.add(new Option(port, port));
  portSel.value = port;
}

function flag(cc: string): string {
  if (!/^[A-Za-z]{2}$/.test(cc)) return "";
  return [...cc.toUpperCase()].map((c) => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65)).join("");
}
function pingColor(ms: number): string {
  return ms < 60 ? "var(--success)" : ms < 150 ? "var(--warn)" : "var(--danger)";
}

function renderScanTable(rows: ws.ScanRow[]): void {
  const box = $("wsResults");
  box.textContent = "";
  show(box, rows.length > 0);
  if (!rows.length) return;

  const head = document.createElement("div");
  head.className = "ws-row head";
  head.innerHTML =
    "<span>Endpoint</span><span class='ping'>Ping</span><span>Страна</span><span>Нода</span><span class='loc'>Локация</span>";

  const scroll = document.createElement("div");
  scroll.className = "ws-scroll";
  rows.forEach((r, i) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "ws-row" + (i === 0 ? " sel" : "");
    row.innerHTML =
      `<span class="ep">${esc(r.endpoint)}</span>` +
      `<span class="ping" style="color:${pingColor(r.ping)}">${r.ping}ms</span>` +
      `<span>${flag(r.country)} ${esc(r.country)}</span>` +
      `<span>${esc(r.node)}</span>` +
      `<span class="loc">${esc(r.location)}</span>`;
    row.addEventListener("click", () => {
      scroll.querySelectorAll(".ws-row").forEach((el) => el.classList.remove("sel"));
      row.classList.add("sel");
      applyEndpoint(r.endpoint);
      setText("wsStatus", `✓ Выбран ${r.endpoint} · ${r.ping}ms · ${r.location} — подставлен в «Генератор».`);
    });
    scroll.appendChild(row);
  });
  box.append(head, scroll);
}

async function onScan(): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  wsBusy(true);
  show($("wsResults"), false);
  show($("wsLog"), false);
  setText("wsStatus", "Сканирование сети… (до ~минуты)");
  try {
    const { rows } = await ws.scanEndpoints({
      proto: val("wsProto") as ws.Proto,
      ...wsFilters(),
      speed: $<HTMLInputElement>("wsSpeed").checked,
      tunPing: $<HTMLInputElement>("wsTunPing").checked,
      // Show only progress phases in the status line — the table is the result.
      onLine: (line) => {
        if (/phase|probing|verifying|reachable/i.test(line)) setText("wsStatus", line.trim());
      },
      signal: wsAbort.signal,
    });
    if (!rows.length) {
      setText("wsStatus", "Рабочих endpoint'ов не найдено.");
      return;
    }
    renderScanTable(rows);
    applyEndpoint(rows[0].endpoint);
    setText(
      "wsStatus",
      `✓ Найдено ${rows.length}. Быстрейший ${rows[0].endpoint} (${rows[0].ping}ms, ${rows[0].location}) подставлен. Кликните строку — выбрать другой.`,
    );
  } catch (err) {
    setText("wsStatus", wsAbort?.signal.aborted ? "⏹ Остановлено." : `⚠ ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    wsBusy(false);
    wsAbort = null;
  }
}

async function wsRun(kind: "scan" | "import" | "junk" | "sni"): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  wsBusy(true);
  setText("wsStatus", "Работает warpscout… (может занять до минуты)");
  const proto = val("wsProto") as ws.Proto;
  const onLine: ws.LineSink = (line) => wsLog(line);
  const scanOpts: ws.ScanParams = {
    proto,
    ...wsFilters(),
    speed: $<HTMLInputElement>("wsSpeed").checked,
    tunPing: $<HTMLInputElement>("wsTunPing").checked,
    onLine,
    signal: wsAbort.signal,
  };
  try {
    if (kind === "scan") {
      const { endpoint } = await ws.scanBest(scanOpts);
      applyEndpoint(endpoint);
      setText("wsStatus", `✓ Лучший endpoint: ${endpoint} — подставлен в форму.`);
    } else if (kind === "import") {
      const { config, endpoint } = await ws.importConfig(scanOpts);
      $<HTMLTextAreaElement>("configOutput").value = config;
      lastConfigType = proto === "wg" ? "wireguard" : "amnezia";
      $("accountBadge").textContent = "warpscout";
      $("accountBadge").className = "badge badge-free";
      setText("resultStatus", `Конфиг из warpscout${endpoint ? ` · ${endpoint}` : ""}`);
      showView("result");
      pushHistory(lastConfigType, endpoint || "", config);
      setText("wsStatus", "✓ Конфиг импортирован из warpscout.");
    } else if (kind === "junk") {
      await ws.findJunk({ proto, onLine, signal: wsAbort.signal });
      setText("wsStatus", "✓ find-junk завершён — смотрите лог для параметров.");
    } else {
      await ws.findSni({ proto, onLine, signal: wsAbort.signal });
      setText("wsStatus", "✓ find-sni завершён — смотрите лог.");
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    setText("wsStatus", wsAbort?.signal.aborted ? "⏹ Остановлено." : `⚠ ${msg}`);
  } finally {
    wsBusy(false);
    wsAbort = null;
  }
}

async function checkWarpscout(): Promise<void> {
  try {
    const v = await ws.warpscoutVersion();
    setText("wsStatus", `warpscout ${v} готов.`);
    ($("wsMissing")).style.display = "none";
  } catch (err) {
    // Surface the real reason instead of just hiding — buttons stay enabled so a
    // manual scan also reports what actually goes wrong.
    const msg = err instanceof Error ? err.message : String(err);
    const box = $("wsMissing");
    box.style.display = "block";
    box.textContent = `warpscout недоступен: ${msg}`;
    console.error("warpscout probe failed:", err);
  }
}

// ─────────────── Secret tools: license ───────────────
async function onCheckKey(): Promise<void> {
  const key = val("secretKey").trim();
  const btn = $<HTMLButtonElement>("checkKeyBtn");
  if (!key) return setText("secretStatus", "Введите ключ для проверки.");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Проверяем…';
  try {
    const r = await checkLicense(key);
    const ref = r.referralCount !== null ? ` · referrals: ${r.referralCount}` : "";
    setText("secretStatus", `Ключ ${r.valid ? "валидный" : "невалидный"} · type: ${r.accountType}${ref} · ${r.message}`);
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
  btn.innerHTML = '<span class="spinner"></span>…';
  try {
    const r = await generateTestLicense();
    $<HTMLInputElement>("secretKey").value = r.license;
    setText("secretStatus", `TEST ключ · type: ${r.accountType} · авто-проверка…`);
    await onCheckKey();
  } catch (err) {
    setText("secretStatus", `Ошибка: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Сген. TEST ключ";
  }
}

// ─────────────── Secret tools: proxies + bruteforce ───────────────
const PROXY_SOURCES: Record<string, { url: string; prefix: string }> = {
  mono_http: { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", prefix: "" },
  mono_socks4: { url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", prefix: "socks4://" },
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
    const text = await res.text();
    return text
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
  const status = $("proxyLoadStatus");
  status.textContent = "⏳ Загружаем…";
  const ta = $<HTMLTextAreaElement>("bfProxies");
  let lines: string[];
  if (which === "all") {
    const results = await Promise.all(Object.keys(PROXY_SOURCES).map(fetchProxySource));
    results.push(ta.value.split("\n"));
    lines = [...new Set(results.flat().map((s) => s.trim()).filter(Boolean))];
  } else {
    lines = await fetchProxySource(which);
  }
  if (!lines.length) return void (status.textContent = "Ошибка загрузки");
  ta.value = lines.join("\n");
  status.textContent = `✓ ${lines.length} прокси`;
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
  bar.style.display = "block";

  const valid = await runProxyCheck(proxies, {
    concurrency: 200,
    signal: proxyAbort.signal,
    onProgress: ({ checked, valid, total }) => {
      (bar.firstElementChild as HTMLElement).style.width = `${Math.round((checked / total) * 100)}%`;
      setText("proxyCheckStatus", `Проверено ${checked}/${total} · рабочих ${valid}`);
    },
  });
  ta.value = valid.join("\n");
  setText("proxyCheckStatus", `✓ Готово: ${valid.length} рабочих прокси`);
  btn.disabled = false;
  $<HTMLButtonElement>("proxyStopBtn").disabled = true;
  proxyAbort = null;
}

let bfAbort: AbortController | null = null;
function bfLog(html: string): void {
  const log = $("bfLog");
  show(log, true);
  log.insertAdjacentHTML("beforeend", html + "\n");
  log.scrollTop = log.scrollHeight;
}

async function onBruteforce(): Promise<void> {
  const count = Math.min(Math.max(parseInt(val("bfCount"), 10) || 100, 1), 10000);
  const concurrency = parseInt(val("bfThreads"), 10) || 30;
  const proxies = val("bfProxies").trim().split("\n").map((l) => l.trim()).filter(Boolean);
  const keys = Array.from({ length: count }, generateWarpKey);

  bfAbort = new AbortController();
  const startBtn = $<HTMLButtonElement>("bfStartBtn");
  startBtn.disabled = true;
  startBtn.innerHTML = '<span class="spinner"></span>Проверяем…';
  $<HTMLButtonElement>("bfStopBtn").disabled = false;
  $("bfProgress").style.display = "block";
  $("bfLog").textContent = "";
  $<HTMLTextAreaElement>("bfValidKeys").value = "";
  show($("bfValidWrap"), false);

  const bar = $("bfProgress").firstElementChild as HTMLElement;
  const validKeys = await runBruteforce(keys, proxies, {
    concurrency,
    signal: bfAbort.signal,
    onEvent: (e) => {
      bar.style.width = `${Math.round((e.checked / e.total) * 100)}%`;
      const alive = proxies.length ? ` · живых прокси ${e.aliveCount}` : "";
      setText("bfCounters", `Проверено ${e.checked}/${e.total} · найдено ${e.found}${alive}`);
      if (e.type === "valid") {
        bfLog(`<span style="color:var(--success)">✅ VALID [${esc(e.accountType || "")}]: ${esc(e.key)}</span>`);
        const ta = $<HTMLTextAreaElement>("bfValidKeys");
        ta.value = ta.value ? `${ta.value}\n${e.key}` : e.key;
        show($("bfValidWrap"), true);
      } else if (e.checked % 5 === 0 || e.error === "Invalid license") {
        bfLog(`<span style="color:var(--muted)">✗ ${esc(e.key)}${e.error ? ` (${esc(e.error)})` : ""}</span>`);
      }
    },
  });

  setText("bfCounters", `Готово: найдено WARP+ ключей ${validKeys.length}`);
  startBtn.disabled = false;
  startBtn.textContent = "⚡ Сгенерировать и проверить";
  $<HTMLButtonElement>("bfStopBtn").disabled = true;
  bfAbort = null;
}

// ─────────────── DPI bypass (winws, Windows) ───────────────
let dpiBusy = false;

function dpiLog(line: string): void {
  const l = $("dpiLog");
  show(l, true);
  l.textContent += line + "\n";
  l.scrollTop = l.scrollHeight;
}

function dpiSetRunning(on: boolean): void {
  $<HTMLButtonElement>("dpiStartBtn").disabled = on;
  $<HTMLButtonElement>("dpiStopBtn").disabled = !on;
  setText("dpiStatus", on ? "🟢 DPI-обход активен." : "⚪ Выключено.");
}

async function dpiStart(): Promise<void> {
  if (dpiBusy) return;
  dpiBusy = true;
  $<HTMLButtonElement>("dpiStartBtn").disabled = true;
  setText("dpiStatus", "Запуск… (подтвердите UAC)");
  try {
    await winws.startWinws(
      { ports: val("dpiPorts"), fakeTtl: parseInt(val("dpiTtl"), 10) || 0, quic: $<HTMLInputElement>("dpiQuic").checked },
      dpiLog,
    );
    dpiSetRunning(true);
  } catch (err) {
    setText("dpiStatus", `⚠ ${err instanceof Error ? err.message : String(err)}`);
    $<HTMLButtonElement>("dpiStartBtn").disabled = false;
  } finally {
    dpiBusy = false;
  }
}

async function dpiStop(): Promise<void> {
  try {
    await winws.stopWinws(dpiLog);
  } catch {
    /* ignore */
  }
  dpiSetRunning(false);
}

async function initDpi(): Promise<void> {
  if (currentOs() !== "windows") return;
  show($("navDpi"), true);
  $("dpiStartBtn").addEventListener("click", dpiStart);
  $("dpiStopBtn").addEventListener("click", dpiStop);
  dpiSetRunning(await winws.winwsRunning());
}

// ─────────────── Settings persistence ───────────────
const SETTINGS_KEY = "warpgen.settings";

interface Settings {
  configType?: string;
  obfsProfile?: string;
  endpointPort?: string;
  endpointIp?: string;
  dnsServer?: string;
  i1Preset?: string;
  customI1Domain?: string;
  splitMode?: string;
  splitTargets?: string[];
  mtu?: string;
  keepalive?: string;
  includeIpv6?: boolean;
}

function collectSettings(): Settings {
  return {
    configType: val("configType"),
    obfsProfile: val("obfsProfile"),
    endpointPort: val("endpointPort"),
    endpointIp: val("endpointIp"),
    dnsServer: val("dnsServer"),
    i1Preset: val("i1Preset"),
    customI1Domain: val("customI1Domain"),
    splitMode: val("splitMode"),
    splitTargets: selectedSplitTargets(),
    mtu: val("mtu"),
    keepalive: val("keepalive"),
    includeIpv6: $<HTMLInputElement>("includeIpv6").checked,
  };
}

function applySettings(s: Settings): void {
  const setSel = (id: string, v?: string) => {
    if (v == null) return;
    const el = $<HTMLSelectElement>(id);
    if ([...el.options].some((o) => o.value === v)) el.value = v;
  };
  setSel("configType", s.configType);
  setSel("obfsProfile", s.obfsProfile);
  setSel("endpointPort", s.endpointPort);
  setSel("endpointIp", s.endpointIp);
  setSel("dnsServer", s.dnsServer);
  setSel("i1Preset", s.i1Preset);
  setSel("splitMode", s.splitMode);
  if (s.customI1Domain != null) $<HTMLInputElement>("customI1Domain").value = s.customI1Domain;
  if (s.mtu != null) $<HTMLInputElement>("mtu").value = s.mtu;
  if (s.keepalive != null) $<HTMLInputElement>("keepalive").value = s.keepalive;
  if (typeof s.includeIpv6 === "boolean") $<HTMLInputElement>("includeIpv6").checked = s.includeIpv6;
  if (Array.isArray(s.splitTargets)) setSplitTargets(s.splitTargets);
}

const saveSettings = () => saveJson(SETTINGS_KEY, collectSettings());

// ─────────────── Config history ───────────────
function coerceType(t: string): "amnezia" | "wireguard" | "clash" {
  return t === "clash" ? "clash" : t === "wireguard" ? "wireguard" : "amnezia";
}

function chip(label: string, fn: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.className = "chip";
  b.textContent = label;
  b.addEventListener("click", fn);
  return b;
}

function renderHistory(): void {
  const list = loadHistory();
  const box = $("historyList");
  box.textContent = "";
  show($("historyEmpty"), list.length === 0);
  for (const e of list) {
    const row = document.createElement("div");
    row.className = "split-box";
    row.style.cssText = "display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:8px;";

    const info = document.createElement("span");
    info.style.cssText = "flex:1; min-width:150px; font-size:12px;";
    info.innerHTML = `<b>${esc(e.configType)}</b> · ${esc(e.endpoint || "—")} · <span style="color:var(--muted)">${esc(new Date(e.ts).toLocaleString())}</span>`;

    const tag = document.createElement("input");
    tag.type = "text";
    tag.placeholder = "тег";
    tag.value = e.tag;
    tag.style.cssText = "width:100px; padding:6px 8px; font-size:12px;";
    tag.addEventListener("change", () => updateHistoryTag(e.id, tag.value));

    const load = chip("Загрузить", () => {
      $<HTMLTextAreaElement>("configOutput").value = e.config;
      lastConfigType = coerceType(e.configType);
      $("accountBadge").textContent = e.tag || "история";
      $("accountBadge").className = "badge badge-free";
      setText("resultStatus", `Из истории · ${e.endpoint || "—"}`);
      show($("qrWrap"), false);
      showView("result");
    });
    const copy = chip("⎘", () => void navigator.clipboard.writeText(e.config).catch(() => {}));
    const del = chip("✕", () => {
      deleteHistory(e.id);
      renderHistory();
    });

    row.append(info, tag, load, copy, del);
    box.appendChild(row);
  }
}

function pushHistory(configType: string, endpoint: string, config: string): void {
  addHistory({ configType, endpoint, config });
  renderHistory();
}

// ─────────────── Wire up ───────────────
function init(): void {
  buildI1Select();
  buildSplitGrid();
  buildClientButtons();
  applySettings(loadJson<Settings>(SETTINGS_KEY, {}));
  renderHistory();
  setText("siteVersion", `v${__APP_VERSION__}`);

  $("generateBtn").addEventListener("click", onGenerate);
  $("resetBtn").addEventListener("click", resetDefaults);
  $("downloadBtn").addEventListener("click", downloadConfig);
  $("copyBtn").addEventListener("click", (e) =>
    copyText($<HTMLTextAreaElement>("configOutput").value, e.currentTarget as HTMLButtonElement, "✓ Скопировано!", "⎘ Копировать"),
  );
  $("qrBtn").addEventListener("click", toggleQr);
  $("importClashBtn").addEventListener("click", () => onImport(true));
  $("importRawBtn").addEventListener("click", () => onImport(false));

  $("configType").addEventListener("change", updateConfigTypeVisibility);
  $("splitMode").addEventListener("change", updateSplitVisibility);
  $("i1Preset").addEventListener("change", updateCustomI1Visibility);
  $("advToggle").addEventListener("click", () => show($("advBox"), $("advBox").classList.contains("hidden")));
  document.querySelectorAll<HTMLElement>(".nav-item").forEach((n) => n.addEventListener("click", () => showView(n.dataset.view!)));

  document.querySelectorAll<HTMLButtonElement>("[data-preset]").forEach((b) =>
    b.addEventListener("click", () => {
      const kind = b.dataset.preset!;
      if (kind === "clear") setSplitTargets([]);
      else if (kind === "all") setSplitTargets(splitCheckboxes().map((c) => c.dataset.split!));
      else setSplitTargets(SPLIT_PRESETS[kind] || []);
    }),
  );

  $("wsScanBtn").addEventListener("click", onScan);
  $("wsImportBtn").addEventListener("click", () => wsRun("import"));
  $("wsJunkBtn").addEventListener("click", () => wsRun("junk"));
  $("wsSniBtn").addEventListener("click", () => wsRun("sni"));
  $("wsStopBtn").addEventListener("click", () => wsAbort?.abort());

  $("checkKeyBtn").addEventListener("click", onCheckKey);
  $("genTestBtn").addEventListener("click", onGenTest);
  $("bfThreads").addEventListener("input", (e) => setText("bfThreadsVal", (e.target as HTMLInputElement).value));
  $("bfStartBtn").addEventListener("click", onBruteforce);
  $("bfStopBtn").addEventListener("click", () => bfAbort?.abort());
  $("proxyClearBtn").addEventListener("click", () => ($<HTMLTextAreaElement>("bfProxies").value = ""));
  $("proxyCheckBtn").addEventListener("click", onCheckProxies);
  $("proxyStopBtn").addEventListener("click", () => proxyAbort?.abort());
  document.querySelectorAll<HTMLButtonElement>("[data-proxy]").forEach((b) =>
    b.addEventListener("click", () => loadProxies(b.dataset.proxy!)),
  );

  $("copyBfBtn").addEventListener("click", (e) =>
    copyText($<HTMLTextAreaElement>("bfValidKeys").value, e.currentTarget as HTMLButtonElement, "✓ Скопировано!", "⎘ Копировать ключи"),
  );

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") void onGenerate();
  });
  document.addEventListener("change", saveSettings);
  $("historyClearBtn").addEventListener("click", () => {
    clearHistory();
    renderHistory();
  });

  updateConfigTypeVisibility();
  updateSplitVisibility();
  updateCustomI1Visibility();
  void checkWarpscout();
  void initDpi();
}

init();
