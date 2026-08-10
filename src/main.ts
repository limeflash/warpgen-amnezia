import { generateConfig } from "./core/generate";
import { I1_GROUPS, DEFAULT_I1_KEY } from "./core/i1";
import { splitTargetList } from "./core/split";
import { checkLicense, generateTestLicense, generateWarpKey } from "./core/license";
import { runProxyCheck, runBruteforce } from "./core/proxy";
import { httpFetch } from "./core/http";
import * as ws from "./core/warpscout";

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

let lastConfigType: "amnezia" | "wireguard" = "amnezia";

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
    l.className = "split-item";
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
};

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
  const isAmnezia = val("configType") !== "wireguard";
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
  show($("resultCard"), false);

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
    show($("resultCard"), true);
    $("resultCard").scrollIntoView({ behavior: "smooth", block: "start" });
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

function downloadConfig(): void {
  const text = $<HTMLTextAreaElement>("configOutput").value;
  const name = lastConfigType === "wireguard" ? "WARP_WireGuard.conf" : "WARP_AmneziaWG.conf";
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
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

async function wsRun(kind: "scan" | "import" | "junk" | "sni"): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  wsBusy(true);
  setText("wsStatus", "Работает warpscout… (может занять до минуты)");
  const proto = val("wsProto") as ws.Proto;
  const onLine: ws.LineSink = (line) => wsLog(line);
  try {
    if (kind === "scan") {
      const { endpoint } = await ws.scanBest({ proto, ...wsFilters(), onLine, signal: wsAbort.signal });
      applyEndpoint(endpoint);
      setText("wsStatus", `✓ Лучший endpoint: ${endpoint} — подставлен в форму.`);
    } else if (kind === "import") {
      const { config, endpoint } = await ws.importConfig({ proto, ...wsFilters(), onLine, signal: wsAbort.signal });
      $<HTMLTextAreaElement>("configOutput").value = config;
      lastConfigType = proto === "wg" ? "wireguard" : "amnezia";
      $("accountBadge").textContent = "warpscout";
      $("accountBadge").className = "badge badge-free";
      setText("resultStatus", `Конфиг из warpscout${endpoint ? ` · ${endpoint}` : ""}`);
      show($("resultCard"), true);
      $("resultCard").scrollIntoView({ behavior: "smooth", block: "start" });
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
  const ok = await ws.isWarpscoutAvailable();
  if (!ok) {
    ($("wsMissing")).style.display = "block";
    for (const id of ["wsScanBtn", "wsImportBtn", "wsJunkBtn", "wsSniBtn"]) $<HTMLButtonElement>(id).disabled = true;
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

// ─────────────── Secret card reveal (tap logo x7) ───────────────
let tapCount = 0;
let tapTimer: ReturnType<typeof setTimeout> | null = null;
function onLogoTap(): void {
  tapCount++;
  if (tapTimer) clearTimeout(tapTimer);
  tapTimer = setTimeout(() => (tapCount = 0), 3000);
  if (tapCount >= 7) {
    tapCount = 0;
    const card = $("secretCard");
    show(card, card.classList.contains("hidden"));
    if (!card.classList.contains("hidden")) card.scrollIntoView({ behavior: "smooth", block: "center" });
  }
}

// ─────────────── Wire up ───────────────
function init(): void {
  buildI1Select();
  buildSplitGrid();
  setText("siteVersion", `v${__APP_VERSION__}`);

  $("generateBtn").addEventListener("click", onGenerate);
  $("resetBtn").addEventListener("click", resetDefaults);
  $("downloadBtn").addEventListener("click", downloadConfig);
  $("copyBtn").addEventListener("click", (e) =>
    copyText($<HTMLTextAreaElement>("configOutput").value, e.currentTarget as HTMLButtonElement, "✓ Скопировано!", "⎘ Копировать"),
  );

  $("configType").addEventListener("change", updateConfigTypeVisibility);
  $("splitMode").addEventListener("change", updateSplitVisibility);
  $("i1Preset").addEventListener("change", updateCustomI1Visibility);
  $("advToggle").addEventListener("click", () => show($("advBox"), $("advBox").classList.contains("hidden")));
  $("logoTrigger").addEventListener("click", onLogoTap);

  document.querySelectorAll<HTMLButtonElement>("[data-preset]").forEach((b) =>
    b.addEventListener("click", () => {
      const kind = b.dataset.preset!;
      if (kind === "clear") setSplitTargets([]);
      else if (kind === "all") setSplitTargets(splitCheckboxes().map((c) => c.dataset.split!));
      else setSplitTargets(SPLIT_PRESETS[kind] || []);
    }),
  );

  $("wsScanBtn").addEventListener("click", () => wsRun("scan"));
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

  updateConfigTypeVisibility();
  updateSplitVisibility();
  updateCustomI1Visibility();
  void checkWarpscout();
}

init();
