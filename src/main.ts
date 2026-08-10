import { generateConfig } from "./core/generate.ts";
import { I1_GROUPS, DEFAULT_I1_KEY } from "./core/i1.ts";
import { splitTargetList, catalogTargetGroups } from "./core/split.ts";
import { SVC_CATEGORIES, CATEGORY_MAP, designService, svcId, svcHue, tileColor } from "./core/design-services.ts";
import { BRAND_ICONS } from "./core/brand-icons.ts";
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
import { type AwgVersion, compatWarning, recommendedMtu } from "./core/obfuscation.ts";
import { analyzeConfig, type AnalysisResult } from "./core/analyzer.ts";
import { open as shellOpen } from "@tauri-apps/plugin-shell";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { downloadDir, join } from "@tauri-apps/api/path";
import {
  $, must, setText, show, esc, bindGroup, groupValue, setGroup, fillSelect, bindSelect, selectValue,
  setSelect, addSelectOption, bindToggle, setToggle, toggleValue, onClick, inputValue, setInput,
  setBusy,
} from "./ui.ts";

type ConfigKind = "amnezia" | "wireguard" | "clash";

let lastConfigType: ConfigKind = "amnezia";
let lastConfig = "";
/** History id of the config on screen, so «Сохранённые» can mark it active. */
let activeConfigId = 0;
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

  // macOS: the design shows traffic-light dots instead of the Windows cluster.
  if (currentOs() === "macos" && buttons.length) {
    const cluster = buttons[0].parentElement;
    if (cluster) {
      cluster.innerHTML = "";
      cluster.style.gap = "8px";
      for (const [color, act] of [["#ff5f57", actions[2]], ["#febc2e", actions[0]], ["#28c840", actions[1]]] as const) {
        const dot = document.createElement("div");
        dot.style.cssText = `width:12px;height:12px;border-radius:99px;background:${color};cursor:pointer`;
        dot.addEventListener("click", () => void act());
        cluster.appendChild(dot);
      }
      // move the cluster to the left of the bar
      const bar2 = cluster.closest<HTMLElement>('[style*="flex: 0 0 46px"]');
      if (bar2) bar2.insertBefore(cluster, bar2.firstChild);
    }
    return;
  }

  buttons.forEach((b, i) => {
    const act = actions[i];
    if (act) b.addEventListener("click", () => void act());
  });
}

// ─────────────── theme ───────────────
function applyTheme(dark: boolean): void {
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  saveJson("warpgen.theme", dark ? "dark" : "light");

  // The design draws the switch statically — move its knob to match the theme.
  const pill = $("themeToggle")?.querySelector<HTMLElement>('[style*="width: 38px"]');
  const knob = pill?.querySelector<HTMLElement>('[style*="width: 14px"]');
  if (pill) pill.style.background = dark ? "var(--accent)" : "var(--line-2)";
  if (knob) {
    knob.style.transition = "transform .22s cubic-bezier(.4,0,.2,1)";
    knob.style.transform = dark ? "translateX(19px)" : "translateX(0)";
  }
  // sun stroke/fill + moon crescent recolour with the theme, as the design does
  const icon = dark ? "rgba(7,16,38,.55)" : "rgba(255,255,255,.9)";
  const t = $("themeToggle");
  t?.querySelectorAll<SVGElement>("svg *").forEach((n) => {
    if (n.getAttribute("stroke")) n.setAttribute("stroke", icon);
    const f = n.getAttribute("fill");
    if (f && f !== "none") n.setAttribute("fill", icon);
  });
  const moon = t?.querySelector<HTMLElement>('[style*="box-shadow"][style*="inset"]');
  if (moon) moon.style.boxShadow = `inset -3px -2px 0 0 ${icon}`;
}

// ─────────────── views ───────────────
/** Active nav item: 2px accent bar + --sel fill — the design's gradient. */
function showView(name: string): void {
  document.querySelectorAll<HTMLElement>(".view").forEach((v) => v.classList.toggle("active", v.dataset.view === name));
  document.querySelectorAll<HTMLElement>(".nav-item").forEach((n) => {
    const on = n.dataset.view === name;
    n.style.background = on ? "linear-gradient(90deg,var(--accent) 0 2px,var(--sel) 2px 100%)" : "transparent";
    n.style.color = on ? "var(--accent)" : "var(--text-2)";
  });
  document.querySelector<HTMLElement>('[style*="overflow: hidden auto"]')?.scrollTo({ top: 0 });
}

/** Toggle an accent dot on a nav item (result = has config, scout = scanning). */
function navDot(view: string, on: boolean, pulse = false): void {
  const nav = document.querySelector<HTMLElement>(`.nav-item[data-view="${view}"]`);
  if (!nav) return;
  nav.querySelector("[data-nav-dot]")?.remove();
  if (!on) return;
  const dot = document.createElement("div");
  dot.dataset.navDot = "1";
  dot.style.cssText = `margin-left:auto;width:6px;height:6px;border-radius:99px;background:var(--accent)${pulse ? ";animation:breathe 1.3s ease-in-out infinite" : ""}`;
  nav.appendChild(dot);
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
 * Rebinds a row of chips the design draws by caption. The capture sometimes put
 * the group markers on the surrounding section instead of the chips themselves;
 * the selected/unselected looks are taken from the design's own chips.
 */
function repairChips(view: string, group: string, labels: Array<[string, string]>): void {
  const sec = screenEl(view);
  for (const bad of sec.querySelectorAll<HTMLElement>(`[data-group="${group}"]`)) {
    bad.removeAttribute("data-group");
    bad.removeAttribute("data-value");
    if (bad.getAttribute("style") === "null") bad.removeAttribute("style");
  }
  const leaves = [...sec.querySelectorAll<HTMLElement>("div")].filter((d) => !d.children.length);
  const chips = labels.map(([label, value]) => [leaves.find((d) => d.textContent?.trim() === label), value] as const);
  if (chips.some(([el]) => !el)) return;

  const styles = chips.map(([el]) => el!.getAttribute("style") ?? "");
  const on = styles.find((s) => s.includes("var(--accent)")) ?? styles[0];
  const off = styles.find((s) => s !== on) ?? styles[0];
  for (const [el, value] of chips) {
    el!.dataset.group = group;
    el!.dataset.value = value;
    el!.dataset.on = on;
    el!.dataset.off = off;
  }
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
      first.dataset.toggle = "on"; // design default: state.speed = true
    }
  }

  // header subtitle for the scan screen (scoutSub) is live in the design
  const scoutBar = screenEl("scan").querySelector<HTMLElement>('[style*="position: sticky"]');
  scoutBar?.children[0]?.children[1]?.setAttribute("id", "scoutSub");

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
  // the design renders the caption lowercase and uppercases it in CSS
  const header = [...hist.querySelectorAll<HTMLElement>("*")].find(
    (e) => e.textContent?.trim().toLowerCase() === "endpoint" && e.children.length === 0,
  )?.parentElement;
  const rows = header?.parentElement;
  if (rows) {
    $("historyList")?.removeAttribute("id");
    rows.id = "historyList";
    header!.id = "historyHead";
  }

  // Chip rows the capture mis-annotated: the markers landed on section
  // wrappers (with style="null"), so clicking them did nothing.
  repairChips("generate", "archIntensity", [["низкая", "low"], ["средняя", "medium"], ["высокая", "high"]]);
  repairChips("generate", "archBrowser", [
    ["не задавать", ""], ["Chrome", "chrome"], ["Edge", "edge"],
    ["Firefox", "firefox"], ["Safari", "safari"], ["Яндекс", "yandex"],
  ]);

  // history count sits in the nav item, unnamed
  const histNav = document.querySelector<HTMLElement>('.nav-item[data-view="history"]');
  if (histNav && histNav.children.length > 2) histNav.lastElementChild!.id = "historyCount";

  // The generator's hero card, «Параметры» panel and «Дополнительно» header are
  // captured but static; tag them so updateProfile() can drive them live.
  const leaf = (text: string): HTMLElement | undefined =>
    [...gen.querySelectorAll<HTMLElement>("div")].find((d) => !d.children.length && d.textContent?.trim() === text);
  const hero = [...gen.querySelectorAll<HTMLElement>("div")].find((d) => (d.getAttribute("style") || "").includes("var(--hero-bg)"));
  if (hero) {
    hero.querySelector<HTMLElement>('[style*="font-size: 24px"]')?.setAttribute("id", "heroType");
    hero.querySelector<HTMLElement>('[style*="ui-monospace"][style*="opacity: 0.6"], [style*="ui-monospace"][style*="opacity:.6"]')?.setAttribute("id", "heroEp");
    for (const [k, id] of [["Порт", "heroPort"], ["DNS", "heroDns"], ["MTU", "heroMtu"]] as const) {
      [...hero.querySelectorAll<HTMLElement>("div")].find((d) => !d.children.length && d.textContent?.trim() === k)?.nextElementSibling?.setAttribute("id", id);
    }
  }
  for (const [k, id] of [["Маскировка I1", "pMask"], ["Keepalive", "pKeep"], ["IPv6", "pIpv6"], ["Аккаунт", "pAccount"]] as const) {
    const el = [...gen.querySelectorAll<HTMLElement>("div")].find((d) => !d.children.length && d.textContent?.trim() === k);
    el?.nextElementSibling?.setAttribute("id", id);
  }
  // two rows read "Маршрутизация" (nav vs param) — take the one inside the panel
  const routeRows = [...gen.querySelectorAll<HTMLElement>("div")].filter((d) => !d.children.length && d.textContent?.trim() === "Маршрутизация");
  routeRows[routeRows.length - 1]?.nextElementSibling?.setAttribute("id", "pRoute");

  // the obfuscation-profile section shares the Конфигурация card with the type
  // selector; tag it so it can be hidden without taking the whole card
  const obfCap = leaf("Профиль обфускации");
  if (obfCap?.parentElement?.parentElement) obfCap.parentElement.parentElement.id = "obfSection";

  // live generator bits the design binds but the capture froze
  leaf("весь трафик через WARP")?.setAttribute("id", "routeNote");
  leaf("endpoint · auto")?.setAttribute("id", "arcEp");
  [...gen.querySelectorAll<HTMLElement>("div")].find((d) => d.textContent?.trim() === "Поиск endpoint →")?.setAttribute("id", "scoutLink");

  // I1 custom-domain input, hidden until the 'Свой домен' preset is chosen
  const i1Card = $("i1Preset")?.closest<HTMLElement>('[style*="var(--panel)"]');
  if (i1Card && !$("i1CustomRow")) {
    const row = document.createElement("div");
    row.id = "i1CustomRow";
    row.className = "hidden";
    row.style.cssText = "display:grid;grid-template-columns:154px minmax(0,1fr);gap:18px;align-items:center;padding:13px 18px;border-top:1px solid var(--line)";
    row.innerHTML =
      `<div style="min-width:0"><div style="font-size:12.5px;font-weight:600;letter-spacing:-.012em">Свой домен</div>` +
      `<div style="font-size:11px;color:var(--text-3);margin-top:2px">валидный QUIC Initial под SNI</div></div>` +
      `<div style="min-width:0;max-width:430px"><input id="i1Domain" placeholder="example.com" spellcheck="false" style="width:100%;padding:8px 12px;border-radius:9px;border:1px solid var(--line-2);background:var(--panel-2);box-shadow:inset 0 1px 2px rgba(10,12,27,.05);font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:12.5px;outline:none" /></div>`;
    i1Card.appendChild(row);
  }

  const advCap = leaf("Дополнительно");
  const advHead = advCap?.parentElement;
  if (advHead) {
    advHead.id = "advHead";
    advHead.classList.add("scp1");
    (advHead.style as CSSStyleDeclaration).cursor = "pointer";
    advHead.children[1]?.firstElementChild?.setAttribute("id", "advSummary");
    advHead.children[1]?.lastElementChild?.setAttribute("id", "advArrow");
  }

  // Only the result screen's empty state was captured, so tag the places its
  // config branch has to be rebuilt into.
  const res = screenEl("result");
  // the empty-state "Взять из истории" subtitle carries a live saved-config count
  [...res.querySelectorAll<HTMLElement>("div")].find((d) => !d.children.length && /сохранённ\w* конфиг/.test(d.textContent || ""))?.setAttribute("id", "resultEmptyCount");
  const col = res.querySelector<HTMLElement>('[style*="padding: 18px 26px 40px"]');
  if (col) {
    col.id = "resultCol";
    col.firstElementChild?.setAttribute("id", "resultEmpty");
  }
  const bar = res.querySelector<HTMLElement>('[style*="position: sticky"]');
  bar?.children[1]?.setAttribute("id", "resultActions");
  bar?.children[0]?.children[1]?.setAttribute("id", "resultSub");
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
  ...["162.159.192.1", "162.159.193.10", "188.114.96.1", "188.114.97.1"].map((v) => ({ value: v, label: v, group: "Официальные" })),
  ...["162.159.192.2", "162.159.192.5"].map((v) => ({ value: v, label: v, group: "Consumer" })),
  ...["162.159.195.1", "162.159.195.4", "188.114.98.1"].map((v) => ({ value: v, label: v, group: "Community" })),
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
}

/**
 * Split-tunnel service picker, built to the design: title and hint from its
 * view-model, a search row with the "N из M выбрано" counter, the six category
 * chips and a grid of tiles with the design's two-letter mark, oklch colour and
 * corner check. The mockup keeps all of it behind `showSvc`, so nothing of it
 * was captured.
 */
const splitState = { selected: new Set<string>(), cat: "all", query: "" };

interface PickerService {
  key: string;
  label: string;
  cat: string;
  mark: string;
  hue: number;
}

/** Every pickable service, tagged the way the design tags them. */
function splitCatalog(): PickerService[] {
  const seen = new Set<string>();
  const out: PickerService[] = [];
  const add = (key: string, label: string, fallbackCat: string): void => {
    const id = svcId(label);
    if (seen.has(id)) return;
    seen.add(id);
    const known = designService(label);
    out.push({
      key,
      label,
      cat: known?.category ?? fallbackCat,
      mark: known?.mark ?? initials(label),
      hue: known?.hue ?? svcHue(id),
    });
  };
  for (const t of splitTargetList()) add(t.key, t.label, "cloud");
  for (const g of catalogTargetGroups()) {
    const cat = CATEGORY_MAP[g.key] ?? "cloud";
    for (const t of g.targets) {
      if (/^Все /.test(t.label)) continue; // category aggregates are the chips' job
      add(t.key, t.label, cat);
    }
  }
  return out;
}

const initials = (label: string): string =>
  label.replace(/[^\p{L}\p{N}]/gu, "").slice(0, 2).toUpperCase();

/**
 * The design draws a two-letter mark on an oklch tile. We keep that tile, but
 * drop the real brand glyph on top where simple-icons has one (white on the
 * brand colour), falling back to the design's mark otherwise.
 */
function svcMark(s: { key: string; mark: string; hue: number }): string {
  const icon = BRAND_ICONS[s.key] ?? BRAND_ICONS[s.key.replace(/^cat:/, "")];
  if (icon) {
    return `<div style="width:30px;height:30px;border-radius:9px;background:${icon.h};display:grid;place-items:center">` +
      `<svg viewBox="0 0 24 24" width="17" height="17" style="fill:#fff"><path d="${icon.p}"></path></svg></div>`;
  }
  return `<div style="width:30px;height:30px;border-radius:9px;background:${tileColor(s.hue)};display:grid;place-items:center;color:#fff;font-size:11px;font-weight:700;letter-spacing:-.02em">${esc(s.mark)}</div>`;
}

function buildSplitPicker(): void {
  const card = cardOf(document.querySelector<HTMLElement>('[data-group="splitMode"]'));
  if (!card || $("splitBox")) return;

  const box = document.createElement("div");
  box.id = "splitBox";
  box.className = "hidden";
  box.style.cssText = "padding:14px 0 4px;border-top:1px solid var(--line);margin-top:14px";
  box.innerHTML =
    `<div style="display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:10px">` +
    `<div id="svcTitle" style="font-size:12.5px;font-weight:600;letter-spacing:-.012em">Сервисы в туннеле</div>` +
    `<div id="svcHint" style="font-size:11px;color:var(--text-3);text-align:right">домены и IP пойдут в AllowedIPs</div></div>` +
    `<div style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:11px;border:1px solid var(--line-2);background:var(--panel-2);box-shadow:inset 0 1px 2px rgba(10,12,27,.05)">` +
    `<svg width="15" height="15" style="fill:none;stroke:var(--text-3);stroke-width:1.6;stroke-linecap:round;flex:0 0 15px"><circle cx="6.6" cy="6.6" r="4.4"></circle><line x1="10" y1="10" x2="13.2" y2="13.2"></line></svg>` +
    `<input id="catalogSearch" placeholder="discord, steam, ai…" spellcheck="false" style="flex:1;min-width:0;border:0;background:transparent;outline:none;font-size:12.5px;color:inherit" />` +
    `<div id="svcTotal" style="font-size:11.5px;color:var(--text-3);white-space:nowrap"></div></div>` +
    `<div id="svcCats" style="display:flex;flex-wrap:wrap;gap:6px;margin-top:10px"></div>` +
    `<div id="splitGrid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(102px,1fr));gap:7px;margin-top:11px;max-height:340px;overflow-y:auto;overflow-x:hidden;padding:2px"></div>` +
    `<div id="svcEmpty" class="hidden" style="padding:26px 0;text-align:center;font-size:12.5px;color:var(--text-3)">Ничего не найдено</div>` +
    `<div style="display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin-top:12px;padding-top:12px;border-top:1px solid var(--line)">` +
    `<div style="font-size:11.5px;color:var(--text-3);margin-right:3px">Быстрый выбор</div>` +
    `<div id="splitPresets" style="display:flex;flex-wrap:wrap;gap:6px"></div></div>`;
  card.appendChild(box);

  const preset = (label: string, pick: (all: PickerService[]) => string[]): [string, (all: PickerService[]) => string[]] => [label, pick];
  const COMMON = ["discord", "youtube", "telegram", "instagram", "xcom", "chatgpt", "claude", "steam", "twitch", "tiktok", "spotify", "github"];
  const presets = [
    preset("Часто нужно", (all) => all.filter((s) => COMMON.includes(svcId(s.label))).map((s) => s.key)),
    preset("Игры", (all) => all.filter((s) => s.cat === "games").map((s) => s.key)),
    preset("AI", (all) => all.filter((s) => s.cat === "ai").map((s) => s.key)),
    preset("Всё", (all) => all.map((s) => s.key)),
    preset("Очистить", () => []),
  ];
  const pbox = must("splitPresets");
  pbox.innerHTML = presets
    .map(([label], i) =>
      `<div data-preset="${i}" class="scp9" style="padding:4px 10px;border-radius:7px;border:1px solid var(--line-2);font-size:11px;font-weight:600;color:var(--text-2);cursor:pointer">${esc(label)}</div>`)
    .join("");
  for (const el of pbox.querySelectorAll<HTMLElement>("[data-preset]")) {
    el.addEventListener("click", () => {
      setSplit(presets[Number(el.dataset.preset)][1](splitCatalog()));
      saveSettings();
    });
  }
  must("catalogSearch").addEventListener("input", (e) => {
    splitState.query = (e.target as HTMLInputElement).value.trim().toLowerCase();
    renderSplit();
  });
  renderSplit();
}

function renderSplit(): void {
  const all = splitCatalog();
  const chip = (value: string, label: string, n: number): string => {
    const on = splitState.cat === value;
    return `<div data-cat="${esc(value)}" class="scp7" style="display:flex;align-items:center;gap:6px;padding:5px 10px;border-radius:8px;border:1px solid ${on ? "var(--accent)" : "var(--line-2)"};background:${on ? "var(--sel)" : "var(--panel-2)"};color:${on ? "var(--accent)" : "var(--text-2)"};font-size:11.5px;font-weight:${on ? "650" : "550"};cursor:pointer">` +
      `<span>${esc(label)}</span><span style="font-size:10.5px;opacity:.55;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace">${n}</span></div>`;
  };

  const catsBox = $("svcCats");
  if (catsBox) {
    catsBox.innerHTML = SVC_CATEGORIES
      .map((c) => chip(c.value, c.label, c.value === "all" ? all.length : all.filter((s) => s.cat === c.value).length))
      .join("");
    for (const el of catsBox.querySelectorAll<HTMLElement>("[data-cat]")) {
      el.addEventListener("click", () => {
        splitState.cat = el.dataset.cat!;
        renderSplit();
      });
    }
  }

  const shown = all.filter((s) =>
    (splitState.cat === "all" || s.cat === splitState.cat) &&
    (!splitState.query || s.label.toLowerCase().includes(splitState.query) || s.key.includes(splitState.query)));

  const grid = $("splitGrid");
  if (grid) {
    grid.innerHTML = shown.map((s) => {
      const on = splitState.selected.has(s.key);
      return `<div data-split="${esc(s.key)}" class="scp6" style="position:relative;display:flex;flex-direction:column;align-items:center;gap:8px;padding:13px 8px 11px;border-radius:13px;border:1px solid ${on ? "var(--accent)" : "var(--line-2)"};background:${on ? "var(--sel)" : "var(--panel-2)"};cursor:pointer;user-select:none;transition:border-color .14s ease,background .14s ease,transform .14s ease">` +
        svcMark(s) +
        `<div style="font-size:11.5px;font-weight:${on ? "650" : "500"};color:${on ? "var(--accent)" : "var(--text)"};text-align:center;line-height:1.2;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%">${esc(s.label)}</div>` +
        `<div style="position:absolute;top:7px;right:7px;width:13px;height:13px;border-radius:5px;background:${on ? "var(--accent)" : "transparent"};border:1.5px solid ${on ? "var(--accent)" : "var(--line-2)"};display:grid;place-items:center">` +
        `<div style="width:4px;height:4px;border-radius:1px;background:${on ? "var(--on-accent)" : "transparent"}"></div></div></div>`;
    }).join("");
    for (const el of grid.querySelectorAll<HTMLElement>("[data-split]")) {
      el.addEventListener("click", () => {
        const key = el.dataset.split!;
        if (!splitState.selected.delete(key)) splitState.selected.add(key);
        renderSplit();
        saveSettings();
      });
    }
  }

  // the design shows the type-specific caption and counts against the whole list
  const clash = groupValue("configType") === "clash";
  setText("svcTitle", clash ? "Сервисы через туннель" : "Сервисы в туннеле");
  setText("svcHint", clash ? "правила DOMAIN-SUFFIX · резолв не нужен" : "домены и IP пойдут в AllowedIPs");
  setText("svcTotal", `${splitState.selected.size} из ${all.length} выбрано`);
  show($("svcEmpty"), shown.length === 0);
  updateSplitCount();
  updateProfile();
}

const selectedSplit = (): string[] => [...splitState.selected];
function setSplit(keys: string[]): void {
  splitState.selected = new Set(keys);
  renderSplit();
}
const updateSplitCount = () => setText("splitCount", `выбрано ${selectedSplit().length}`);

/**
 * «Расширенная обфускация» — the design ships this card collapsed, so it was
 * never captured; its markup is copied from the mockup source instead.
 */
const AWG_VERSIONS: Array<[string, string, string]> = [
  ["wg", "WireGuard", "без обфускации"],
  ["1.0", "AWG 1.0", "Jc / S / H"],
  ["1.5", "AWG 1.5", "+ CPS (I1…I5)"],
  ["2.0", "AWG 2.0", "+ S3/S4, H-диапазоны"],
  ["3.0", "AWG 3.0", "+ шифрование заголовка"],
];

function mountAwgSection(): void {
  // The card itself was captured (collapsed); only its body is missing, so the
  // design's own header — caption, version chip, summary and chevron — is reused.
  const col = screenEl("generate");
  const cap = [...col.querySelectorAll<HTMLElement>("div")].find(
    (d) => !d.children.length && d.textContent?.trim() === "Расширенная обфускация",
  );
  const head = cap?.parentElement?.parentElement;
  const card = head?.parentElement;
  if (!cap || !head || !card || $("awgBody")) return;

  card.id = "awgCard";
  head.id = "awgHead";
  head.classList.add("scp1");
  head.style.cursor = "pointer";
  cap.nextElementSibling?.setAttribute("id", "awgVerChip");
  const right = head.children[1];
  right?.firstElementChild?.setAttribute("id", "awgSummary");
  right?.lastElementChild?.setAttribute("id", "awgArrow");

  const tileBase = "padding:9px 11px;border-radius:11px;cursor:pointer;min-width:0;transition:border-color .14s ease,background .14s ease,transform .14s ease";
  const off = `${tileBase};border:1px solid var(--line-2);background:var(--panel-2)`;
  const on = `${tileBase};border:1px solid var(--accent);background:var(--sel)`;

  const body = document.createElement("div");
  body.id = "awgBody";
  body.className = "hidden";
  body.style.cssText = "padding:2px 18px 16px;border-top:1px solid var(--line)";
  body.innerHTML =
    `<div style="padding:13px 0">` +
    `<div style="display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:9px">` +
    `<div style="font-size:12.5px;font-weight:600;letter-spacing:-.012em">Версия профиля</div>` +
    `<div style="font-size:11px;color:var(--text-3)">новее — сильнее маскировка</div></div>` +
    `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(126px,1fr));gap:7px;max-width:660px">` +
    AWG_VERSIONS.map(([v, t, d]) =>
      `<div class="scp6" data-group="awgVer" data-value="${v}" data-on="${on}" data-off="${off}" style="${v === "1.5" ? on : off}">` +
      `<div data-ver-title style="font-size:12.5px;letter-spacing:-.015em;line-height:1.25">${t}</div>` +
      `<div style="font-size:10.5px;color:var(--text-3);margin-top:2px">${d}</div></div>`).join("") +
    `</div>` +
    `<div id="verWarn" class="hidden" style="display:flex;align-items:flex-start;gap:10px;margin-top:11px;padding:11px 13px;border-radius:11px;background:var(--panel-2);border:1px solid var(--warn);max-width:660px">` +
    `<div style="flex:0 0 16px;width:16px;height:16px;border-radius:99px;background:var(--warn);display:grid;place-items:center;color:#fff;font-size:11px;font-weight:700;line-height:1">!</div>` +
    `<div id="verWarnText" style="font-size:11.5px;color:var(--text-2);line-height:1.5"></div></div>` +
    `<div style="display:flex;align-items:center;gap:10px;margin-top:11px">` +
    `<div style="font-size:11.5px;color:var(--text-3)">Рекомендуемый MTU для профиля: ` +
    `<span id="mtuRec" style="color:var(--text);font-weight:600;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace"></span></div>` +
    `<div id="applyMtu" class="scp9" style="padding:4px 10px;border-radius:7px;border:1px solid var(--line-2);font-size:11px;font-weight:600;color:var(--text-2);cursor:pointer">Применить</div></div>` +
    `</div>`;
  card.appendChild(body);

  onClick("applyMtu", () => {
    setInput("mtuInput", $("mtuRec")?.textContent ?? "");
    updateProfile();
    saveSettings();
  });
  onClick("awgHead", () => {
    const open = !must("awgBody").classList.toggle("hidden");
    must("awgArrow").style.transform = open ? "rotate(-135deg)" : "rotate(45deg)";
  });
  bindGroup("awgVer", () => {
    updateAwgVersion();
    saveSettings();
  });
  updateAwgVersion();
}

/** Keeps the chip, the compatibility warning and the MTU hint in sync. */
function updateAwgVersion(): void {
  const v = groupValue("awgVer") || "1.5";
  setText("awgVerChip", AWG_VERSIONS.find(([k]) => k === v)?.[1] ?? "AWG 1.5");
  const warn = v === "wg"
    ? "Без обфускации DPI видит сигнатуру WireGuard — используйте только там, где блокировок нет."
    : compatWarning(v as AwgVersion);
  setText("verWarnText", warn ?? "");
  show($("verWarn"), !!warn);
  setText("mtuRec", String(v === "wg" ? 1420 : recommendedMtu(v as AwgVersion)));
  // design formula: 'Jc N · H h1/h2/h3/h4' + ' · CPS' when version ≥ 1.5
  const jc = architect?.junk.jc ?? 5;
  const vi = ["wg", "1.0", "1.5", "2.0", "3.0"].indexOf(v);
  setText("awgSummary", `Jc ${jc} · H 1/2/3/4${vi >= 2 ? " · CPS" : ""}`);
}

/** «Дополнительно» — MTU / keepalive / IPv6, built into the captured header. */
function mountAdvSection(): void {
  const head = $("advHead");
  const card = head?.parentElement;
  if (!head || !card || $("advBody")) return;

  const body = document.createElement("div");
  body.id = "advBody";
  body.className = "hidden";
  body.style.cssText = "padding:2px 18px 14px;border-top:1px solid var(--line)";
  const rowTop = "display:grid;grid-template-columns:154px minmax(0,1fr);gap:18px;align-items:center;padding:13px 0";
  const rowMid = `${rowTop};border-top:1px solid var(--line)`;
  const field = (id: string, val: string) =>
    `<div style="min-width:0;max-width:430px"><div style="max-width:140px"><input id="${id}" value="${esc(val)}" spellcheck="false" style="width:100%;padding:8px 12px;border-radius:9px;border:1px solid var(--line-2);background:var(--panel-2);box-shadow:inset 0 1px 2px rgba(10,12,27,.05);font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:12.5px;outline:none" /></div></div>`;
  const label = (t: string, sub: string) =>
    `<div style="min-width:0"><div style="font-size:12.5px;font-weight:600;letter-spacing:-.012em">${t}</div><div style="font-size:11px;color:var(--text-3);margin-top:2px">${sub}</div></div>`;
  body.innerHTML =
    `<div style="${rowTop}">${label("MTU", "по умолчанию 1280")}${field("mtuInput", "1280")}</div>` +
    `<div style="${rowMid}">${label("PersistentKeepalive", "0 — выключено")}${field("keepaliveInput", "25")}</div>` +
    `<div style="${rowMid}">${label("IPv6", "адрес и AllowedIPs")}` +
    `<div style="min-width:0"><div id="ipv6Toggle" style="display:flex;align-items:center;gap:10px;cursor:pointer;user-select:none">` +
    `<div id="ipv6Track" style="width:34px;height:20px;border-radius:99px;background:var(--line-2);padding:2px;display:flex;transition:background .2s ease">` +
    `<div id="ipv6Knob" style="width:16px;height:16px;border-radius:99px;background:#fff;box-shadow:var(--shadow-sm);transform:translateX(0);transition:transform .22s cubic-bezier(.4,0,.2,1)"></div></div>` +
    `<span id="ipv6Label" style="font-size:12px;color:var(--text-3)">выключен</span></div></div></div>`;
  card.appendChild(body);

  onClick("advHead", () => {
    const open = !must("advBody").classList.toggle("hidden");
    must("advArrow").style.transform = open ? "rotate(-135deg)" : "rotate(45deg)";
  });
  for (const id of ["mtuInput", "keepaliveInput"]) {
    $(id)?.addEventListener("input", () => {
      updateProfile();
      saveSettings();
    });
  }
  onClick("ipv6Toggle", () => {
    advState.ipv6 = !advState.ipv6;
    updateProfile();
    saveSettings();
  });
}

const advState = { ipv6: false };

/** The hero card, «Параметры» panel and «Дополнительно» summary, live. */
function updateProfile(): void {
  const type = groupValue("configType");
  const typeLabel = type === "clash" ? "Clash / Mihomo" : type === "wireguard" ? "WireGuard" : "AmneziaWG";
  const ip = selectValue("endpointIp") || "auto";
  const port = groupValue("endpointPort") || "2408";
  const split = groupValue("splitMode") === "selective";
  const mtu = inputValue("mtuInput") || "1280";
  const keep = inputValue("keepaliveInput") || "0";
  // sel labels carry extras (DNS shows " · <ip>", I1 an emoji / "(рекомендуется)") —
  // the hero and panel want the short name, as the design spells it
  const short = (t: string): string => t.split(" · ")[0].replace(/^\p{Emoji}\s*/u, "").replace(/\s*\([^)]*\)$/, "").trim();
  const dnsLabel = short(document.querySelector<HTMLElement>('[data-sel-label="dnsServer"]')?.textContent || "—");
  const i1Label = short(document.querySelector<HTMLElement>('[data-sel-label="i1Preset"]')?.textContent || "—");
  const plus = ($("accountBadge")?.textContent || "Free").includes("WARP+");

  setText("heroType", typeLabel);
  setText("heroEp", `${ip}:${port}  ·  ${split ? `split · ${splitState.selected.size}` : "full tunnel"}`);
  setText("heroPort", port);
  setText("heroDns", dnsLabel);
  setText("heroMtu", mtu);

  setText("pMask", type === "amnezia" ? i1Label : "—");
  setText("pRoute", split ? `Split · ${splitState.selected.size} серв.` : "Full Tunnel");
  setText("pKeep", Number(keep) > 0 ? `${keep} c` : "выкл");
  setText("pIpv6", advState.ipv6 ? "включён" : "выключен");
  setText("pAccount", plus ? "WARP+" : "Free");

  setText("advSummary", `MTU ${mtu} · KA ${keep}${advState.ipv6 ? " · IPv6" : ""}`);

  const track = $("ipv6Track"), knob = $("ipv6Knob");
  if (track) track.style.background = advState.ipv6 ? "var(--accent)" : "var(--line-2)";
  if (knob) knob.style.transform = advState.ipv6 ? "translateX(14px)" : "translateX(0)";
  setText("ipv6Label", advState.ipv6 ? "включён" : "выключен");

  // live routing-card hint and the Architect endpoint label
  setText("routeNote", split ? `${splitState.selected.size} сервисов` : "весь трафик через WARP");
  setText("arcEp", ip === "auto" ? "endpoint · auto" : `${ip}:${port}`);
  // sidebar account card reacts to the key field immediately (design isPlus)
  const keyed = inputValue("licenseKey").trim().length > 0;
  setAccount(keyed);
}

/** Account card: flips to WARP+ the moment a key is typed (design isPlus). */
function setAccount(plus: boolean): void {
  const badge = $("accountBadge"); // flex row: [dot, label]
  if (badge && badge.children.length >= 2) {
    (badge.children[0] as HTMLElement).style.background = plus ? "var(--accent)" : "var(--text-3)";
    badge.children[1].textContent = plus ? "WARP+" : "Free";
  } else if (badge) {
    badge.textContent = plus ? "WARP+" : "Free";
  }
  setText("accountNote", plus ? "Ключ будет применён при генерации" : "пусто — бесплатный аккаунт");
}

function updateVisibility(): void {
  const type = groupValue("configType");
  show($("awgCard"), type === "amnezia");
  updateProfile();
  // The obfuscation profile lives INSIDE the Конфигурация card next to the type
  // selector, so it must be hidden at the section level — hiding cardOf() would
  // take the whole card (type/port/endpoint/DNS) with it. Architect and the I1
  // mask are their own cards, so cardOf is right for them.
  show($("obfSection"), type === "amnezia");
  for (const group of ["archProfile", "archIntensity"]) {
    show(cardOf(document.querySelector<HTMLElement>(`[data-group="${group}"]`)), type === "amnezia");
  }
  show(cardOf($("i1Preset")), type === "amnezia");
  // design showSvc = split OR clash; a full-tunnel Clash still lists services
  show($("splitBox"), groupValue("splitMode") === "selective" || type === "clash");
  // I1 custom-domain input appears only for the 'custom' preset
  show($("i1CustomRow"), type === "amnezia" && selectValue("i1Preset") === "custom");
  updateChainSize();
}

/**
 * The design draws a range slider as a track + a blue fill div + a transparent
 * native input, with the current value shown in the header. The capture keeps
 * the pieces but freezes the fill and value; this makes them follow the input.
 */
function bindSlider(id: string): void {
  const inp = $<HTMLInputElement>(id);
  const wrap = inp?.parentElement;
  if (!inp || !wrap) return;
  const fill = [...wrap.children].find(
    (c) => c !== inp && /position:\s*absolute/.test(c.getAttribute("style") || "") && !/right:\s*0/.test(c.getAttribute("style") || ""),
  ) as HTMLElement | undefined;
  const label = wrap.previousElementSibling?.querySelector<HTMLElement>('[style*="var(--accent)"]');
  const min = Number(inp.min) || 0;
  const max = Number(inp.max) || 100;
  const paint = (): void => {
    const pct = ((Number(inp.value) - min) / (max - min)) * 100;
    if (fill) fill.style.width = `${pct}%`;
    if (label) label.textContent = inp.value;
  };
  inp.addEventListener("input", () => {
    paint();
    saveSettings();
  });
  paint();
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
    browserProfile: (groupValue("archBrowser") || "") as never,
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

/**
 * The design's code view: a gutter number per line and tokens coloured from the
 * --tk-* palette. Same rules as the mockup's tokenize(), so a config looks the
 * same here as it does there.
 */
function tokenizeConfig(text: string): string {
  const V = {
    sec: "var(--tk-sec)", key: "var(--tk-key)", num: "var(--tk-num)", str: "var(--tk-str)",
    tag: "var(--tk-tag)", com: "var(--tk-com)", op: "var(--tk-op)", fg: "var(--code-fg)",
  };
  return text.split("\n").map((line, i) => {
    const parts: string[] = [];
    const push = (t: string, c: string, w = "450"): void => {
      if (t) parts.push(`<span style="color:${c};font-weight:${w}">${esc(t)}</span>`);
    };
    const ci = line.indexOf("#");
    const body = ci >= 0 ? line.slice(0, ci) : line;
    const com = ci >= 0 ? line.slice(ci) : "";
    if (/^\s*\[/.test(body)) push(body, V.sec, "700");
    else {
      const m = body.match(/^(\s*)([A-Za-z][A-Za-z0-9_-]*)(\s*[=:]\s*)([\s\S]*)$/);
      if (m) {
        push(m[1], V.fg);
        push(m[2], V.key, "600");
        push(m[3], V.op);
        const rx = /(<[^>]*>)|([0-9]+(?:\.[0-9]+){0,3}(?::[0-9]+)?(?:\/[0-9]+)?)|([\s,]+)|([^\s,]+)/g;
        for (let x = rx.exec(m[4]); x; x = rx.exec(m[4])) {
          if (x[1]) push(x[1], V.tag, "550");
          else if (x[2]) push(x[2], V.num, "550");
          else if (x[3]) push(x[3], V.fg);
          else push(x[4], V.str);
        }
      } else push(body, V.fg);
    }
    if (com) push(com, V.com);
    if (!parts.length) push(" ", V.fg);
    return (
      `<div class="scpb" style="display:flex;align-items:flex-start;gap:14px;padding:0 18px;min-height:21px">` +
      `<div style="flex:0 0 24px;text-align:right;color:var(--code-gut);user-select:none;font-variant-numeric:tabular-nums">${i + 1}</div>` +
      `<div style="flex:1;min-width:0;white-space:pre-wrap;word-break:break-word">${parts.join("")}</div></div>`
    );
  }).join("");
}

/** «Сохранённые» column — the history, with the shown config marked active. */
function savedCards(): string {
  return loadHistory().map((e) => {
    const on = e.id === activeConfigId;
    const d = new Date(e.ts);
    const time = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    const type = e.configType === "clash" ? "Clash" : e.configType === "wireguard" ? "WireGuard" : "AmneziaWG";
    return (
      `<div data-card="${e.id}" class="scp7" style="padding:10px 12px;border-radius:12px;border:1px solid ${on ? "var(--line-2)" : "var(--line)"};background:${on ? "var(--panel-2)" : "var(--panel)"};box-shadow:${on ? "inset 2px 0 0 var(--accent)" : "var(--shadow-sm)"};cursor:pointer;min-width:0;transition:border-color .14s ease,background .14s ease">` +
      `<div style="display:flex;align-items:center;gap:8px;min-width:0">` +
      `<div style="width:5px;height:5px;border-radius:99px;background:${on ? "var(--accent)" : "var(--line-2)"};flex:0 0 5px"></div>` +
      `<input data-name="${e.id}" value="${esc(e.tag)}" placeholder="Без названия" class="scp5 scpa" style="flex:1;min-width:0;padding:2px 5px;margin-left:-5px;border:1px solid transparent;border-radius:6px;background:transparent;font-size:12.5px;font-weight:650;letter-spacing:-.015em;color:${on ? "var(--accent)" : "var(--text)"};outline:none;transition:border-color .14s ease" /></div>` +
      `<div style="display:flex;align-items:center;gap:7px;margin-top:5px;padding-left:13px;min-width:0">` +
      `<div style="flex:0 0 auto;font-size:9.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:2px 6px;border-radius:5px;background:var(--panel-3);color:var(--text-3)">${esc(type)}</div>` +
      `<div style="flex:1;min-width:0;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:11px;color:var(--text-3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.endpoint || "—")}</div>` +
      `<div style="flex:0 0 auto;font-size:10.5px;color:var(--text-3);opacity:.8">${time}</div></div></div>`
    );
  }).join("");
}

/** Копировать / QR / Скачать live in the screen's sticky bar, as in the design. */
function resultActions(): void {
  const bar = $("resultActions");
  if (!bar) return;
  bar.innerHTML =
    `<div style="display:flex;align-items:center;gap:8px">` +
    `<div id="copyCfg" class="scp0" style="padding:8px 14px;border-radius:10px;border:1px solid var(--line-2);font-size:12.5px;font-weight:600;color:var(--text-2);cursor:pointer;transition:background .14s ease,color .14s ease,border-color .14s ease;white-space:nowrap">Копировать</div>` +
    `<div id="qrBtn" class="scp1" style="padding:8px 14px;border-radius:10px;border:1px solid var(--line-2);font-size:12.5px;font-weight:600;color:var(--text-2);cursor:pointer">QR</div>` +
    `<div id="dlBtn" class="scp4 scpj" style="display:flex;align-items:center;gap:8px;padding:8px 16px;border-radius:10px;background:var(--accent);color:var(--on-accent);box-shadow:inset 0 -1px 0 rgba(0,0,0,.14);transition:transform .12s ease,opacity .12s ease;font-size:12.5px;font-weight:650;cursor:pointer;white-space:nowrap"><span>Скачать</span></div></div>`;
  onClick("copyCfg", () => void copyText(lastConfig, "copyCfg", "Скопировано", "Копировать"));
  onClick("qrBtn", toggleQr);
  onClick("dlBtn", () => void downloadConfig());
}

function setResult(config: string, type: ConfigKind, meta: string): void {
  lastConfig = config;
  lastConfigType = type;
  show($("resultEmpty"), false);
  // design: lead with the config name (the saved entry's tag or the type title),
  // then the endpoint — not the download filename
  const typeTitle = type === "clash" ? "Clash / Mihomo" : type === "wireguard" ? "WireGuard" : "AmneziaWG";
  const active = loadHistory().find((h) => h.id === activeConfigId);
  const name = active?.tag?.trim() || typeTitle;
  setText("resultSub", meta ? `${name} · ${meta}` : name);
  resultActions();

  const box = ensureBox("resultBox", $("resultCol") ?? screenEl("result"));
  box.innerHTML =
    `<div style="display:grid;grid-template-columns:minmax(0,272px) minmax(0,1fr);gap:16px;align-items:start">` +
    `<div style="display:flex;flex-direction:column;gap:9px;min-width:0">` +
    `<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:0 2px 2px">` +
    `<div style="font-size:10.5px;font-weight:700;letter-spacing:.11em;text-transform:uppercase;color:var(--text-3)">Сохранённые</div>` +
    `<div id="newCfg" style="font-size:11.5px;font-weight:600;color:var(--accent);cursor:pointer">+ Новый</div></div>` +
    savedCards() +
    `</div>` +
    `<div style="min-width:0;background:var(--code-bg);border:1px solid var(--code-line);border-radius:18px;box-shadow:var(--shadow);overflow:hidden">` +
    `<div style="display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--code-line);background:var(--code-head)">` +
    `<div style="display:flex;gap:6px">` +
    `<div style="width:9px;height:9px;border-radius:99px;background:#ff5f57"></div>` +
    `<div style="width:9px;height:9px;border-radius:99px;background:#febc2e"></div>` +
    `<div style="width:9px;height:9px;border-radius:99px;background:#28c840"></div></div>` +
    `<div style="flex:1;min-width:0;display:flex;align-items:baseline;gap:8px">` +
    `<div style="min-width:0;flex:0 1 auto;font-size:12.5px;font-weight:650;letter-spacing:-.015em;color:var(--code-fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(name)}</div>` +
    `<div style="flex:0 1 auto;min-width:0;font-size:11px;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;color:var(--code-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(fileName())}</div></div>` +
    `<div style="flex:0 0 auto;font-size:11px;color:var(--code-dim);white-space:nowrap">${config.split("\n").length} строк · read-only</div></div>` +
    `<div style="margin:0;padding:14px 0 16px;max-height:min(56vh,560px);overflow-y:auto;overflow-x:hidden;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:12px;line-height:1.75;color:var(--code-fg)">${tokenizeConfig(config)}</div></div>` +
    `<div id="qrWrap" class="hidden" style="grid-column:2;width:232px;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:var(--shadow-sm);animation:rise .15s ease-out">` +
    `<img id="qrImg" alt="QR" style="width:200px;height:200px;image-rendering:pixelated;background:#fff;border-radius:12px;border:1px solid var(--line-2)" />` +
    `<div style="font-size:11.5px;color:var(--text-3);margin-top:11px;line-height:1.45">Отсканируйте в мобильном клиенте AmneziaVPN или WireGuard.</div></div>` +
    `</div>`;

  onClick("newCfg", () => showView("generate"));
  for (const card of box.querySelectorAll<HTMLElement>("[data-card]")) {
    card.addEventListener("click", (ev) => {
      if ((ev.target as HTMLElement).dataset.name) return; // renaming, not opening
      const e = loadHistory().find((h) => h.id === Number(card.dataset.card));
      if (!e) return;
      activeConfigId = e.id;
      setResult(e.config, e.configType as ConfigKind, "из истории");
    });
  }
  for (const input of box.querySelectorAll<HTMLInputElement>("[data-name]")) {
    input.addEventListener("change", () => {
      updateHistoryTag(Number(input.dataset.name), input.value);
      renderHistory();
    });
  }
  navDot("result", true);
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
      customI1Domain: inputValue("i1Domain").trim() || undefined,
      dnsServer: selectValue("dnsServer") || "malw_link",
      splitMode: groupValue("splitMode") === "selective" ? "selective" : "full",
      splitTargets: selectedSplit(),
      awgVersion: (groupValue("awgVer") === "wg" ? "1.0" : groupValue("awgVer") || "1.5") as AwgVersion,
      mtu: parseInt(inputValue("mtuInput"), 10) || recommendedMtu((groupValue("awgVer") === "wg" ? "1.0" : groupValue("awgVer") || "1.5") as AwgVersion),
      persistentKeepalive: parseInt(inputValue("keepaliveInput"), 10) || null,
      includeIpv6: advState.ipv6,
      ...(architect ? { customJunk: architect.junk, obfuscation: architect.obfuscation } : {}),
    });

    const plus = result.accountType === "warp_plus" || result.accountType === "unlimited";
    setText("accountBadge", plus ? "WARP+" : "Free");
    setText("accountNote", plus ? "Аккаунт WARP+" : "Бесплатный аккаунт Cloudflare");

    let meta = result.endpoint;
    if (result.splitTunnel.mode === "selective") meta += ` · ${result.splitTunnel.resolvedAllowedIps} маршрутов`;
    pushHistory(result.configType, result.endpoint, result.config); // before setResult, so «Сохранённые» shows it
    setResult(result.config, result.configType, meta);
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
  setGroup("awgVer", "1.5");
  updateAwgVersion();
  updateVisibility();
  status("generate", "Форма сброшена к настройкам по умолчанию.", "ok");
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
  const lit = (on: boolean): void => {
    const b = $("qrBtn");
    if (!b) return;
    b.style.borderColor = on ? "var(--accent)" : "var(--line-2)";
    b.style.background = on ? "var(--sel)" : "transparent";
    b.style.color = on ? "var(--accent)" : "var(--text-2)";
  };
  if (!wrap.classList.contains("hidden")) {
    show(wrap, false);
    lit(false);
    return;
  }
  try {
    ($("qrImg") as HTMLImageElement).src = qrDataUrl(lastConfig);
    show(wrap, true);
    lit(true);
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

function scanProgress(title: string, percent: number, active: ScanStep | null, note?: Partial<Record<ScanStep, string>>, tiles = true): void {
  const box = ensureBox("wsProgress", hostCard("scan").parentElement ?? screenEl("scan"));
  placeAfterCard("scan", box);
  // design: 16px radius, shadow-sm, 18px 20px padding, 16px margin-bottom
  box.style.cssText = "background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px 20px;box-shadow:var(--shadow-sm);margin-bottom:16px";
  // a step is lit if it's active OR already passed; at 100% (active null) all pass
  const idx = (s: ScanStep) => STEP_INFO.findIndex(([k]) => k === s);
  const activeIdx = active ? idx(active) : STEP_INFO.length;
  const speedOn = toggleValue("wsSpeed");
  box.innerHTML =
    `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:13px">` +
    `<div style="font-size:12.5px;font-weight:600">${esc(title)}</div>` +
    `<div style="font-size:11.5px;color:var(--text-3);font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace">${percent}%</div></div>` +
    `<div style="height:5px;border-radius:99px;background:var(--panel-3);overflow:hidden;margin-bottom:14px">` +
    `<div style="height:100%;border-radius:99px;width:${percent}%;transition:width .5s cubic-bezier(.2,.8,.2,1);background-color:var(--accent);background-image:repeating-linear-gradient(115deg,rgba(255,255,255,.22) 0 8px,rgba(255,255,255,0) 8px 16px);background-size:28px 100%;animation:flow .7s linear infinite"></div></div>` +
    (tiles
      ? `<div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px">` +
        STEP_INFO.map(([key, label, sub], i) => {
          const on = i < activeIdx || key === active;
          const t = key === "speed" ? (speedOn ? "Скорость" : "Пинг") : label;
          const s = key === "speed" ? (speedOn ? "download" : "RTT") : sub;
          return `<div style="padding:9px 12px;border-radius:10px;border:1px solid ${on ? "var(--accent)" : "var(--line-2)"};background:${on ? "var(--sel)" : "transparent"}">` +
            `<div style="font-size:12px;font-weight:600;color:${on ? "var(--accent)" : "var(--text)"}">${esc(t)}</div>` +
            `<div style="font-size:11px;color:var(--text-3);margin-top:1px">${esc(note?.[key] ?? s)}</div></div>`;
        }).join("") +
        `</div>`
      : "");
}

function wsStatus(text: string, spin = false): void {
  // warpscout is driven from both the scan screen and the generator card, so the
  // line shows up wherever the user actually clicked
  const html = spin ? `<span class="spinner"></span> ${esc(text)}` : esc(text);
  const view = document.querySelector<HTMLElement>(".view.active")?.dataset.view;
  status(view === "generate" ? "generate" : "scan", html);
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
/**
 * The design's shared find-junk / find-sni card: what warpscout measured, and a
 * jump to the Architect where the values were just applied.
 */
function renderFindCard(title: string, note: string, params: Array<[string, string]>): void {
  const box = ensureBox("wsFindResult", hostCard("scan").parentElement ?? screenEl("scan"));
  placeAfterCard("scan", box);
  box.style.cssText =
    "background:var(--panel);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow-sm),inset 0 1px 0 var(--hl);margin-bottom:16px;animation:pop .26s cubic-bezier(.2,.8,.2,1)";
  const tile = ([k, v]: [string, string]) =>
    `<div style="padding:10px 12px;border-radius:11px;background:var(--panel-2);border:1px solid var(--line)">` +
    `<div style="font-size:9.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text-3)">${esc(k)}</div>` +
    `<div style="font-size:13px;font-weight:650;letter-spacing:-.02em;margin-top:4px;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v)}</div></div>`;

  box.innerHTML =
    `<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 18px 11px;border-bottom:1px solid var(--line)">` +
    `<div style="font-size:10.5px;font-weight:700;letter-spacing:.11em;text-transform:uppercase;color:var(--text-3)">${esc(title)}</div>` +
    `<div style="display:flex;align-items:center;gap:7px">` +
    `<div style="width:6px;height:6px;border-radius:99px;background:var(--ok)"></div>` +
    `<div style="font-size:11px;font-weight:600;color:var(--text-2)">подставлено в Architect</div></div></div>` +
    `<div style="padding:14px 18px 16px">` +
    `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:8px">${params.map(tile).join("")}</div>` +
    `<div style="display:flex;align-items:center;justify-content:space-between;gap:14px;margin-top:14px;padding-top:13px;border-top:1px solid var(--line)">` +
    `<div style="font-size:11.5px;color:var(--text-3);min-width:0">${esc(note)}</div>` +
    `<div id="openArchitect" class="scp4 scpd" style="display:flex;align-items:center;gap:7px;padding:8px 15px;border-radius:10px;background:var(--accent);color:var(--on-accent);box-shadow:inset 0 -1px 0 rgba(0,0,0,.14);transition:transform .12s ease,opacity .12s ease;font-size:12.5px;font-weight:650;cursor:pointer;white-space:nowrap;flex:0 0 auto">` +
    `<span>Открыть в Architect</span><span style="opacity:.75">→</span></div></div></div>`;

  onClick("openArchitect", () => {
    showView("generate");
    document.querySelector('[data-group="archProfile"]')?.scrollIntoView({ behavior: "smooth", block: "center" });
  });
}

function renderJunkResult(
  junk: { jc: number; jmin: number; jmax: number },
  handshakeMs?: string,
  packets?: string,
  attempts?: string,
): void {
  renderFindCard(
    "find-junk · параметры обфускации",
    `Профиль обфускации переключён на Custom${packets ? ` · ${packets} пакетов` : ""}${attempts ? `, ${attempts} попытки` : ""}`,
    [["Jc", String(junk.jc)], ["Jmin", String(junk.jmin)], ["Jmax", String(junk.jmax)], ["Handshake", handshakeMs ? `${handshakeMs} ms` : "—"]],
  );
}

/**
 * Результаты card. Markup and the ping/dot tiers mirror the design's scanRows
 * view-model: dot <30 ok / <60 accent / else warn, ping green only under 30 ms,
 * row highlighted when its IP is the one currently in the generator.
 */
function renderScanRows(rows: ws.ScanRow[]): void {
  const box = ensureBox("wsResults", hostCard("scan").parentElement ?? screenEl("scan"));
  const cols = "1.5fr .8fr .9fr .8fr 1.4fr";
  const mono = "ui-monospace,'SF Mono',Menlo,Consolas,monospace";
  box.style.cssText =
    "background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow-sm),inset 0 1px 0 var(--hl);overflow:hidden;margin-bottom:16px";
  box.innerHTML =
    `<div style="display:flex;align-items:center;justify-content:space-between;padding:13px 18px;border-bottom:1px solid var(--line)">` +
    `<div style="font-size:10.5px;font-weight:700;letter-spacing:.11em;text-transform:uppercase;color:var(--text-3)">Результаты</div>` +
    `<div style="font-size:11.5px;color:var(--text-3)">клик по строке — подставить endpoint в генератор</div></div>` +
    `<div style="display:grid;grid-template-columns:${cols};padding:9px 18px;background:var(--panel-2);border-bottom:1px solid var(--line);font-size:10.5px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--text-3)">` +
    `<div>Endpoint</div><div>Ping</div><div>Страна</div><div>Нода</div><div>Локация</div></div>` +
    `<div id="wsRows" style="max-height:340px;overflow:auto"></div>`;

  const list = must("wsRows");
  const currentIp = selectValue("endpointIp");

  rows.forEach((r, i) => {
    const row = document.createElement("div");
    row.className = "scan-row scp1" + (r.endpoint.split(":")[0] === currentIp ? " sel" : "");
    row.style.cssText =
      `display:grid;grid-template-columns:${cols};align-items:center;padding:11px 18px;border-bottom:1px solid var(--line);cursor:pointer;` +
      `animation:fadeUp .34s cubic-bezier(.2,.8,.2,1) both;animation-delay:${i * 45}ms;transition:background .14s ease`;
    row.innerHTML =
      `<div style="font-family:${mono};font-size:12.5px;font-weight:600;display:flex;align-items:center;gap:8px">` +
      `<div style="width:6px;height:6px;border-radius:99px;flex:0 0 6px;background:${r.ping < 30 ? "var(--ok)" : r.ping < 60 ? "var(--accent)" : "var(--warn)"}"></div>` +
      `<span>${esc(r.endpoint)}</span></div>` +
      `<div style="font-family:${mono};font-size:12.5px;font-weight:600;color:${r.ping < 30 ? "var(--ok)" : "var(--text)"}">${r.ping} ms</div>` +
      `<div style="font-size:12.5px">${esc(COUNTRY[r.country] ?? r.country)}</div>` +
      `<div style="font-family:${mono};font-size:12px;color:var(--text-2)">${esc(r.node)}</div>` +
      `<div style="font-size:12.5px;color:var(--text-2)">${esc(r.location.split(",")[0])}</div>`;
    row.addEventListener("click", () => {
      [...list.children].forEach((d) => d.classList.remove("sel"));
      row.classList.add("sel");
      applyEndpoint(r.endpoint);
    });
    list.appendChild(row);
  });
  placeAfterCard("scan", box);
}

const wsFilters = () => {
  const f = inputValue("wsFilter").trim();
  if (!f) return {};
  return /^[A-Za-z]{2}(,[A-Za-z]{2})*$/.test(f) ? { country: f.toUpperCase() } : { node: f.toUpperCase() };
};

/** The design's scanning state: nav dot, spinner in Scan, red Stop, live subtitle. */
function scoutBusy(on: boolean, msg?: string): void {
  navDot("scan", on, true);
  const scan = $("wsScanBtn");
  if (scan) {
    scan.querySelector(".spinner")?.remove();
    if (on) scan.insertAdjacentHTML("afterbegin", '<span class="spinner" style="margin-right:7px"></span>');
  }
  const stop = $("wsStopBtn");
  if (stop) {
    stop.style.borderColor = on ? "var(--err)" : "var(--line-2)";
    stop.style.color = on ? "var(--err)" : "var(--text-3)";
  }
  setText("scoutSub", `warpscout · ${msg ?? (on ? "сканирование…" : "сканер endpoint'ов")}`);
}

async function onScan(): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  $("wsResults")?.remove();
  $("wsFindResult")?.remove(); // the design clears `find` when a scan starts
  status("scan", "");
  scoutBusy(true, "проверка портов…");
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
    applyEndpoint(rows[0].endpoint); // before the table, so the best row renders selected
    renderScanRows(rows);
  } catch (err) {
    $("wsProgress")?.remove();
    wsStatus(wsAbort?.signal.aborted ? "Остановлено." : `⚠ ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    wsAbort = null;
    scoutBusy(false);
  }
}

/**
 * The design's find tiles carry their own state: the "запустить" label becomes
 * "измеряю…", the leading dot pulses, then a short result stays inline. Both the
 * generator tiles and the scan-screen tiles share ids, so we style whichever
 * exist.
 */
function tileState(kind: "junk" | "sni", label: string, busy: boolean): void {
  for (const id of [kind === "junk" ? "genJunkBtn" : "genSniBtn", kind === "junk" ? "wsJunkBtn" : "wsSniBtn"]) {
    const tile = $(id);
    if (!tile) continue;
    const right = tile.querySelector<HTMLElement>('[style*="margin-left: auto"], [style*="margin-left:auto"]');
    if (right) {
      right.textContent = label;
      right.style.color = busy ? "var(--accent)" : "var(--text-3)";
    }
    const dot = tile.querySelector<HTMLElement>('[style*="width: 6px"][style*="height: 6px"], [style*="width:6px"][style*="height:6px"]');
    if (dot) dot.style.animation = busy ? "pulse 1.1s ease-in-out infinite" : "none";
  }
}

async function wsRun(kind: "import" | "junk" | "sni"): Promise<void> {
  if (wsAbort) return;
  wsAbort = new AbortController();
  if (kind !== "import") {
    tileState(kind, "измеряю…", true);
    // design: the scan progress bar (no phase tiles) runs during junk/sni too
    $("wsResults")?.remove();
    scanProgress(kind === "junk" ? "find-junk: подбор параметров обфускации…" : "find-sni: перебор SNI…", 66, "tunnels", undefined, false);
  }
  wsStatus(kind === "import" ? "Импорт конфига…" : kind === "junk" ? "Подбор junk-параметров…" : "Поиск SNI…", true);
  const proto = (groupValue("wsProto") || "awg") as ws.Proto;
  try {
    if (kind === "import") {
      const { config, endpoint } = await ws.importConfig({ proto, ...wsFilters(), signal: wsAbort.signal });
      const kind = proto === "wg" ? "wireguard" : "amnezia";
      pushHistory(kind, endpoint ?? "", config);
      setResult(config, kind, `warpscout${endpoint ? ` · ${endpoint}` : ""}`);
    } else if (kind === "junk") {
      const out = await ws.findJunk({ proto, signal: wsAbort.signal });
      const m = out.match(/jc\s*=?\s*(\d+).*?jmin\s*=?\s*(\d+).*?jmax\s*=?\s*(\d+)/is);
      if (m) {
        architect = { junk: { jc: +m[1], jmin: +m[2], jmax: +m[3] }, profile: architect?.profile ?? "quic_initial", obfuscation: architect?.obfuscation ?? {} };
        const hs = out.match(/(\d+(?:\.\d+)?)\s*ms/i)?.[1];
        renderJunkResult(
          { jc: +m[1], jmin: +m[2], jmax: +m[3] },
          hs,
          out.match(/(\d+)\s*(?:packets|пакет)/i)?.[1],
          out.match(/(\d+)\s*(?:attempts?|попыт)/i)?.[1],
        );
        tileState("junk", `junk ${m[1]}${hs ? ` · ${hs} ms` : ""}`, false);
        status("scan", "");
        status("generate", "");
      } else {
        tileState("junk", "готово", false);
        wsStatus("find-junk завершён.");
      }
    } else {
      const out = await ws.findSni({ proto, signal: wsAbort.signal });
      const host = out.match(/\b([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)\b/i)?.[1];
      if (host) {
        setInput("archHost", host);
        const rtt = out.match(/(\d+(?:\.\d+)?)\s*ms/i)?.[1];
        const tried = out.match(/(\d+)\s*(?:domains?|домен)/i)?.[1];
        renderFindCard(
          "find-sni · рабочий SNI",
          `Маскировка I1 переключена на ${proto === "masque" ? "MASQUE" : "QUIC"} под ${host}${tried ? ` · проверено ${tried} доменов` : ""}`,
          [["SNI", host], ["Протокол", proto === "masque" ? "MASQUE" : "QUIC"], ["RTT", rtt ? `${rtt} ms` : "—"]],
        );
        tileState("sni", `${host}${rtt ? ` · ${rtt} ms` : ""}`, false);
        status("scan", "");
        status("generate", "");
      } else {
        tileState("sni", "готово", false);
        wsStatus("find-sni завершён.");
      }
    }
  } catch (err) {
    if (kind !== "import") tileState(kind, "ошибка", false);
    wsStatus(wsAbort?.signal.aborted ? "Остановлено." : `⚠ ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    wsAbort = null;
    $("wsProgress")?.remove();
  }
}

// ─────────────── DPI ───────────────
/** The design's running state: header word, pill, button label and the nav dot. */
function setDpiOn(on: boolean): void {
  setText("dpiState", on ? "Работает" : "Выключен");

  const pill = screenEl("dpi").querySelector<HTMLElement>('[style*="border-radius: 99px"][style*="padding: 5px 12px"]');
  if (pill) {
    pill.style.background = on ? "var(--sel)" : "var(--panel-2)";
    pill.style.border = `1px solid ${on ? "var(--accent-2)" : "var(--line)"}`;
    const dot = pill.firstElementChild as HTMLElement | null;
    if (dot) dot.style.background = on ? "var(--ok)" : "var(--text-3)";
    const label = pill.lastElementChild as HTMLElement | null;
    if (label && label !== dot) {
      label.textContent = on ? "Работает" : "Выключен";
      label.style.color = on ? "var(--accent)" : "var(--text-3)";
    }
  }

  // the design keeps this button a solid accent fill in BOTH states; only the label changes
  const btn = $("dpiStartBtn");
  if (btn) btn.textContent = on ? "Перезапустить" : "Включить DPI-обход";

  const nav = document.querySelector<HTMLElement>('.nav-item[data-view="dpi"]');
  nav?.querySelector("[data-dpi-dot]")?.remove();
  if (on && nav) {
    const dot = document.createElement("div");
    dot.dataset.dpiDot = "1";
    dot.style.cssText = "margin-left:auto;width:6px;height:6px;border-radius:99px;background:var(--ok)";
    nav.appendChild(dot);
  }
}

async function dpiStart(): Promise<void> {
  setText("dpiState", "Запуск…");
  status("dpi", "Подтвердите UAC…");
  try {
    await winws.startWinws(
      { ports: inputValue("dpiPorts"), fakeTtl: parseInt(inputValue("dpiTtl"), 10) || 0, quic: toggleValue("dpiQuic") },
      (l) => status("dpi", esc(l)),
    );
    setDpiOn(true);
    status("dpi", "DPI-обход активен.", "ok");
  } catch (err) {
    setDpiOn(false);
    status("dpi", `⚠ ${esc(err instanceof Error ? err.message : String(err))}`, "err");
  }
}

// ─────────────── import ───────────────
/** The design puts import feedback in a bar at the bottom of the code card. */
function importStatus(text: string, ok = false): void {
  const card = $("importInput")?.closest<HTMLElement>('[style*="code-line"]');
  let bar = $("importStatus");
  if (!text) {
    bar?.remove();
    return;
  }
  if (!card) return;
  if (!bar) {
    bar = document.createElement("div");
    bar.id = "importStatus";
    card.appendChild(bar);
  }
  bar.style.cssText = `padding:11px 16px;border-top:1px solid var(--code-line);background:var(--panel-2);font-size:12px;font-weight:550;color:${ok ? "var(--ok)" : "var(--err)"}`;
  bar.textContent = text;
}

/** The design's distinct Amnezia Premium warning card, below the code card. */
function importPremiumCard(show: boolean): void {
  $("importPremium")?.remove();
  if (!show) return;
  const card = $("importInput")?.closest<HTMLElement>('[style*="code-line"]');
  const host = card?.parentElement;
  if (!host) return;
  const el = document.createElement("div");
  el.id = "importPremium";
  el.style.cssText = "display:flex;align-items:flex-start;gap:11px;margin-top:13px;padding:13px 15px;border-radius:13px;border:1px solid var(--warn);background:var(--panel);box-shadow:var(--shadow-sm);max-width:640px";
  el.innerHTML =
    `<div style="flex:0 0 18px;width:18px;height:18px;border-radius:99px;background:var(--warn);display:grid;place-items:center;color:#fff;font-size:12px;font-weight:700;line-height:1">!</div>` +
    `<div><div style="font-size:12.5px;font-weight:650;letter-spacing:-.012em">Это ссылка Amnezia Premium</div>` +
    `<div style="font-size:11.5px;color:var(--text-2);line-height:1.5;margin-top:3px">Она содержит доступ к API подписки, а не готовый конфиг. Получите <span style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace">.conf</span> в приложении AmneziaVPN и вставьте его сюда.</div></div>`;
  host.insertBefore(el, card!.nextSibling);
}

async function onImport(toClash: boolean): Promise<void> {
  const input = inputValue("importInput").trim();
  importPremiumCard(false);
  if (!input) {
    importStatus("Вставьте конфиг или ссылку vpn://");
    return;
  }
  try {
    const raw = await normalizeImportedConfig(input);
    const output = toClash ? clashFromNode(parseImportedConf(raw)) : raw;
    const type: ConfigKind = toClash ? "clash" : /(\bJc\s*=|\bI1\s*=)/.test(raw) ? "amnezia" : "wireguard";
    importStatus("");
    pushHistory(type, "", output);
    setResult(output, type, toClash ? "импорт → Clash" : "импорт");
  } catch (err) {
    const premium = (err as { premium?: boolean })?.premium === true;
    importStatus(err instanceof Error ? err.message : String(err));
    importPremiumCard(premium);
  }
}

// ─────────────── history ───────────────
/** Same grid as the design's history header row, so cells line up with it. */
const HISTORY_COLS =
  "display:grid;grid-template-columns:minmax(70px,104px) minmax(0,172px) minmax(0,96px) minmax(64px,1fr) 168px";

/** Russian pluralisation for the saved-config counts the design shows. */
function savedWord(n: number): string {
  const d = n % 10, dd = n % 100;
  if (d === 1 && dd !== 11) return "сохранённый конфиг";
  if (d >= 2 && d <= 4 && (dd < 10 || dd >= 20)) return "сохранённых конфига";
  return "сохранённых конфигов";
}

function renderHistory(): void {
  const list = loadHistory();
  setText("historyCount", String(list.length));
  setText("resultEmptyCount", `${list.length} ${savedWord(list.length)}`);
  const box = $("historyList");
  if (!box) return;
  // «Очистить всё» only exists when there is history (design sc-if hasHistory)
  show($("historyClearBtn"), list.length > 0);
  // drop the previous render (and the mock rows the design ships with); the
  // header row is the design's own and stays, hidden when there is nothing to head
  for (const row of [...box.children]) {
    if (row.id !== "historyHead") row.remove();
  }
  const head = $("historyHead");
  if (head) head.style.display = list.length ? "grid" : "none";
  if (!list.length) {
    // the design renders a self-contained card INSTEAD of the table panel
    box.style.cssText = "background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow-sm),inset 0 1px 0 var(--hl);padding:22px 24px 24px;max-width:560px";
    const empty = document.createElement("div");
    empty.dataset.hist = "1";
    empty.innerHTML =
      `<div style="font-size:15px;font-weight:680;letter-spacing:-.024em">История пуста</div>` +
      `<div style="font-size:12.5px;color:var(--text-2);margin-top:7px;line-height:1.55">` +
      `Сгенерированные и импортированные конфиги сохраняются здесь автоматически — до 20 последних, ` +
      `с названием, тегом и быстрым переключением.</div>` +
      `<div id="historyFirst" class="scp4" style="margin-top:16px;display:inline-block;padding:8px 15px;border-radius:10px;background:var(--accent);color:var(--on-accent);box-shadow:inset 0 -1px 0 rgba(0,0,0,.14);font-size:12.5px;font-weight:650;cursor:pointer">Сгенерировать первый</div>`;
    box.appendChild(empty);
    onClick("historyFirst", () => showView("generate"));
    return;
  }
  // restore the table-panel look when there are rows
  box.style.cssText = "background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow-sm),inset 0 1px 0 var(--hl);overflow:hidden;max-width:1000px";
  for (const e of list) {
    const d = new Date(e.ts);
    const date = `${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")} · ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
    const type = e.configType === "clash" ? "Clash" : e.configType === "wireguard" ? "WireGuard" : "AmneziaWG";
    const row = document.createElement("div");
    row.dataset.hist = "1";
    box.appendChild(row);

    /** The design shows the row either idle or asking to confirm a delete. */
    const draw = (confirm: boolean): void => {
      if (confirm) {
        row.className = "";
        row.style.cssText = "display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 18px;border-bottom:1px solid var(--line);background:var(--panel-2)";
        row.innerHTML =
          `<div style="flex:1;min-width:140px;font-size:12.5px;color:var(--text-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">Удалить <span style="font-weight:650;color:var(--text)">${esc(`${type} · ${e.endpoint || "—"}`)}</span>?</div>` +
          `<div data-act="del" class="scph" style="flex:0 0 auto;padding:6px 12px;border-radius:9px;background:var(--err);color:#fff;box-shadow:inset 0 -1px 0 rgba(0,0,0,.14);font-size:11.5px;font-weight:650;cursor:pointer">Удалить</div>` +
          `<div data-act="cancel" class="scp0" style="flex:0 0 auto;padding:6px 12px;border-radius:9px;border:1px solid var(--line-2);font-size:11.5px;font-weight:600;color:var(--text-2);cursor:pointer">Отмена</div>`;
        row.querySelector<HTMLElement>('[data-act="del"]')?.addEventListener("click", () => { deleteHistory(e.id); renderHistory(); });
        row.querySelector<HTMLElement>('[data-act="cancel"]')?.addEventListener("click", () => draw(false));
        return;
      }
      row.className = "scp1";
      row.style.cssText = `${HISTORY_COLS};align-items:center;gap:12px;padding:10px 18px;border-bottom:1px solid var(--line)`;
      row.innerHTML =
        `<div style="justify-self:start;font-size:11px;font-weight:650;padding:3px 9px;border-radius:99px;background:var(--soft);color:var(--accent);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%">${esc(type)}</div>` +
        `<div style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:12.5px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.endpoint || "—")}</div>` +
        `<div style="font-size:11.5px;color:var(--text-3);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(date)}</div>` +
        `<input value="${esc(e.tag)}" placeholder="тег" class="scpe scpa" style="width:100%;min-width:0;padding:5px 9px;border-radius:8px;border:1px solid transparent;background:transparent;font-size:12px;color:var(--text-2);outline:none" />` +
        `<div style="display:flex;gap:6px;align-items:center;justify-content:flex-end;flex-wrap:nowrap;min-width:0">` +
        `<div data-act="open" class="scp9" style="flex:0 0 auto;padding:6px 11px;border-radius:9px;border:1px solid var(--line-2);font-size:11.5px;font-weight:600;color:var(--text-2);cursor:pointer;white-space:nowrap">Открыть</div>` +
        `<div data-act="copy" title="Копировать" class="scpf" style="width:29px;height:27px;flex:0 0 29px;display:grid;place-items:center;border-radius:9px;border:1px solid var(--line-2);color:var(--text-3);cursor:pointer">` +
        `<svg width="14" height="14" style="fill:none;stroke:currentColor;stroke-width:1.4"><rect x="4.4" y="4.4" width="7.2" height="7.2" rx="2"></rect><path d="M9.4 2.4H4a1.6 1.6 0 0 0-1.6 1.6v5.4"></path></svg></div>` +
        `<div data-act="ask" title="Удалить" class="scpg" style="width:29px;height:27px;flex:0 0 29px;display:grid;place-items:center;border-radius:9px;border:1px solid var(--line-2);color:var(--text-3);cursor:pointer">` +
        `<svg width="14" height="14" style="fill:none;stroke:currentColor;stroke-width:1.5;stroke-linecap:round"><line x1="2.4" y1="4.2" x2="11.6" y2="4.2"></line><path d="M4 4.2 L4.5 11.4 A1.4 1.4 0 0 0 5.9 12.6 H8.1 A1.4 1.4 0 0 0 9.5 11.4 L10 4.2"></path><line x1="5.6" y1="2.2" x2="8.4" y2="2.2"></line></svg></div></div>`;
      const tag = row.querySelector("input");
      tag?.addEventListener("change", () => updateHistoryTag(e.id, tag.value));
      row.querySelector<HTMLElement>('[data-act="open"]')?.addEventListener("click", () => {
        activeConfigId = e.id;
        setResult(e.config, e.configType as ConfigKind, "из истории");
      });
      row.querySelector<HTMLElement>('[data-act="copy"]')?.addEventListener("click", () => void navigator.clipboard.writeText(e.config));
      row.querySelector<HTMLElement>('[data-act="ask"]')?.addEventListener("click", () => draw(true));
    };
    draw(false);
  }
}

function pushHistory(configType: string, endpoint: string, config: string): void {
  // design: a new entry is never blank — name it from the field or type+time
  const typeTitle = configType === "clash" ? "Clash" : configType === "wireguard" ? "WireGuard" : "AmneziaWG";
  const now = new Date();
  const stamp = `${String(now.getDate()).padStart(2, "0")}.${String(now.getMonth() + 1).padStart(2, "0")} ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
  const tag = inputValue("configName").trim() || `${typeTitle} · ${stamp}`;
  activeConfigId = addHistory({ configType, endpoint, config, tag })[0]?.id ?? 0;
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

/** The design's checker panel: progress bar, four counters, log, found keys. */
function checkerPanel(pct: number, counters: Array<[string, number, string]>, log: Array<[string, string]>, found: string[]): void {
  const box = ensureBox("bfPanel", hostCard("tools").parentElement ?? screenEl("tools"));
  placeAfterCard("tools", box);
  box.style.cssText = "margin-top:18px";
  box.innerHTML =
    `<div style="height:5px;border-radius:99px;background:var(--panel-3);overflow:hidden;margin-bottom:13px">` +
    `<div style="height:100%;border-radius:99px;width:${pct}%;transition:width .3s linear;background-color:var(--accent);background-image:repeating-linear-gradient(115deg,rgba(255,255,255,.22) 0 8px,rgba(255,255,255,0) 8px 16px);background-size:28px 100%;animation:flow .7s linear infinite"></div></div>` +
    `<div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-bottom:13px">` +
    counters.map(([k, v, fg]) =>
      `<div style="padding:11px 14px;border-radius:12px;background:var(--panel-2);border:1px solid var(--line)">` +
      `<div style="font-size:10.5px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--text-3)">${esc(k)}</div>` +
      `<div style="font-size:19px;font-weight:700;letter-spacing:-.03em;margin-top:3px;color:${fg};font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace">${v}</div></div>`).join("") +
    `</div>` +
    `<div style="border-radius:12px;background:var(--panel-2);border:1px solid var(--line);padding:12px 14px;max-height:150px;overflow:auto;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:11.5px;line-height:1.75;color:var(--text-2)">` +
    log.map(([t, fg]) => `<div style="color:${fg}">${esc(t)}</div>`).join("") + `</div>` +
    (found.length
      ? `<div style="margin-top:13px">` +
        `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:7px">` +
        `<div style="font-size:11.5px;font-weight:550;color:var(--text-2)">Найденные WARP+ ключи</div>` +
        `<div id="copyFound" class="scp0" style="padding:5px 11px;border-radius:8px;border:1px solid var(--line-2);font-size:11.5px;font-weight:600;color:var(--text-2);cursor:pointer">Копировать</div></div>` +
        `<textarea readonly style="width:100%;height:90px;resize:vertical;padding:12px 14px;border-radius:12px;border:1px solid var(--line-2);background:var(--panel-2);box-shadow:inset 0 1px 2px rgba(10,12,27,.05);font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:12px;line-height:1.7;outline:none;color:var(--ok)">${esc(found.join("\n"))}</textarea></div>`
      : "");
  if (found.length) onClick("copyFound", () => void copyText(found.join("\n"), "copyFound", "Скопировано", "Копировать"));
}

let bfAbort: AbortController | null = null;
async function onBruteforce(): Promise<void> {
  const count = Math.min(Math.max(parseInt(inputValue("bfCount"), 10) || 100, 1), 10000);
  const keys = Array.from({ length: count }, generateWarpKey);
  const proxies = inputValue("bfProxies").trim().split("\n").map((l) => l.trim()).filter(Boolean);
  const threads = parseInt(inputValue("bfThreads"), 10) || 30;
  bfAbort = new AbortController();
  setBusy("bfStartBtn", true, "Проверяем…");
  status("tools", "");

  const found: string[] = [];
  const log: Array<[string, string]> = [[`[start] потоков ${threads}, ключей ${count}`, "var(--accent)"]];
  const draw = (pct: number, checked: number): void =>
    checkerPanel(pct, [
      ["Проверено", checked, "var(--text)"],
      ["Найдено", found.length, "var(--ok)"],
      ["Живых прокси", proxies.length, "var(--text)"],
      ["Потоки", threads, "var(--text)"],
    ], log.slice(-40), found);
  draw(0, 0);

  await runBruteforce(keys, proxies, {
    concurrency: threads,
    signal: bfAbort.signal,
    onEvent: (e) => {
      if (e.type === "valid") {
        found.push(e.key);
        log.push([`[+] ${e.key}`, "var(--ok)"]);
      }
      draw(Math.round((e.checked / e.total) * 100), e.checked);
    },
  });
  log.push([`[done] найдено ${found.length}`, found.length ? "var(--ok)" : "var(--text-3)"]);
  draw(100, count);
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
    awgVer: groupValue("awgVer"),
    endpointIp: selectValue("endpointIp"), dnsServer: selectValue("dnsServer"),
    i1Preset: selectValue("i1Preset"), archBrowser: groupValue("archBrowser"),
    configName: inputValue("configName"), archHost: inputValue("archHost"),
    mtu: inputValue("mtuInput"), keepalive: inputValue("keepaliveInput"), ipv6: advState.ipv6,
    archJunk: inputValue("archJunk"), i1Domain: inputValue("i1Domain"),
    dpiPorts: inputValue("dpiPorts"), dpiTtl: inputValue("dpiTtl"), dpiQuic: toggleValue("dpiQuic"),
    splitTargets: selectedSplit(),
  });
}

function loadSettings(): void {
  const s = loadJson<Record<string, unknown>>(SETTINGS_KEY, {});
  for (const g of ["configType", "obfsProfile", "endpointPort", "splitMode", "archProfile", "archIntensity", "archBrowser", "awgVer"]) {
    if (typeof s[g] === "string") setGroup(g, s[g] as string);
  }
  for (const id of ["endpointIp", "dnsServer", "i1Preset"]) {
    if (typeof s[id] === "string") setSelect(id, s[id] as string);
  }
  if (typeof s.configName === "string") setInput("configName", s.configName);
  if (typeof s.archHost === "string") setInput("archHost", s.archHost);
  if (typeof s.mtu === "string") setInput("mtuInput", s.mtu);
  if (typeof s.keepalive === "string") setInput("keepaliveInput", s.keepalive);
  if (typeof s.archJunk === "string") setInput("archJunk", s.archJunk);
  if (typeof s.i1Domain === "string") setInput("i1Domain", s.i1Domain);
  if (typeof s.dpiPorts === "string") setInput("dpiPorts", s.dpiPorts);
  if (typeof s.dpiTtl === "string") setInput("dpiTtl", s.dpiTtl);
  if (s.dpiQuic === true) setToggle("dpiQuic", true);
  advState.ipv6 = s.ipv6 === true;
  if (Array.isArray(s.splitTargets)) setSplit(s.splitTargets as string[]);
  updateAwgVersion();
  updateProfile();
}

// ─────────────── init ───────────────
function init(): void {
  // desktop app: suppress the webview's own context menu except in text fields
  document.addEventListener("contextmenu", (e) => {
    if (!(e.target as HTMLElement).closest("input, textarea")) e.preventDefault();
  });

  repairHooks();
  buildControls();
  buildSplitPicker();

  applyTheme(loadJson<string>("warpgen.theme", "light") === "dark");
  setText("siteVersion", `v${__APP_VERSION__}`);
  const osLabel = currentOs() === "windows" ? "Windows" : currentOs() === "macos" ? "macOS" : "Linux";
  setText("platformChip", osLabel);
  // clients header subtitle is the same live OS label in the design
  const clientsBar = screenEl("clients").querySelector<HTMLElement>('[style*="position: sticky"]');
  const clientsSub = clientsBar?.children[0]?.children[1] as HTMLElement | undefined;
  if (clientsSub) clientsSub.textContent = `загрузки для ${osLabel}`;

  for (const g of ["configType", "obfsProfile", "endpointPort", "splitMode", "archProfile", "archIntensity", "archBrowser", "wsProto"]) {
    bindGroup(g, () => {
      updateVisibility();
      saveSettings();
    });
  }
  for (const s of ["endpointIp", "dnsServer"]) bindSelect(s, saveSettings);
  bindSelect("i1Preset", () => { updateVisibility(); saveSettings(); }); // custom-domain row toggles on this
  onClick("scoutLink", () => showView("scan"));
  $("licenseKey")?.addEventListener("input", () => setAccount(inputValue("licenseKey").trim().length > 0));
  $("i1Domain")?.addEventListener("input", saveSettings);
  for (const t of ["archRouter", "wsSpeed", "wsTunPing"]) bindToggle(t);
  bindToggle("dpiQuic", saveSettings);
  for (const id of ["dpiPorts", "dpiTtl"]) $(id)?.addEventListener("input", saveSettings);
  bindSlider("archJunk");
  bindSlider("bfThreads");

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
    setDpiOn(false);
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
    activeConfigId = 0;
    renderHistory();
    if (lastConfig) setResult(lastConfig, lastConfigType, "текущий"); // refresh «Сохранённые»
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

  mountAwgSection();
  mountAdvSection();
  loadSettings();
  renderHistory();
  updateVisibility();
  updateSplitCount();

  const dpiNav = document.querySelector<HTMLElement>('.nav-item[data-view="dpi"]');
  if (currentOs() !== "windows") show(dpiNav, false);
  else void winws.winwsRunning().then(setDpiOn);

  void ws.warpscoutVersion().catch((err) => status("scan", `warpscout недоступен: ${esc(String(err))}`, "err"));
  showView("generate");
  void initWindowChrome();
}

init();
