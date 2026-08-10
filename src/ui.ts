/**
 * Binding layer for the design markup.
 *
 * index.html is generated from the Claude Design mockup (see scripts/build-ui.mjs),
 * where controls are drawn as plain divs. These helpers make them behave like
 * real controls without touching their styling:
 *   • option cards  — `data-group` / `data-value`, styles swapped from data-on/data-off
 *   • dropdowns     — a transparent native <select> layered over the drawn row
 *   • toggles       — `data-toggle`, accent border/background when on
 */

export function $<T extends HTMLElement = HTMLElement>(id: string): T | null {
  return document.getElementById(id) as T | null;
}
export function must<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = $<T>(id);
  if (!el) throw new Error(`#${id} missing`);
  return el;
}
export const setText = (id: string, text: string): void => {
  const el = $(id);
  if (el) el.textContent = text;
};
export const show = (el: HTMLElement | null, on: boolean): void => {
  if (el) el.classList.toggle("hidden", !on);
};
export const esc = (s: string): string =>
  String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

// ─────────────── option cards ───────────────

const cardsOf = (group: string) => Array.from(document.querySelectorAll<HTMLElement>(`[data-group="${group}"]`));

export function groupValue(group: string): string {
  const on = cardsOf(group).find((c) => c.dataset.selected === "1");
  return on?.dataset.value ?? cardsOf(group)[0]?.dataset.value ?? "";
}

/**
 * The design also recolours a card's caption when it is picked, and the capture
 * only holds that look on whichever card was selected in the mockup. Both looks
 * are read once, before the first swap, and then applied to every card.
 */
const titleLooks = new Map<string, { on: string; off: string }>();

function captureTitles(group: string, cards: HTMLElement[]): void {
  if (titleLooks.has(group)) return;
  const selected = cards.find((c) => c.getAttribute("style") === c.dataset.on);
  const style = (c?: HTMLElement) => (c?.firstElementChild as HTMLElement | null)?.getAttribute("style") ?? "";
  const on = style(selected);
  const off = style(cards.find((c) => c !== selected));
  if (on && off && on !== off) titleLooks.set(group, { on, off });
}

export function setGroup(group: string, value: string): void {
  const look = titleLooks.get(group);
  for (const card of cardsOf(group)) {
    const on = card.dataset.value === value;
    card.dataset.selected = on ? "1" : "0";
    const style = on ? card.dataset.on : card.dataset.off;
    if (style) card.setAttribute("style", style);
    const title = card.firstElementChild as HTMLElement | null;
    if (look && title) title.setAttribute("style", on ? look.on : look.off);
  }
}

/** Wires a card group; `onChange` fires with the new value. */
export function bindGroup(group: string, onChange?: (v: string) => void): void {
  const cards = cardsOf(group);
  if (!cards.length) return;
  // seed selection from the design's own default (the accent-styled card)
  const initial = cards.find((c) => c.getAttribute("style") === c.dataset.on)?.dataset.value ?? cards[0].dataset.value!;
  captureTitles(group, cards);
  setGroup(group, initial);
  for (const card of cards) {
    card.addEventListener("click", () => {
      setGroup(group, card.dataset.value!);
      onChange?.(card.dataset.value!);
    });
  }
}

// ─────────────── dropdowns ───────────────

export interface SelectOption {
  value: string;
  label: string;
  group?: string;
}

/** Fills the hidden native select and keeps the drawn row's caption in sync. */
export function fillSelect(id: string, options: SelectOption[], selected?: string): void {
  const sel = $<HTMLSelectElement>(id);
  if (!sel) return;
  sel.textContent = "";
  let currentGroup: HTMLOptGroupElement | null = null;
  for (const o of options) {
    const opt = new Option(o.label, o.value);
    if (o.group) {
      if (!currentGroup || currentGroup.label !== o.group) {
        currentGroup = document.createElement("optgroup");
        currentGroup.label = o.group;
        sel.appendChild(currentGroup);
      }
      currentGroup.appendChild(opt);
    } else {
      currentGroup = null;
      sel.appendChild(opt);
    }
  }
  if (selected !== undefined) sel.value = selected;
  syncSelectLabel(id);
}

export function syncSelectLabel(id: string): void {
  const sel = $<HTMLSelectElement>(id);
  const label = document.querySelector<HTMLElement>(`[data-sel-label="${id}"]`);
  if (sel && label) label.textContent = sel.selectedOptions[0]?.text ?? "";
}

/**
 * The design opens its own panel instead of the OS list. The native <select>
 * stays as the value store — everything else reads it — but it never opens:
 * clicking the drawn row renders the panel below it, styled like the mockup.
 */
function openPanel(id: string): void {
  const sel = $<HTMLSelectElement>(id);
  const wrap = document.querySelector<HTMLElement>(`[data-sel-label="${id}"]`)?.closest<HTMLElement>(".sel-wrap");
  if (!sel || !wrap) return;
  closePanels();

  const backdrop = document.createElement("div");
  backdrop.dataset.selPanel = id;
  backdrop.style.cssText = "position:fixed;inset:0;z-index:30";
  backdrop.addEventListener("click", closePanels);

  const panel = document.createElement("div");
  panel.dataset.selPanel = id;
  panel.style.cssText =
    "position:absolute;z-index:40;top:calc(100% + 6px);left:0;right:0;max-height:300px;overflow:auto;background:var(--panel);border:1px solid var(--line-2);border-radius:13px;box-shadow:var(--shadow);padding:6px;animation:rise .12s ease-out";

  const row = (o: HTMLOptionElement): string => {
    const on = o.value === sel.value;
    return `<div data-opt="${esc(o.value)}" class="scp1" style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:7px 10px;border-radius:8px;cursor:pointer;font-size:12.5px;font-weight:${on ? "650" : "500"};color:${on ? "var(--accent)" : "var(--text)"};background:${on ? "var(--sel)" : "transparent"}">` +
      `<span>${esc(o.text)}</span></div>`;
  };
  const label = (t: string): string =>
    `<div style="font-size:9.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text-3);padding:9px 10px 5px">${esc(t)}</div>`;

  panel.innerHTML = [...sel.children]
    .map((child) =>
      child instanceof HTMLOptGroupElement
        ? label(child.label) + [...child.children].map((o) => row(o as HTMLOptionElement)).join("")
        : row(child as HTMLOptionElement))
    .join("");

  for (const el of panel.querySelectorAll<HTMLElement>("[data-opt]")) {
    el.addEventListener("click", () => {
      sel.value = el.dataset.opt!;
      sel.dispatchEvent(new Event("change", { bubbles: true }));
      closePanels();
    });
  }
  wrap.append(backdrop, panel);
}

export function closePanels(): void {
  for (const el of document.querySelectorAll("[data-sel-panel]")) el.remove();
}

export function bindSelect(id: string, onChange?: (v: string) => void): void {
  const sel = $<HTMLSelectElement>(id);
  if (!sel) return;
  sel.style.display = "none"; // the panel replaces the OS dropdown
  const wrap = document.querySelector<HTMLElement>(`[data-sel-label="${id}"]`)?.closest<HTMLElement>(".sel-wrap");
  wrap?.addEventListener("click", (e) => {
    if ((e.target as HTMLElement).closest("[data-sel-panel]")) return;
    openPanel(id);
  });
  sel.addEventListener("change", () => {
    syncSelectLabel(id);
    onChange?.(sel.value);
  });
}

export const selectValue = (id: string): string => $<HTMLSelectElement>(id)?.value ?? "";

export function setSelect(id: string, value: string): void {
  const sel = $<HTMLSelectElement>(id);
  if (!sel) return;
  if ([...sel.options].some((o) => o.value === value)) {
    sel.value = value;
    syncSelectLabel(id);
  }
}

/** Adds an option (used when the scanner finds a new endpoint) and selects it. */
export function addSelectOption(id: string, value: string, label: string): void {
  const sel = $<HTMLSelectElement>(id);
  if (!sel) return;
  if (![...sel.options].some((o) => o.value === value)) sel.add(new Option(label, value), 0);
  sel.value = value;
  syncSelectLabel(id);
}

// ─────────────── toggles ───────────────

export function toggleValue(id: string): boolean {
  return $(id)?.dataset.toggle === "on";
}

/** The design draws the checkbox as a 15–16px rounded square; only it changes. */
function toggleBox(el: HTMLElement): HTMLElement | null {
  return el.querySelector<HTMLElement>(
    '[style*="width: 16px"][style*="height: 16px"], [style*="width: 15px"][style*="height: 15px"]',
  );
}

/**
 * The design draws one checkbox checked and another unchecked; both looks are
 * captured once and then applied to every toggle, so they stay identical.
 */
let checkedLook: { style: string; inner: string } | null = null;
let uncheckedLook: { style: string; inner: string } | null = null;

function captureLooks(): void {
  if (checkedLook && uncheckedLook) return;
  const boxes = Array.from(document.querySelectorAll<HTMLElement>('[data-toggle] [style*="width: 16px"][style*="height: 16px"]'));
  for (const b of boxes) {
    const style = b.getAttribute("style") ?? "";
    const look = { style, inner: b.innerHTML };
    if (/background:\s*var\(--accent\)/.test(style)) checkedLook ??= look;
    else uncheckedLook ??= look;
  }
  checkedLook ??= {
    style: "width: 16px; height: 16px; border-radius: 5px; border: 1.5px solid var(--accent); background: var(--accent); display: grid; place-items: center;",
    inner: '<div style="width: 6px; height: 6px; border-radius: 1.5px; background: var(--on-accent);"></div>',
  };
  uncheckedLook ??= {
    style: "width: 16px; height: 16px; border-radius: 5px; border: 1.5px solid var(--line-2); background: transparent; display: grid; place-items: center;",
    inner: "",
  };
}

export function setToggle(id: string, on: boolean): void {
  const el = $(id);
  if (!el) return;
  el.dataset.toggle = on ? "on" : "off";
  const box = toggleBox(el);
  if (!box) return;
  captureLooks();
  const look = on ? checkedLook! : uncheckedLook!;
  box.setAttribute("style", look.style);
  box.innerHTML = look.inner;
}

export function bindToggle(id: string, onChange?: (v: boolean) => void): void {
  const el = $(id);
  if (!el) return;
  setToggle(id, el.dataset.toggle === "on");
  el.addEventListener("click", () => {
    const next = !toggleValue(id);
    setToggle(id, next);
    onChange?.(next);
  });
}

// ─────────────── misc ───────────────

export function onClick(id: string, fn: () => void): void {
  $(id)?.addEventListener("click", fn);
}

export function inputValue(id: string): string {
  return $<HTMLInputElement | HTMLTextAreaElement>(id)?.value ?? "";
}

export function setInput(id: string, value: string): void {
  const el = $<HTMLInputElement | HTMLTextAreaElement>(id);
  if (el) el.value = value;
}

export function setBusy(id: string, busy: boolean, busyText?: string, idleText?: string): void {
  const el = $<HTMLElement>(id);
  if (!el) return;
  el.style.pointerEvents = busy ? "none" : "";
  el.style.opacity = busy ? "0.6" : "";
  if (busy && busyText) el.innerHTML = `<span class="spinner"></span> ${esc(busyText)}`;
  else if (!busy && idleText) el.textContent = idleText;
}

/** A panel styled like the design's cards, for content the mockup only sketches. */
export function panel(inner: string): string {
  return `<div style="background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:18px 20px;margin-bottom:14px">${inner}</div>`;
}

export function sectionTitle(text: string): string {
  return `<div style="font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-3);margin-bottom:11px">${esc(text)}</div>`;
}
