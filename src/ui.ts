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

export function setGroup(group: string, value: string): void {
  for (const card of cardsOf(group)) {
    const on = card.dataset.value === value;
    card.dataset.selected = on ? "1" : "0";
    const style = on ? card.dataset.on : card.dataset.off;
    if (style) card.setAttribute("style", style);
  }
}

/** Wires a card group; `onChange` fires with the new value. */
export function bindGroup(group: string, onChange?: (v: string) => void): void {
  const cards = cardsOf(group);
  if (!cards.length) return;
  // seed selection from the design's own default (the accent-styled card)
  const initial = cards.find((c) => c.getAttribute("style") === c.dataset.on)?.dataset.value ?? cards[0].dataset.value!;
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

export function bindSelect(id: string, onChange?: (v: string) => void): void {
  const sel = $<HTMLSelectElement>(id);
  if (!sel) return;
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

const toggleBase = new WeakMap<HTMLElement, string>();

export function toggleValue(id: string): boolean {
  return $(id)?.dataset.toggle === "on";
}

export function setToggle(id: string, on: boolean): void {
  const el = $(id);
  if (!el) return;
  if (!toggleBase.has(el)) toggleBase.set(el, el.getAttribute("style") ?? "");
  el.dataset.toggle = on ? "on" : "off";
  const base = toggleBase.get(el)!;
  el.setAttribute(
    "style",
    on ? `${base};border-color:var(--accent);background:var(--sel);color:var(--accent)` : base,
  );
  const box = el.querySelector<HTMLElement>('[style*="border-radius: 5px"], [style*="border-radius:5px"]');
  if (box) box.style.background = on ? "var(--accent)" : "";
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
