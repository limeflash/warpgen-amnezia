// Assembles index.html from the design markup captured out of the Claude Design
// mockup (shell + 9 screens), so the UI is the design itself rather than a
// re-interpretation. Run after re-capturing a new design revision:
//
//   node scripts/build-ui.mjs <captured-dir> <design-styles.css>
//
// The captures are static (the mockup draws option cards / selects / buttons as
// divs), so main.ts makes them live: it binds by the data-* hooks added here.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const capDir = process.argv[2];
const cssPath = process.argv[3];
if (!capDir || !cssPath) {
  console.error("usage: node scripts/build-ui.mjs <captured-dir> <design-styles.css>");
  process.exit(1);
}

const SCREENS = ["generate", "result", "scan", "dpi", "import", "clients", "history", "tools", "analyzer"];

/** Removes the design-tool bookkeeping so the markup is plain HTML. */
function clean(html) {
  return html
    .replace(/ data-dc-tpl="\d+"/g, "")
    .replace(/<span class="sc-interp[^"]*">([\s\S]*?)<\/span>/g, "$1")
    .replace(/ class="sc-interp[^"]*"/g, "")
    .replace(/<!--\s*-->/g, "")
    .replace(/[ \t]+$/gm, "");
}

/** Adds attributes to the tag that opens at `idx`. */
function addAttrsAt(html, idx, attrs) {
  const end = html.indexOf(">", idx);
  const selfClosing = html[end - 1] === "/";
  const insertAt = selfClosing ? end - 1 : end;
  return html.slice(0, insertAt) + " " + attrs + html.slice(insertAt);
}

/** Finds the start of the element that encloses `pos` and opens with `tag`. */
function openingTagBefore(html, pos, tag = "div") {
  return html.lastIndexOf(`<${tag}`, pos);
}

/** Annotates the nth element whose opening tag precedes `needle`. */
function annotateBefore(html, needle, attrs, { tag = "div", occurrence = 1 } = {}) {
  let from = 0;
  for (let i = 0; i < occurrence; i++) {
    const found = html.indexOf(needle, from);
    if (found < 0) return html;
    if (i === occurrence - 1) {
      const open = openingTagBefore(html, found, tag);
      if (open < 0) return html;
      return addAttrsAt(html, open, attrs);
    }
    from = found + needle.length;
  }
  return html;
}

// ── shell ──────────────────────────────────────────────────────────────────
let shell = clean(readFileSync(join(capDir, "wired-shell.html"), "utf8"));


// Screens go where the scroll area was emptied.
const screensHtml = SCREENS.map((name) => {
  const file = join(capDir, `wired-${name}.html`);
  if (!existsSync(file)) return "";
  let body = clean(readFileSync(file, "utf8"));
  return `\n<section class="view${name === "generate" ? " active" : ""}" data-view="${name}">\n${body}\n</section>`;
}).join("\n");

shell = shell.replace("<!--SCREENS-->", screensHtml);

// Logos live in public/ so Vite serves them from the root.
shell = shell.replace(/src="logo-solid\.svg"/g, 'src="/logo-accent.svg"').replace(/src="logo-gradient\.svg"/g, 'src="/logo-gradient.svg"');

const css = readFileSync(cssPath, "utf8");

// The mockup writes interaction states as style-hover / style-focus / style-active
// attributes; its runtime compiles them into these .scpN rules and tags the elements
// with the matching class. The captured DOM keeps the classes but not the rules, so
// they are reproduced here verbatim (dumped from the design's own stylesheet).
const STATE_CSS = `
    .scp0:hover { background: var(--hover) !important; color: var(--text) !important; }
    .scp1:hover { background: var(--hover) !important; }
    .scp2:hover { background: #ff5f57 !important; }
    .scp3:active { transform: translateY(1px) !important; font-size: 12.5px !important; font-weight: 650 !important; cursor: pointer !important; white-space: nowrap !important; }
    .scp4:hover { opacity: .92 !important; }
    .scp5:focus { border-color: var(--accent) !important; background: var(--panel) !important; }
    .scp6:hover { border-color: var(--accent-2) !important; transform: translateY(-1px) !important; }
    .scp7:hover { border-color: var(--accent-2) !important; }
    .scp8:active { transform: translateY(1px) !important; }
    .scp9:hover { background: var(--sel) !important; color: var(--accent) !important; border-color: var(--accent-2) !important; }
    .scpa:hover { border-color: var(--line-2) !important; }
    .scpb:hover { background: var(--code-head) !important; }
    .scpc:hover { background: var(--hover) !important; border-color: var(--accent-2) !important; }
    .scpd:active { transform: translateY(1px) !important; font-size: 12.5px !important; font-weight: 650 !important; cursor: pointer !important; white-space: nowrap !important; flex: 0 0 auto !important; }
    .scpe:focus { border-color: var(--accent) !important; background: var(--panel-2) !important; color: var(--text) !important; }
    .scpf:hover { color: var(--text) !important; background: var(--hover) !important; }
    .scpg:hover { border-color: var(--err) !important; color: var(--err) !important; background: var(--hover) !important; }
    .scph:hover { opacity: .9 !important; }
    .scpi:active { transform: translateY(1px) !important; font-size: 12.5px !important; font-weight: 650 !important; cursor: pointer !important; }
    .scpj:active { transform: translateY(1px) !important; font-size: 12.5px !important; font-weight: 650 !important; cursor: pointer !important; display: flex !important; align-items: center !important; gap: 8px !important; }
    .scpk:hover { background: rgba(255,255,255,.06) !important; color: var(--code-fg) !important; }`;

const out = `<!DOCTYPE html>
<html lang="ru" data-theme="dark">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WarpGen</title>
  <style>
${css}
    /* ── app additions on top of the design system ── */
    .view { display: none; }
    .view.active { display: block; animation: fadeUp .24s cubic-bezier(.2,.8,.2,1); }
    .hidden { display: none !important; }
    .spinner { display: inline-block; width: 13px; height: 13px; border: 2px solid currentcolor; border-right-color: transparent; border-radius: 50%; animation: spin .7s linear infinite; vertical-align: -2px; }
    /* Everything the design draws as a clickable div */
    .nav-item, [data-group] > *, [data-value], [data-client], [data-toggle],
    [id$="Btn"], #themeToggle, .sel-wrap { cursor: pointer; }
    /* Native control layered over a design-drawn field, keeping its exact look */
    .sel-wrap { position: relative; }
    .sel-wrap > select { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
    .live-input { width: 100%; background: transparent; border: 0; outline: none; padding: 0; font: inherit; color: inherit; }
    .live-input::placeholder { color: var(--text-3); }
    /* AWG version tiles: the design also recolours the caption when selected */
    [data-ver-title] { font-weight: 500; color: var(--text); }
    [data-selected="1"] > [data-ver-title] { font-weight: 650; color: var(--accent); }
    /* selected scan row (the design binds this per row: sel when its IP is in the generator) */
    .scan-row.sel { background: var(--sel); }
${STATE_CSS}
  </style>
</head>

<body>
${shell}
  <script type="module" src="/src/main.ts"></script>
</body>

</html>
`;

writeFileSync(join(root, "index.html"), out);
console.log(`index.html written — shell + ${SCREENS.length} screens, ${(out.length / 1024).toFixed(0)} KB`);
