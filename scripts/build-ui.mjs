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
shell = shell.replace(/src="logo-solid\.svg"/g, 'src="/logo-solid.svg"').replace(/src="logo-gradient\.svg"/g, 'src="/logo-gradient.svg"');

const css = readFileSync(cssPath, "utf8");

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
    /* scan results — the design's row background / style-hover, which the capture can't carry */
    .scan-row.sel { background: var(--sel); }
    .scan-row:hover { background: var(--hover); }
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
