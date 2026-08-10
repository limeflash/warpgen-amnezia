// Generates src-tauri/icon-source.png — a 1024x1024 brand icon used as the
// source for `tauri icon` (which produces the .ico/.icns/png set). Pure Node
// PNG encoder so there's no image dependency.
//   node scripts/gen-icon.mjs
import { deflateSync } from "node:zlib";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const SIZE = 1024;
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const PURPLE = [124, 107, 219];
const CYAN = [79, 195, 247];
const lerp = (a, b, t) => Math.round(a + (b - a) * t);
const clamp01 = (v) => Math.min(1, Math.max(0, v));

// Soft coverage of a rounded square (inset margin, corner radius r).
function roundedCoverage(x, y, margin, r) {
  const w = SIZE - margin * 2;
  const dx = Math.max(Math.abs(x - SIZE / 2) - (w / 2 - r), 0);
  const dy = Math.max(Math.abs(y - SIZE / 2) - (w / 2 - r), 0);
  const dist = Math.hypot(dx, dy) - r;
  return clamp01(0.5 - dist); // ~1px antialiased edge
}

const cx = SIZE / 2;
const cy = SIZE / 2;
const RING_R = 300;
const RING_W = 30;
const DOT_R = 96;

// Row = 1 filter byte + RGBA per pixel.
const stride = SIZE * 4 + 1;
const raw = Buffer.alloc(stride * SIZE);

for (let y = 0; y < SIZE; y++) {
  raw[y * stride] = 0; // filter: none
  for (let x = 0; x < SIZE; x++) {
    const o = y * stride + 1 + x * 4;
    const cov = roundedCoverage(x, y, 48, 200);
    if (cov <= 0) {
      raw[o] = raw[o + 1] = raw[o + 2] = raw[o + 3] = 0;
      continue;
    }
    // Background: vertical purple → cyan gradient.
    const t = y / SIZE;
    let r = lerp(PURPLE[0], CYAN[0], t);
    let g = lerp(PURPLE[1], CYAN[1], t);
    let b = lerp(PURPLE[2], CYAN[2], t);

    // White ring + center dot (the "warp" mark).
    const d = Math.hypot(x - cx, y - cy);
    const ring = clamp01(RING_W / 2 - Math.abs(d - RING_R));
    const dot = clamp01(DOT_R - d);
    const mark = Math.max(ring, dot);
    if (mark > 0) {
      r = lerp(r, 255, mark);
      g = lerp(g, 255, mark);
      b = lerp(b, 255, mark);
    }

    raw[o] = r;
    raw[o + 1] = g;
    raw[o + 2] = b;
    raw[o + 3] = Math.round(cov * 255);
  }
}

// ── Minimal PNG container ──
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const typeBuf = Buffer.from(type, "ascii");
  const body = Buffer.concat([typeBuf, data]);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0);
ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // RGBA
ihdr[10] = 0;
ihdr[11] = 0;
ihdr[12] = 0;

const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  chunk("IHDR", ihdr),
  chunk("IDAT", deflateSync(raw, { level: 9 })),
  chunk("IEND", Buffer.alloc(0)),
]);

const out = join(root, "src-tauri", "icon-source.png");
writeFileSync(out, png);
console.log(`wrote ${out} (${SIZE}x${SIZE}, ${(png.length / 1024).toFixed(0)} KB)`);
