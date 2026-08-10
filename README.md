# WarpGen — WARP generator for AmneziaWG 2.x (Tauri desktop app)

Desktop app that generates Cloudflare WARP configs for **AmneziaWG 2.x** / **WireGuard**,
with the [**warpscout**](https://github.com/vernette/warpscout) endpoint scanner bundled in
to find a working, low-latency endpoint from your network.

- **Frontend + backend in TypeScript** (type-checked with **`tsgo`** — TypeScript 7 native compiler).
- **Tauri v2** shell (Rust). All app logic runs in the webview; the Cloudflare API,
  DoH resolution and proxy checks go through the Tauri **HTTP plugin** (no CORS, real
  User-Agent, per-request proxy), and **warpscout** runs as a Tauri **sidecar**.
- **Modernized AmneziaWG `I1`**: generates a *real, valid* QUIC Initial packet
  (HKDF → AES-GCM → header protection) instead of a malformed one — plus verified
  real-traffic captures, generated DNS/STUN/NTP/DTLS masks, and a custom-domain option.

## Features

- **Config generator** — Free or WARP+ (paste a key), AmneziaWG or vanilla WireGuard,
  obfuscation profiles, endpoint/port/DNS selection, IPv6 toggle, MTU/keepalive, and
  split tunneling by service (domains resolved via DoH at generation time).
- **🛰 warpscout** — *Find best endpoint* (auto-fills the form), *Import config*,
  *find-junk* (AmneziaWG obfuscation tuning) and *find-sni* (MASQUE), all streamed live and stoppable.
- **🔑 Tools** (tap the logo 7×) — WARP+ key check, test-key generation, and a
  proxy checker + key generator/checker with rotating proxies.

## Requirements

- [Node.js](https://nodejs.org) 20+ and [Rust](https://rustup.rs) 1.77+
- Windows: WebView2 (preinstalled on Win 11); Linux: WebKitGTK; macOS: Xcode CLT

## Getting started

```bash
npm install
npm run fetch:warpscout   # downloads the warpscout sidecar for your platform
npm run app:dev           # launches the app (Vite + Tauri)
```

Build an installer:

```bash
npm run fetch:warpscout -- --all   # bundle every platform's sidecar (optional)
npm run app:build
```

## Scripts

| Script | What it does |
|--------|--------------|
| `npm run app:dev` | Run the desktop app in dev mode (HMR) |
| `npm run app:build` | Build the release app + installer |
| `npm run dev` / `build` | Frontend only (Vite); `build` runs `tsgo` first |
| `npm run typecheck` | Type-check with `tsgo` (TypeScript 7) |
| `npm run fetch:warpscout` | Install the warpscout sidecar binary (`--all` for every platform) |
| `npm run gen:icon` | Regenerate the app icon set |

## Project layout

```
index.html            # Vite entry (webview UI)
src/
  main.ts             # UI controller — wires the DOM to the core (no HTTP server)
  core/
    quic.ts           # valid QUIC Initial generator for the AmneziaWG I1 mask
    i1.ts             # I1 preset registry (QUIC / captures / DNS / STUN / NTP / DTLS)
    generate.ts       # config builder (register → license → enable WARP → assemble)
    cloudflare*/http  # Cloudflare API + DoH via the Tauri HTTP plugin
    warpscout.ts      # drives the warpscout sidecar (scan / find-junk / find-sni)
    license.ts, proxy.ts, split.ts, dns.ts, keys.ts, …
src-tauri/            # Rust shell: plugins (shell/http/fs), capabilities, sidecar
scripts/              # fetch-warpscout.mjs, gen-icon.mjs
```

The warpscout binary and generated `*.conf` files are git-ignored — run
`npm run fetch:warpscout` after cloning.

## Credits

- [vernette/warpscout](https://github.com/vernette/warpscout) — the WARP endpoint scanner.
- The valid-QUIC `I1` generator is ported from
  [nellimonix/warp-config-generator-vercel](https://github.com/nellimonix/warp-config-generator-vercel).
