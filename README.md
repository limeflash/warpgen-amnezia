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
  *find-junk* (AmneziaWG obfuscation tuning), *find-sni* (MASQUE), plus `-speed`
  (download-test) and `-P` (tun-ping/loss) toggles — all streamed live and stoppable.
- **Clash / Mihomo** output (`.yaml`) + import a `.conf` or Amnezia `vpn://` link, and a **QR** for any config.
- **📦 Clients** — one-click download links for WireGuard / AmneziaVPN / Clash Verge / WireSock (OS auto-detected).
- **🕘 History & settings** — every config is logged (load / tag / copy / delete); the form is remembered across restarts.
- **🛡 DPI bypass (Windows)** — runs zapret2's `winws2` to push the WARP handshake through DPI (see below).
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

Build an installer (produces a `.dmg` on macOS, `.msi`/`.exe` on Windows, `.deb`/`.AppImage` on Linux):

```bash
npm run fetch:warpscout       # sidecar for the current platform
npm run app:build
```

### Cross-platform / releases

The app is cross-platform; each OS build just needs its own warpscout sidecar.

- **CI:** `.github/workflows/release.yml` builds macOS (Apple Silicon + Intel), Windows
  and Linux in one matrix — each job fetches the sidecar for its target
  (`node scripts/fetch-warpscout.mjs --target=<triple>`). Push a `v*` tag to publish a
  draft release with all installers; a manual run uploads them as artifacts. Building
  macOS bundles requires a macOS machine/runner (they can't be cross-compiled from Windows).
- **macOS locally:** `npm install && npm run fetch:warpscout && npm run app:build` on a Mac.
  The bundle is unsigned — first launch: right-click the app → *Open* (or
  `xattr -dr com.apple.quarantine /Applications/WarpGen.app`). For distribution, add
  Apple signing/notarization secrets to the workflow.

### DPI bypass (winws / zapret2) — Windows

The 🛡 card runs zapret2's `winws2` to push the WARP UDP handshake through DPI
(filters the WARP ports both ways, matches the WireGuard L7 + payloads, and
injects Lua "fake" desync packets with a tuned fake-TTL). On first *Start* it
downloads `winws2` + `WinDivert` + the Lua scripts from
[`bol-van/zapret-win-bundle`](https://github.com/bol-van/zapret-win-bundle) into
the app-data dir and launches `winws2` **elevated (UAC)** — WinDivert is a kernel
driver, so Administrator is required. *Stop* kills it. After enabling, run the
warpscout scan to find endpoints that now get through.

> ⚠ Not verifiable in CI (needs admin + a live network) — test on your own
> machine.

**macOS / Linux.** The DPI screen is Windows-only, and the originally planned
`tpws` port would not have helped: `tpws` is a transparent **TCP** proxy, while
WARP is UDP (2408/500/4500/1701). The tool that handles UDP is `nfqws`, and it
needs Linux **NFQUEUE** — so:

* **Linux** — feasible with `nfqws` + an `iptables -j NFQUEUE` rule, run as root
  (`pkexec`). Not implemented.
* **macOS** — no zapret path for UDP: pf can redirect TCP to `tpws`, but there is
  no nfqueue equivalent, so WARP's UDP cannot be desynced this way.

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
