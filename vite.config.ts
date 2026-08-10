import { defineConfig } from "vite";
import pkg from "./package.json" with { type: "json" };

// Tauri expects a fixed dev-server port and does its own process management,
// so we disable Vite's screen clearing and lock the port.
export default defineConfig({
  clearScreen: false,
  envPrefix: ["VITE_", "TAURI_"],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // src-tauri is watched by the Tauri CLI, not Vite.
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    // WebView2 (Windows) / WKWebView (macOS) / WebKitGTK (Linux) all support ES2022.
    target: "es2022",
    minify: "esbuild",
    sourcemap: false,
  },
});
