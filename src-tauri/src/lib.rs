// All application logic lives in the TypeScript frontend (running in the
// webview). Rust only hosts the window and the three plugins the frontend
// drives over IPC:
//   * shell  — spawns the bundled `warpscout` sidecar (scan / find-junk / find-sni)
//   * http   — makes the Cloudflare API / DoH / proxy-check requests (no CORS,
//              real User-Agent, per-request proxy support)
//   * fs     — checks/creates the app-data dir that holds the warpscout account
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_fs::init())
        .run(tauri::generate_context!())
        .expect("error while running WarpGen");
}
