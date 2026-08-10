// All network I/O goes through the Tauri HTTP plugin (reqwest in Rust): no CORS,
// real User-Agent, and per-request proxy support — none of which the webview's
// own fetch can do. The Cloudflare WARP API in particular rejects browser
// fetches and needs the okhttp User-Agent.

import { fetch as tauriFetch } from "@tauri-apps/plugin-http";

export { tauriFetch as httpFetch };

export interface CfResponse {
  status: number;
  // Cloudflare responses are loosely shaped; callers probe fields defensively.
  body: any;
}

export interface CfRequestOptions {
  apiVersion?: string;
  userAgent?: string;
  proxy?: string;
  connectTimeout?: number;
}

const CF_HOST = "https://api.cloudflareclient.com";

export async function cfRequest(
  method: string,
  urlPath: string,
  token: string | null,
  body: unknown,
  opts: CfRequestOptions = {},
): Promise<CfResponse> {
  const data = body != null ? JSON.stringify(body) : undefined;
  const version = opts.apiVersion ?? "v0i1909051800";

  const headers: Record<string, string> = {
    "User-Agent": opts.userAgent ?? "okhttp/3.12.1",
    "Content-Type": "application/json",
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await tauriFetch(`${CF_HOST}/${version}/${urlPath}`, {
    method,
    headers,
    body: data,
    connectTimeout: opts.connectTimeout ?? 10000,
    ...(opts.proxy ? { proxy: { all: opts.proxy } } : {}),
  });

  const text = await res.text();
  let parsed: any;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { _raw: text };
  }
  return { status: res.status, body: parsed };
}
