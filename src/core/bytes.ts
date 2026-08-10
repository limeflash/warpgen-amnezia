// Small byte helpers so the packet builders read like the original Node code
// but run in the webview (Uint8Array instead of Buffer, Web Crypto for RNG).

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function u8(...bytes: number[]): Uint8Array {
  return Uint8Array.from(bytes);
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const x of bytes) s += x.toString(16).padStart(2, "0");
  return s;
}

export function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const x of bytes) bin += String.fromCharCode(x);
  return btoa(bin);
}

export function asciiBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
