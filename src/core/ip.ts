// Browser replacements for the bits of Node's `net` module we relied on.

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIPv4(value: string): boolean {
  const m = IPV4.exec(value);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) <= 255);
}

export function isIPv6(value: string): boolean {
  // Good enough for validating resolver output / user endpoints; not a full RFC parser.
  if (!value.includes(":")) return false;
  return /^[0-9a-fA-F:]+$/.test(value) && (value.match(/::/g)?.length ?? 0) <= 1;
}

/** Mirrors Node's net.isIP: 0 (neither), 4, or 6. */
export function isIP(value: string): 0 | 4 | 6 {
  if (isIPv4(value)) return 4;
  if (isIPv6(value)) return 6;
  return 0;
}

/** Adds the host route mask (/32 or /128) to a bare interface address. */
export function normalizeInterfaceAddress(raw: string): string {
  const value = (raw ?? "").trim();
  if (!value) return "";
  if (value.includes("/")) return value;
  const t = isIP(value);
  if (t === 4) return `${value}/32`;
  if (t === 6) return `${value}/128`;
  return value;
}
