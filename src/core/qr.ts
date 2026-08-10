import qrcode from "qrcode-generator";

// Client-side QR (replaces the web app's server-side /api/qr). Returns a
// data-URL image for the given text (a WireGuard/AmneziaWG .conf, etc.).
export function qrDataUrl(text: string): string {
  const qr = qrcode(0, "L");
  qr.addData(text);
  qr.make();
  return qr.createDataURL(6, 8);
}
