// VPN client download links (ported from the web app's CLIENT_DOWNLOADS).
// In the desktop app these open in the default browser via the shell plugin.

export type OsKey = "windows" | "macos" | "linux" | "android" | "ios";

export interface ClientDownload {
  title: string;
  links: Record<OsKey, string>;
}

export const CLIENT_DOWNLOADS: Record<string, ClientDownload> = {
  wireguard: {
    title: "WireGuard",
    links: {
      windows: "https://download.wireguard.com/windows-client/wireguard-installer.exe",
      macos: "https://apps.apple.com/us/app/wireguard/id1451685025",
      linux: "https://www.wireguard.com/install/",
      android: "https://play.google.com/store/apps/details?id=com.wireguard.android",
      ios: "https://apps.apple.com/us/app/wireguard/id1451685025",
    },
  },
  amnezia: {
    title: "AmneziaVPN",
    links: {
      windows: "https://github.com/amnezia-vpn/amnezia-client/releases/latest",
      macos: "https://github.com/amnezia-vpn/amnezia-client/releases/latest",
      linux: "https://github.com/amnezia-vpn/amnezia-client/releases/latest",
      android: "https://github.com/amnezia-vpn/amnezia-client/releases/latest",
      ios: "https://apps.apple.com/us/app/amneziavpn/id1600529900",
    },
  },
  clash_verge: {
    title: "Clash Verge",
    links: {
      windows: "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest",
      macos: "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest",
      linux: "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest",
      android: "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest",
      ios: "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest",
    },
  },
  wiresock: {
    title: "WireSock",
    links: {
      windows: "https://www.wiresock.net/wiresock-secure-connect/download",
      macos: "https://www.wiresock.net/downloads/",
      linux: "https://www.wiresock.net/downloads/",
      android: "https://www.wiresock.net/downloads/",
      ios: "https://www.wiresock.net/downloads/",
    },
  },
};

export function currentOs(): OsKey {
  const p = (navigator.userAgent || navigator.platform || "").toLowerCase();
  if (p.includes("win")) return "windows";
  if (p.includes("mac")) return "macos";
  return "linux";
}

export function clientList(): Array<{ key: string; title: string }> {
  return Object.entries(CLIENT_DOWNLOADS).map(([key, c]) => ({ key, title: c.title }));
}

export function downloadUrl(key: string, os: OsKey = currentOs()): string | null {
  return CLIENT_DOWNLOADS[key]?.links[os] ?? null;
}
