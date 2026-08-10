/**
 * The service taxonomy exactly as the design defines it: six categories, a
 * two-letter mark per service and a hue derived from the service id. Kept in
 * the mockup's own format so it can be diffed against it verbatim.
 */
const SVCCAT: Record<string, string> = {
  ai: "ChatGPT|GP,Claude|CL,Gemini|GM,Grok|GR,Copilot|CP,Perplexity|PX,Midjourney|MJ,Hugging Face|HF,Mistral|MI,DeepSeek|DS",
  social:
    "Discord|DC,Telegram|TG,WhatsApp|WA,Signal|SG,X.com|X,Instagram|IG,Facebook|FB,Reddit|RD,TikTok|TT,Viber|VB,Snapchat|SN,Threads|TH,Bluesky|BS,Mastodon|MA,Pinterest|PI,LinkedIn|LI,Skype|SK,Matrix|MX",
  media:
    "YouTube|YT,Netflix|NF,Spotify|SF,Twitch|TW,Disney+|DP,HBO Max|HB,Prime Video|PV,SoundCloud|SC,Deezer|DZ,Apple Music|AM,Vimeo|VI,Crunchyroll|CR,Rutracker|RU,1337x|13,Торренты|TR,IMDb|IM",
  games:
    "Steam|ST,Epic Games|EP,Battle.net|BN,EA App|EA,Ubisoft|UB,PlayStation|PS,Xbox|XB,Nintendo|NI,Roblox|RX,FACEIT|FC,CS2|CS,Apex|AX,PUBG|PG,Valorant|VA,Genshin|GI,Hearthstone|HS,GOG|GG,Riot|RI",
  dev: "GitHub|GH,GitLab|GL,Docker|DK,npm|NP,JetBrains|JB,Figma|FG,Slack|SL,Notion|NO,Stack Overflow|SO,Vercel|VC,Netlify|NL,Bitbucket|BB,Postman|PM,Atlassian|AT,Homebrew|HW,PyPI|PY",
  cloud:
    "AWS|AW,Cloudflare|CF,Google Cloud|GC,Azure|AZ,Apple|AP,Samsung|SM,PayPal|PP,Binance|BI,Bybit|BY,Coinbase|CO,Dropbox|DB,OneDrive|OD,Oracle|OR,Speedtest|SP,Fast.com|FA,Whoer|WH,2IP|2I,geosite:ru|RU",
};

/** Categories and their captions, in the design's order. */
export const SVC_CATEGORIES: Array<{ value: string; label: string }> = [
  { value: "all", label: "Все" },
  { value: "ai", label: "AI" },
  { value: "social", label: "Соцсети" },
  { value: "media", label: "Медиа" },
  { value: "games", label: "Игры" },
  { value: "dev", label: "Разработка" },
  { value: "cloud", label: "Облака" },
];

/** Our catalog's category ids → the design's buckets. */
export const CATEGORY_MAP: Record<string, string> = {
  ai: "ai",
  social: "social",
  media: "media",
  gaming: "games",
  developer: "dev",
  cloud: "cloud",
  block: "cloud", // the design keeps the utility entries with the cloud ones
};

export interface DesignService {
  /** Two-letter mark. */
  mark: string;
  category: string;
  hue: number;
}

/** The design's id: lowercase, letters and digits only. */
export const svcId = (name: string): string =>
  name.toLowerCase().replace(/[^a-z0-9]/g, "");

/** Hue for the tile, same walk the mockup does over the id. */
export function svcHue(id: string): number {
  let h = 7;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) % 360;
  return h;
}

const byName = new Map<string, DesignService>();
for (const [category, list] of Object.entries(SVCCAT)) {
  for (const entry of list.split(",")) {
    const [name, mark] = entry.split("|");
    const id = svcId(name) || mark.toLowerCase();
    byName.set(svcId(name), { mark, category, hue: svcHue(id) });
  }
}

/** What the design would show for this service name, if it knows it. */
export const designService = (name: string): DesignService | undefined => byName.get(svcId(name));

/** Tile colour, exactly the design's formula. */
export const tileColor = (hue: number): string => `oklch(0.60 0.13 ${hue})`;
