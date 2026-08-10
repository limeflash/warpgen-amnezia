// Thin localStorage JSON helpers for settings + config history persistence.
// The webview's localStorage is per-app and survives restarts.

export function loadJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

export function saveJson(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* quota / disabled storage — ignore */
  }
}

export interface HistoryEntry {
  id: number;
  ts: number;
  configType: string;
  endpoint: string;
  tag: string;
  config: string;
}

const HISTORY_KEY = "warpgen.history";
const HISTORY_MAX = 20;

export function loadHistory(): HistoryEntry[] {
  return loadJson<HistoryEntry[]>(HISTORY_KEY, []);
}

export function addHistory(entry: Omit<HistoryEntry, "id" | "ts" | "tag"> & { tag?: string }): HistoryEntry[] {
  const now = Date.now();
  const list = loadHistory();
  list.unshift({ id: now, ts: now, tag: entry.tag ?? "", configType: entry.configType, endpoint: entry.endpoint, config: entry.config });
  const trimmed = list.slice(0, HISTORY_MAX);
  saveJson(HISTORY_KEY, trimmed);
  return trimmed;
}

export function updateHistoryTag(id: number, tag: string): void {
  const list = loadHistory().map((e) => (e.id === id ? { ...e, tag } : e));
  saveJson(HISTORY_KEY, list);
}

export function deleteHistory(id: number): HistoryEntry[] {
  const list = loadHistory().filter((e) => e.id !== id);
  saveJson(HISTORY_KEY, list);
  return list;
}

export function clearHistory(): void {
  saveJson(HISTORY_KEY, []);
}
