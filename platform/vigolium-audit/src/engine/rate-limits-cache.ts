import { existsSync, mkdirSync } from "fs";
import { readFile, writeFile } from "fs/promises";
import { homedir } from "os";
import { dirname, join } from "path";
import type { RateLimitsSnapshot, RateLimitsWindow } from "../adapters/adapter.js";

/**
 * On-disk snapshot of the last `rate_limits` block we saw in a Claude API
 * response. Harvested passively by the orchestrator during `vigolium-audit run` so
 * `vigolium-audit usage` can show /usage-style quota state without making a probe
 * call. `fetched_at` lets readers detect staleness.
 */
export interface RateLimitsCacheEntry {
  fetched_at: string;
  data: RateLimitsSnapshot;
}

export function cachePath(): string {
  const override = process.env.VIGOLIUM_AUDIT_RATE_LIMITS_CACHE;
  if (override !== undefined && override.length > 0) return override;
  const xdg = process.env.XDG_CONFIG_HOME;
  const base = xdg !== undefined && xdg.length > 0 ? xdg : join(homedir(), ".config");
  return join(base, "vigolium-results", "rate-limits-cache.json");
}

/**
 * Merge `snapshot` into the existing cache (or write fresh when none exists).
 * Each rate_limit_event covers only ONE window, so callers feed us partial
 * snapshots and we accumulate them. Windows present in `snapshot` overwrite
 * their cached counterpart; untouched windows keep their prior value.
 */
export async function writeCache(snapshot: RateLimitsSnapshot, now: Date = new Date()): Promise<void> {
  const path = cachePath();
  mkdirSync(dirname(path), { recursive: true });
  const existing = await readCache();
  const merged: RateLimitsSnapshot = { ...(existing?.data ?? {}), ...snapshot };
  const entry: RateLimitsCacheEntry = {
    fetched_at: now.toISOString(),
    data: merged,
  };
  await writeFile(path, JSON.stringify(entry, null, 2) + "\n", "utf8");
}

export async function readCache(): Promise<RateLimitsCacheEntry | null> {
  const path = cachePath();
  if (!existsSync(path)) return null;
  try {
    const raw = await readFile(path, "utf8");
    const obj = JSON.parse(raw);
    if (typeof obj !== "object" || obj === null) return null;
    if (typeof obj.fetched_at !== "string") return null;
    if (typeof obj.data !== "object" || obj.data === null) return null;
    return obj as RateLimitsCacheEntry;
  } catch {
    return null;
  }
}

export function ageMs(entry: RateLimitsCacheEntry, now: Date = new Date()): number {
  return now.getTime() - new Date(entry.fetched_at).getTime();
}

/**
 * Best-effort projection of the current `used_percentage` for a window
 * whose snapshot was taken some time ago. Linear interpolation between
 * "snapshot time" and "reset time" assuming usage doesn't continue. If
 * the reset already passed, the window has rolled over and used_percentage
 * is reset to 0. Conservative — real usage may be higher if more API calls
 * have happened since the snapshot.
 */
export function projectWindow(win: RateLimitsWindow, snapshotAt: Date, now: Date = new Date()): RateLimitsWindow {
  const resetsAtMs = win.resets_at * 1000;
  if (now.getTime() >= resetsAtMs) {
    return { used_percentage: 0, resets_at: win.resets_at };
  }
  // Snapshot was taken before reset; usage already accrued doesn't change
  // unless more calls were made (which we can't know). Return as-is.
  void snapshotAt;
  return win;
}

/** Format the time until reset like "2h 14m" or "23m" or "<1m". */
export function formatResetsIn(resetsAt: number, now: Date = new Date()): string {
  const ms = resetsAt * 1000 - now.getTime();
  if (ms <= 0) return "now";
  const totalMin = Math.floor(ms / 60_000);
  if (totalMin < 1) return "<1m";
  const days = Math.floor(totalMin / (60 * 24));
  const hours = Math.floor((totalMin % (60 * 24)) / 60);
  const mins = totalMin % 60;
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}
