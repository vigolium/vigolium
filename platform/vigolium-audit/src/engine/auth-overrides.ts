import { copyFileSync, existsSync, realpathSync, renameSync, unlinkSync } from "fs";
import { homedir } from "os";
import { join, resolve } from "path";
import { platformApiKeyEnv } from "../adapters/detect.js";
import type { AgentPlatform } from "./types.js";

export { platformApiKeyEnv };

export interface AuthOverrideOpts {
  platform: AgentPlatform;
  /** Sets CLAUDE_CODE_OAUTH_TOKEN for the subprocess / SDK. Claude-specific. */
  oauthToken?: string;
  /**
   * Path to a credentials file (json). Replaces the platform's auth file
   * for the lifetime of the run; the original is moved to a sibling
   * `.vigolium-audit-backup` slot and restored on exit.
   *   claude → ~/.claude/.credentials.json
   *   codex  → ~/.codex/auth.json
   */
  oauthCredFile?: string;
  /**
   * API key. Routed by platform:
   *   claude → ANTHROPIC_API_KEY
   *   codex  → OPENAI_API_KEY
   */
  apiKey?: string;
}

export interface AuthOverrideHandle {
  /** Reverts every env mutation and file swap. Idempotent. */
  restore(): void;
  /** Human-readable summary of what was applied. */
  summary(): string;
}

interface SavedEnv {
  key: string;
  prev: string | undefined;
}

interface SavedFile {
  target: string;
  backupPath: string | null; // null → target didn't exist before; remove on restore
}

const BACKUP_SUFFIX = ".vigolium-audit-backup";

export function platformCredFilePath(platform: AgentPlatform): string {
  if (platform === "claude") {
    return join(homedir(), ".claude", ".credentials.json");
  }
  return join(homedir(), ".codex", "auth.json");
}

export function applyAuthOverrides(opts: AuthOverrideOpts): AuthOverrideHandle {
  const savedEnv: SavedEnv[] = [];
  const savedFiles: SavedFile[] = [];
  const noteCodexNoop = opts.platform === "codex" && !!opts.oauthToken;
  let credFileNoop = false;

  const setEnv = (key: string, value: string): void => {
    savedEnv.push({ key, prev: process.env[key] });
    process.env[key] = value;
  };

  let restored = false;
  const restore = (): void => {
    if (restored) return;
    restored = true;
    process.removeListener("exit", hookExit);
    // Reverse order so a key set twice unwinds cleanly to its original value.
    for (let i = savedEnv.length - 1; i >= 0; i--) {
      const { key, prev } = savedEnv[i]!;
      if (prev === undefined) delete process.env[key];
      else process.env[key] = prev;
    }
    for (let i = savedFiles.length - 1; i >= 0; i--) {
      const { target, backupPath } = savedFiles[i]!;
      try {
        unlinkSync(target);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
          /* best effort */
        }
      }
      if (backupPath) {
        try {
          renameSync(backupPath, target);
        } catch {
          /* best effort */
        }
      }
    }
  };

  // Catch unclean shutdowns (process.exit from elsewhere, uncaught throws).
  // Signals (SIGINT/SIGTERM) are NOT hooked here — that's the caller's job;
  // hooking them would race with run.ts's graceful-abort handler.
  const hookExit = (): void => restore();
  process.once("exit", hookExit);

  const handle: AuthOverrideHandle = {
    restore,
    summary: () => {
      const parts: string[] = [];
      for (const { key } of savedEnv) {
        const v = process.env[key];
        const note = key === "CLAUDE_CODE_OAUTH_TOKEN" && noteCodexNoop ? " (no-op for codex)" : "";
        parts.push(`${key}=${redact(v ?? "")}${note}`);
      }
      for (const { target, backupPath } of savedFiles) {
        parts.push(`cred-file: → ${target}${backupPath ? " (backed up)" : " (no prior file)"}`);
      }
      if (credFileNoop) {
        parts.push(`cred-file: → ${platformCredFilePath(opts.platform)} (already in place)`);
      }
      return parts.join("; ") || "(none)";
    },
  };

  if (opts.oauthToken) setEnv("CLAUDE_CODE_OAUTH_TOKEN", opts.oauthToken);
  if (opts.apiKey) setEnv(platformApiKeyEnv(opts.platform), opts.apiKey);

  if (opts.oauthCredFile) {
    const src = resolve(opts.oauthCredFile);
    if (!existsSync(src)) throw new Error(`--oauth-cred-file: file not found: ${src}`);
    const target = platformCredFilePath(opts.platform);
    // If src and target are the same file (common when the user passes the
    // platform's default cred path), there's nothing to swap — the auth file
    // is already in place. Skip rename+copy to avoid renaming src out from
    // under ourselves.
    if (samePath(src, target)) {
      credFileNoop = true;
      return handle;
    }
    const backup = `${target}${BACKUP_SUFFIX}`;
    if (existsSync(backup)) {
      throw new Error(
        `stale backup at ${backup} (from a previous crashed run). ` +
          `Inspect, then either remove it or restore it before re-running.`,
      );
    }
    // Try to rename target → backup. If target doesn't exist, ENOENT means
    // "no prior file" — backupPath stays null and we just write the override.
    let backupPath: string | null = null;
    try {
      renameSync(target, backup);
      backupPath = backup;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    try {
      copyFileSync(src, target);
    } catch (err) {
      // Roll back the rename so we don't lose the user's creds.
      if (backupPath) {
        try {
          renameSync(backupPath, target);
        } catch {
          /* best effort */
        }
      }
      throw new Error(`--oauth-cred-file: failed to write ${target}: ${(err as Error).message}`);
    }
    savedFiles.push({ target, backupPath });
  }

  return handle;
}

/**
 * True when two paths refer to the same file. Resolves symlinks via
 * realpathSync where possible; falls back to string equality when either
 * path doesn't exist on disk.
 */
function samePath(a: string, b: string): boolean {
  if (a === b) return true;
  try {
    return realpathSync(a) === realpathSync(b);
  } catch {
    return false;
  }
}

function redact(secret: string): string {
  if (secret.length <= 12) return "***";
  return `${secret.slice(0, 8)}…${secret.slice(-4)}`;
}
