import { open, readdir, stat } from "fs/promises";
import { homedir } from "os";
import { join } from "path";
import type { AdapterEvent } from "./adapter.js";
import {
  type CodexNormalizeState,
  normalizeCodexSessionRecord,
} from "./codex-events.js";

/**
 * Tail Codex's persisted session JSONL to recover multi-agent lifecycle
 * records omitted by the public SDK/`exec --json` event stream.
 */
export function startCodexSessionTail(
  threadId: string,
  state: CodexNormalizeState,
  push: (evt: AdapterEvent) => void,
  options: { startAtEnd?: boolean } = {},
): { ready: Promise<void>; stop: () => void; flush: () => Promise<void> } {
  let stopped = false;
  let tickPromise: Promise<void> | null = null;
  let sessionFile: string | null = null;
  let offset = 0;
  let pending = "";
  let primed = false;

  const runTick = async (): Promise<void> => {
    if (stopped) return;
    if (sessionFile === null) {
      sessionFile = await findCodexSessionFile(threadId);
      if (sessionFile === null) return;
    }
    const st = await stat(sessionFile).catch(() => null);
    if (!st) {
      sessionFile = null;
      offset = 0;
      pending = "";
      primed = false;
      return;
    }
    if (!primed) {
      primed = true;
      if (options.startAtEnd) {
        offset = st.size;
        return;
      }
    }
    if (st.size < offset) {
      offset = 0;
      pending = "";
    }
    if (st.size === offset) return;
    const length = st.size - offset;
    if (length <= 0) return;
    const buf = Buffer.allocUnsafe(length);
    const fh = await open(sessionFile, "r");
    let bytesRead = 0;
    try {
      const res = await fh.read(buf, 0, length, offset);
      bytesRead = res.bytesRead;
    } finally {
      await fh.close().catch(() => {});
    }
    if (bytesRead <= 0) return;
    offset += bytesRead;
    pending += buf.subarray(0, bytesRead).toString("utf8");
    const lines = pending.split(/\r?\n/);
    pending = lines.pop() ?? "";
    for (const line of lines) {
      if (line.trim().length === 0) continue;
      let record: unknown;
      try {
        record = JSON.parse(line) as unknown;
      } catch {
        continue;
      }
      for (const evt of normalizeCodexSessionRecord(record, state)) push(evt);
    }
  };

  const tick = (): Promise<void> => {
    if (tickPromise) return tickPromise;
    // The persisted log is an optional observability side channel. A missing,
    // unreadable, or concurrently-rotated file must never fail the underlying
    // Codex turn or suppress its finish event.
    tickPromise = runTick()
      .catch(() => {})
      .finally(() => {
        tickPromise = null;
      });
    return tickPromise;
  };

  const timer = setInterval(() => void tick().catch(() => {}), 500);
  const ready = tick();
  return {
    ready,
    flush: async () => {
      await tick();
      await tick();
    },
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}

async function findCodexSessionFile(threadId: string): Promise<string | null> {
  const sessionsRoot = join(process.env.CODEX_HOME ?? join(homedir(), ".codex"), "sessions");
  return findFileByNameFragment(sessionsRoot, threadId, 5);
}

async function findFileByNameFragment(
  dir: string,
  fragment: string,
  depth: number,
): Promise<string | null> {
  if (depth < 0) return null;
  let entries: import("fs").Dirent[];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isFile() && entry.name.includes(fragment) && entry.name.endsWith(".jsonl")) {
      return full;
    }
  }
  const dirs = entries
    .filter((entry) => entry.isDirectory())
    .sort((a, b) => b.name.localeCompare(a.name));
  for (const entry of dirs) {
    const found = await findFileByNameFragment(join(dir, entry.name), fragment, depth - 1);
    if (found) return found;
  }
  return null;
}
