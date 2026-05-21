import { cp, mkdir, readdir, rm, stat } from "fs/promises";
import { existsSync } from "fs";
import { join, relative, sep } from "path";

/**
 * Mirror `srcDir` → `destDir`. Files added/modified in src are copied to
 * dest; files present in dest but missing from src are removed. If src
 * doesn't exist this is a no-op (nothing to sync yet).
 *
 * This is intentionally a full walk on every call — it's only invoked at
 * phase boundaries, not on every file write, so the cost is bounded by the
 * audit dir size (typically a few MB).
 */
export async function mirrorDir(srcDir: string, destDir: string): Promise<void> {
  if (!existsSync(srcDir)) return;
  const srcStat = await stat(srcDir);
  if (!srcStat.isDirectory()) {
    throw new Error(`mirrorDir: source ${srcDir} is not a directory`);
  }
  await mkdir(destDir, { recursive: true });

  const srcPaths = await collectRelPaths(srcDir);
  const destPaths = existsSync(destDir) ? await collectRelPaths(destDir) : new Set<string>();

  for (const rel of srcPaths) {
    const from = join(srcDir, rel);
    const to = join(destDir, rel);
    const s = await stat(from);
    if (s.isDirectory()) {
      await mkdir(to, { recursive: true });
    } else {
      await cp(from, to, { force: true });
    }
  }

  // Reverse-sort so deeper paths are removed before their parents.
  const toRemove = [...destPaths].filter((rel) => !srcPaths.has(rel)).sort((a, b) => b.length - a.length);
  for (const rel of toRemove) {
    await rm(join(destDir, rel), { recursive: true, force: true });
  }
}

async function collectRelPaths(root: string): Promise<Set<string>> {
  const out = new Set<string>();
  await walk(root, root, out);
  return out;
}

async function walk(root: string, dir: string, out: Set<string>): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const ent of entries) {
    const full = join(dir, ent.name);
    const rel = relative(root, full);
    out.add(rel);
    if (ent.isDirectory()) await walk(root, full, out);
  }
}

/**
 * Reject paths that would cause a recursive copy. `outputDir` must not be
 * `srcDir` itself nor a descendant of it; otherwise the mirror would copy
 * itself into itself forever.
 */
export function assertOutputNotNested(outputDir: string, srcDir: string): void {
  if (outputDir === srcDir) {
    throw new Error(`--output cannot equal the vigolium-results working dir (${srcDir})`);
  }
  if (outputDir.startsWith(srcDir + sep)) {
    throw new Error(
      `--output ${outputDir} is inside the vigolium-results working dir (${srcDir}); pass a path outside <target>/vigolium-results/`,
    );
  }
}

/**
 * Serializes mirror calls so concurrent phaseEnd events (parallel-modes)
 * don't overlap and corrupt the destination. Each call awaits any prior
 * sync before starting.
 */
export class OutputSyncer {
  private queue: Promise<void> = Promise.resolve();
  private lastError: Error | null = null;

  constructor(
    private readonly srcDir: string,
    private readonly destDir: string,
    private readonly onError: (err: Error) => void = () => {},
  ) {}

  sync(): Promise<void> {
    this.queue = this.queue.then(async () => {
      try {
        await mirrorDir(this.srcDir, this.destDir);
      } catch (err) {
        this.lastError = err as Error;
        this.onError(err as Error);
      }
    });
    return this.queue;
  }

  async drain(): Promise<void> {
    await this.queue;
  }

  getLastError(): Error | null {
    return this.lastError;
  }
}
