import { spawnSync } from "child_process";
import { mkdirSync, readdirSync, statSync } from "fs";
import { resolve } from "path";
import { repoSlug } from "./seed.js";

/**
 * Detect when `--target` / `--source` is a remote git URL we should clone
 * rather than treat as a local path. Recognized forms:
 *   - https://github.com/owner/repo[.git][/]
 *   - https://gitlab.com/owner/repo[.git][/]
 *   - http(s)://any-host/path  (catch-all for self-hosted forges)
 *   - git://host/path
 *   - ssh://user@host/path
 *   - scp-style: user@host:owner/repo
 *
 * Local paths (./repo, ../repo, /tmp/repo, plain repo) always return false.
 */
export function isRemoteTargetUrl(input: string): boolean {
  if (input.length === 0) return false;
  if (/^(https?|git|ssh):\/\//i.test(input)) return true;
  if (/^[\w.-]+@[\w.-]+:[^/]/.test(input)) return true;
  return false;
}

export interface CloneRemoteTargetResult {
  /** Absolute path to the cloned working tree — pass as targetDir to the orchestrator. */
  clonedTargetDir: string;
  /** Human-readable one-line summary suitable for a `[clone]` log line. */
  summary: string;
  /** True when an existing same-remote checkout was reused instead of cloning fresh. */
  reused: boolean;
}

/**
 * Clone a remote repo into `./<repo-slug>/` under the current working
 * directory. If the destination already exists and points at the same
 * remote, reuse it (no fetch / pull — we don't want to silently mutate
 * an existing working tree). If it exists with a different remote (or
 * is a non-git directory with content), refuse to clobber.
 *
 * Persistent clone — no cleanup hook. The user can rm -rf the slug
 * directory themselves once they're done.
 */
export function cloneRemoteTarget(repository: string): CloneRemoteTargetResult {
  const cwd = process.cwd();
  const slug = repoSlug(repository);
  if (slug.length === 0) {
    throw new Error(`could not derive a directory name from ${repository}`);
  }
  const dest = resolve(cwd, slug);

  const existing = inspectDestination(dest);
  if (existing.kind === "non-empty-non-git") {
    throw new Error(
      `--target ${dest}: directory exists and is non-empty but not a git checkout. ` +
        `Remove it or run from a different working directory.`,
    );
  }
  if (existing.kind === "git-checkout") {
    if (normalizeRemote(existing.remote) === normalizeRemote(repository)) {
      return {
        clonedTargetDir: dest,
        summary: `reusing existing checkout at ${dest} (remote matches ${repository})`,
        reused: true,
      };
    }
    throw new Error(
      `--target ${dest}: directory is a git checkout of a different remote (${existing.remote}). ` +
        `Remove it or run from a different working directory.`,
    );
  }

  if (existing.kind === "missing") {
    mkdirSync(dest, { recursive: true });
  }
  // existing.kind === "empty" || "missing" → safe to clone in.
  const r = spawnSync(
    "git",
    ["clone", "--depth=1", repository, dest],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  if (r.status !== 0) {
    throw new Error(
      `git clone failed (exit ${r.status ?? "null"}): ${r.stderr.trim() || r.stdout.trim() || "(no output)"}`,
    );
  }
  return {
    clonedTargetDir: dest,
    summary: `cloned ${repository} → ${dest} (depth=1)`,
    reused: false,
  };
}

type DestinationState =
  | { kind: "missing" }
  | { kind: "empty" }
  | { kind: "non-empty-non-git" }
  | { kind: "git-checkout"; remote: string };

function inspectDestination(dest: string): DestinationState {
  let entries: string[];
  try {
    const st = statSync(dest);
    if (!st.isDirectory()) {
      return { kind: "non-empty-non-git" };
    }
    entries = readdirSync(dest);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { kind: "missing" };
    throw err;
  }
  if (entries.length === 0) return { kind: "empty" };
  if (!entries.includes(".git")) return { kind: "non-empty-non-git" };
  const remote = readRemote(dest);
  if (remote === null) return { kind: "non-empty-non-git" };
  return { kind: "git-checkout", remote };
}

function readRemote(dest: string): string | null {
  const r = spawnSync(
    "git",
    ["-C", dest, "remote", "get-url", "origin"],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  if (r.status !== 0) return null;
  const out = r.stdout.trim();
  return out.length > 0 ? out : null;
}

/**
 * Normalize a remote URL for equality comparison. Strips trailing `.git`
 * and any trailing slash so e.g. `https://github.com/o/r` and
 * `https://github.com/o/r.git/` compare equal. Exported for tests.
 */
export function normalizeRemote(url: string): string {
  return url.trim().replace(/\/$/, "").replace(/\.git$/, "");
}
