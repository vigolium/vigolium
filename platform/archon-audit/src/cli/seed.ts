import { spawnSync } from "child_process";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "fs";
import { tmpdir } from "os";
import { basename, join, resolve } from "path";
import { StateStore } from "../engine/state.js";
import type { AuditRecord } from "../engine/types.js";

export interface ArchonDirSeedOpts {
  /** Path passed to --from-archon-dir. The audit-state.json this references is the source of truth. */
  fromArchonDir: string;
  /** Value of --target, if any. When set, the clone is placed here instead of a temp dir. */
  targetOverride?: string;
  /** When true, leave the clone in place after the run. Only meaningful for temp-dir clones. */
  keepClone: boolean;
  /** Value of --from-audit, if any. Picks a specific audit by id instead of the latest entry. */
  fromAuditId?: string;
}

export interface ArchonDirSeedHandle {
  /** Absolute path to the cloned repo's working tree — pass as targetDir to the orchestrator. */
  clonedTargetDir: string;
  /** Human-readable one-line summary suitable for the [seed] log line. */
  summary: string;
  /**
   * Sync the clone's archon/ back to the original input dir, then remove the
   * clone (unless --keep-clone or --target was set). Idempotent.
   */
  cleanup(): Promise<void>;
}

export async function resolveArchonDirSeed(
  opts: ArchonDirSeedOpts,
): Promise<ArchonDirSeedHandle> {
  const fromDir = resolve(opts.fromArchonDir);
  if (!isDirectory(fromDir)) {
    throw new Error(`--from-archon-dir: not a directory: ${fromDir}`);
  }

  // Support both layouts: the input path can be the archon/ dir itself
  // (audit-state.json directly inside) or a project dir that contains an
  // archon/ subdir. Whichever holds audit-state.json wins.
  const archonDir = findArchonDir(fromDir);
  if (archonDir === null) {
    throw new Error(
      `--from-archon-dir: no audit-state.json found at ${join(fromDir, "audit-state.json")} ` +
        `or ${join(fromDir, "archon", "audit-state.json")}`,
    );
  }

  const state = await new StateStore(archonDir).load();
  if (state.audits.length === 0) {
    throw new Error(`--from-archon-dir: audit-state.json has no audits to seed from`);
  }
  const audit = pickAudit(state.audits, opts.fromAuditId);
  if (!audit) {
    throw new Error(
      `--from-archon-dir: --from-audit ${opts.fromAuditId} not found in ${archonDir}/audit-state.json`,
    );
  }
  if (!audit.repository) {
    throw new Error(
      `--from-archon-dir: audit ${audit.audit_id} has no recorded repository URL (the original run had no git remote). Cannot clone.`,
    );
  }
  if (!audit.commit) {
    throw new Error(
      `--from-archon-dir: audit ${audit.audit_id} has no recorded commit. Cannot pin the clone.`,
    );
  }

  const cloneRoot = resolveCloneDestination(opts.targetOverride, audit.repository);
  cloneRepoAt({ repository: audit.repository, commit: audit.commit, branch: audit.branch, destination: cloneRoot });

  const destArchon = join(cloneRoot, "archon");
  mkdirSync(destArchon, { recursive: true });
  cpSync(archonDir, destArchon, { recursive: true });

  const summary =
    `cloned ${audit.repository}@${audit.commit.slice(0, 7)} to ${cloneRoot}; ` +
    `archon/ copied from ${archonDir}`;

  const isTempClone = opts.targetOverride === undefined;
  let cleanupResolved: Promise<void> | null = null;
  const doCleanup = async (): Promise<void> => {
    cpSync(destArchon, archonDir, { recursive: true });
    if (isTempClone && !opts.keepClone) {
      try {
        rmSync(cloneRoot, { recursive: true, force: true });
      } catch {
        /* best effort — temp cleanup shouldn't crash exit */
      }
    }
  };

  return {
    clonedTargetDir: cloneRoot,
    summary,
    cleanup: () => {
      if (!cleanupResolved) cleanupResolved = doCleanup();
      return cleanupResolved;
    },
  };
}

function isDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function findArchonDir(input: string): string | null {
  if (isDirectory(input) && statSync(join(input, "audit-state.json"), { throwIfNoEntry: false })?.isFile()) {
    return input;
  }
  const nested = join(input, "archon");
  if (statSync(join(nested, "audit-state.json"), { throwIfNoEntry: false })?.isFile()) {
    return nested;
  }
  return null;
}

function pickAudit(audits: AuditRecord[], fromAuditId?: string): AuditRecord | null {
  if (fromAuditId) return audits.find((a) => a.audit_id === fromAuditId) ?? null;
  return audits[audits.length - 1] ?? null;
}

function resolveCloneDestination(targetOverride: string | undefined, repository: string): string {
  if (targetOverride !== undefined) {
    const dest = resolve(targetOverride);
    try {
      const entries = readdirSync(dest);
      if (entries.length > 0) {
        throw new Error(
          `--target ${dest}: directory is non-empty; refusing to clone over existing contents. ` +
            `Pick an empty or non-existent path, or omit --target to use a temp dir.`,
        );
      }
      return dest;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        mkdirSync(dest, { recursive: true });
        return dest;
      }
      if (code === "ENOTDIR") {
        throw new Error(`--target ${dest}: not a directory`);
      }
      throw err;
    }
  }
  const parent = mkdtempSync(join(tmpdir(), "archon-clone-"));
  const slug = repoSlug(repository);
  const dest = join(parent, slug);
  mkdirSync(dest, { recursive: true });
  return dest;
}

/**
 * Best-effort owner-repo slug pulled from common git URL forms. Falls back to
 * the URL's last path component, then "repo", so the result is always non-empty.
 */
export function repoSlug(repository: string): string {
  const trimmed = repository.trim().replace(/\.git$/, "");
  if (trimmed.startsWith("/") || trimmed.startsWith("./") || trimmed.startsWith("../")) {
    const tail = basename(trimmed);
    return tail.length > 0 ? tail : "repo";
  }
  const sshMatch = /:([^/]+)\/([^/]+)$/.exec(trimmed);
  if (sshMatch) return `${sshMatch[1]}-${sshMatch[2]}`;
  const urlMatch = /\/([^/]+)\/([^/]+)$/.exec(trimmed);
  if (urlMatch) return `${urlMatch[1]}-${urlMatch[2]}`;
  const tail = basename(trimmed);
  return tail.length > 0 ? tail : "repo";
}

function cloneRepoAt(args: {
  repository: string;
  commit: string;
  branch: string | null;
  destination: string;
}): void {
  const { repository, commit, branch, destination } = args;
  // --depth=1 is silently ignored for local-path remotes (git uses hardlinks
  // instead); the cat-file precheck handles that case by skipping the fetch.
  const cloneArgs = ["clone", "--no-checkout", "--depth=1"];
  if (branch) cloneArgs.push("--branch", branch);
  cloneArgs.push(repository, destination);
  runGit(cloneArgs, "git clone");

  // Skip the fetch when the commit is already in the object store — saves a
  // network roundtrip on every confirm-mode re-run where the audited branch
  // tip hasn't moved.
  const hasCommit = spawnSync(
    "git",
    ["-C", destination, "cat-file", "-e", `${commit}^{commit}`],
    { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
  );
  if (hasCommit.status !== 0) {
    // Try shallow fetch by SHA first (works on GitHub by default); fall back
    // to a non-shallow fetch for servers that refuse partial SHA-in-want.
    const shallowFetch = spawnSync(
      "git",
      ["-C", destination, "fetch", "--depth=1", "origin", commit],
      { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
    );
    if (shallowFetch.status !== 0) {
      const fullFetch = spawnSync(
        "git",
        ["-C", destination, "fetch", "origin", commit],
        { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" },
      );
      if (fullFetch.status !== 0) {
        throw new Error(
          `git fetch failed: could not reach commit ${commit} on ${repository}. ` +
            `Shallow: ${shallowFetch.stderr.trim() || "(no stderr)"}. ` +
            `Full: ${fullFetch.stderr.trim() || "(no stderr)"}`,
        );
      }
    }
  }

  runGit(["-C", destination, "checkout", commit], "git checkout");
}

function runGit(args: string[], errLabel: string): void {
  const r = spawnSync("git", args, { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error(`${errLabel} failed (exit ${r.status ?? "null"}): ${r.stderr.trim() || r.stdout.trim()}`);
  }
}
