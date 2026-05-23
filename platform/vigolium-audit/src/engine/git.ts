import { spawnSync } from "child_process";

export interface GitInfo {
  available: boolean;
  branch: string | null;
  commit: string | null;
  repository: string | null;
}

export function probeGit(targetDir: string): GitInfo {
  if (runGit(["rev-parse", "--is-inside-work-tree"], targetDir) !== "true") {
    return { available: false, branch: null, commit: null, repository: null };
  }
  const branchRaw = runGit(["rev-parse", "--abbrev-ref", "HEAD"], targetDir);
  const branch = branchRaw === "HEAD" ? null : branchRaw;
  const commit = runGit(["rev-parse", "HEAD"], targetDir);
  const remote = runGit(["config", "--get", "remote.origin.url"], targetDir);
  return {
    available: branch != null && commit != null,
    branch,
    commit,
    repository: remote,
  };
}

function runGit(args: string[], cwd: string): string | null {
  const result = spawnSync("git", args, { cwd, stdio: ["ignore", "pipe", "ignore"], encoding: "utf8" });
  if (result.status !== 0) return null;
  const out = (result.stdout ?? "").trim();
  return out.length > 0 ? out : null;
}

/**
 * `git ls-files` — every tracked file in the target. Returns an empty array
 * when the target isn't a git repo or the command fails. Paths are repo-relative.
 */
export function listTrackedFiles(targetDir: string): string[] {
  const result = spawnSync("git", ["ls-files"], {
    cwd: targetDir,
    stdio: ["ignore", "pipe", "ignore"],
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
  });
  if (result.status !== 0) return [];
  return (result.stdout ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Files changed between two git refs (or since one ref to HEAD). Repo-relative paths. */
export function listChangedFiles(targetDir: string, fromRef: string, toRef = "HEAD"): string[] {
  const result = spawnSync("git", ["diff", "--name-only", `${fromRef}..${toRef}`], {
    cwd: targetDir,
    stdio: ["ignore", "pipe", "ignore"],
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.status !== 0) return [];
  return (result.stdout ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}
