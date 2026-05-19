import { existsSync } from "fs";
import { resolve, join } from "path";
import chalk from "chalk";
import { listChangedFiles, listTrackedFiles, probeGit } from "../engine/git.js";
import { StateStore } from "../engine/state.js";
import { sha256OfFile } from "../engine/util.js";
import { failCli, statusArrow } from "./util.js";

interface ScopeOptions {
  target?: string;
  since?: string;
  json?: boolean;
}

interface ChangedFile {
  path: string;
  reason: "git-diff" | "hash-mismatch" | "missing-from-state";
  /** Phases that previously touched this file (from file-state.json). */
  priorPhases: string[];
}

/**
 * Compute the set of files that have changed since the last audit baseline.
 *
 * Three signals, merged in order of authority:
 *   1. `git diff --name-only <since>..HEAD` when --since is supplied.
 *   2. `git ls-files` + SHA256 vs. file-state.json: files whose hash drifted
 *      since the snapshot recorded by the last complete audit.
 *   3. tracked files with no entry in file-state.json (new files).
 *
 * Output is the union of changed files and the union of phases that touched
 * them in prior audits — so callers can derive a "phases worth re-running"
 * set for incremental audits, or pipe it into --focus-file.
 */
export async function incrementalScopeCommand(opts: ScopeOptions = {}): Promise<void> {
  const targetDir = resolve(opts.target ?? ".");
  const git = probeGit(targetDir);

  if (!git.available) {
    return fail(opts, `target ${targetDir} is not a git repository — incremental scope needs a git tree`);
  }

  const tracked = listTrackedFiles(targetDir);
  const fromDiff = opts.since ? new Set(listChangedFiles(targetDir, opts.since)) : new Set<string>();

  // Load prior file-state snapshot. When absent, we have nothing to compare
  // hashes against; fall back to treating every tracked file as "new".
  const store = new StateStore(join(targetDir, "archon"));
  const filesIndex = existsSync(join(targetDir, "archon", "file-state.json"))
    ? (await store.loadFileState().catch(() => null))
    : null;

  const changed: ChangedFile[] = [];
  for (const rel of tracked) {
    const indexed = filesIndex?.files[rel];
    let reason: ChangedFile["reason"] | null = null;
    if (fromDiff.has(rel)) {
      reason = "git-diff";
    } else if (!indexed) {
      reason = filesIndex ? "missing-from-state" : null;
    } else {
      const actual = await sha256OfFile(join(targetDir, rel));
      if (actual !== indexed.sha256) reason = "hash-mismatch";
    }
    if (reason !== null) {
      changed.push({ path: rel, reason, priorPhases: indexed?.last_phases ?? [] });
    }
  }

  // Also surface files in the diff that aren't tracked anymore (deletions).
  for (const rel of fromDiff) {
    if (!tracked.includes(rel) && !changed.find((c) => c.path === rel)) {
      changed.push({
        path: rel,
        reason: "git-diff",
        priorPhases: filesIndex?.files[rel]?.last_phases ?? [],
      });
    }
  }

  const phasesUnion = uniq(changed.flatMap((c) => c.priorPhases));

  if (opts.json) {
    process.stdout.write(
      JSON.stringify({
        kind: "incrementalScope",
        targetDir,
        since: opts.since ?? null,
        baselinePresent: filesIndex !== null,
        changed,
        phasesPriorlyTouching: phasesUnion,
      }) + "\n",
    );
    return;
  }

  console.log(chalk.bold(`\narchon — incremental scope for ${chalk.cyan(targetDir)}`));
  console.log(`${statusArrow("Baseline")} Baseline:  ${filesIndex ? chalk.green("file-state.json present") : chalk.yellow("none — first run")}`);
  if (opts.since) console.log(`${statusArrow("Diff ref")} Diff ref:  ${chalk.cyan(opts.since)} → HEAD`);
  console.log(`${statusArrow("Changed")} Changed:   ${chalk.magenta(changed.length)} file(s)`);
  for (const c of changed.slice(0, 50)) {
    console.log(`  ${chalk.dim("·")} ${c.path} ${chalk.dim(`(${c.reason})`)}` +
      (c.priorPhases.length > 0 ? chalk.dim(`  prior phases: ${c.priorPhases.join(", ")}`) : ""));
  }
  if (changed.length > 50) console.log(chalk.dim(`  …(+${changed.length - 50} more)`));
  console.log(`${statusArrow("Phases")} Phases:    ${phasesUnion.length > 0 ? phasesUnion.join(", ") : chalk.dim("(none recorded yet)")}`);
}

function uniq(items: string[]): string[] {
  return Array.from(new Set(items));
}

function fail(opts: ScopeOptions, msg: string): never {
  return failCli(opts, "incrementalScope", msg);
}
