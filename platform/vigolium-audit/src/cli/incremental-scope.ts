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

export interface ChangedFile {
  path: string;
  reason: "git-diff" | "hash-mismatch" | "missing-from-state";
  /** Phases that previously touched this file (from file-state.json). */
  priorPhases: string[];
}

export interface IncrementalScope {
  targetDir: string;
  since: string | null;
  /** Whether a file-state.json baseline was found and read. */
  baselinePresent: boolean;
  changed: ChangedFile[];
  /** Union of phases that touched the changed files in prior audits. */
  phasesPriorlyTouching: string[];
}

/**
 * Compute the set of files that have changed since the last audit baseline.
 * Pure (no console output) so callers — the CLI renderer below, and a future
 * incremental-audit driver — can consume the result programmatically.
 *
 * Three signals, merged in order of authority:
 *   1. `git diff --name-only <since>..HEAD` when --since is supplied.
 *   2. `git ls-files` + SHA256 vs. file-state.json: files whose hash drifted
 *      since the snapshot recorded by the last complete audit.
 *   3. tracked files with no entry in file-state.json (new files).
 *
 * @throws if the target isn't a git repository.
 */
export async function computeIncrementalScope(opts: { target?: string; since?: string } = {}): Promise<IncrementalScope> {
  const targetDir = resolve(opts.target ?? ".");
  const git = probeGit(targetDir);
  if (!git.available) {
    throw new Error(`target ${targetDir} is not a git repository — incremental scope needs a git tree`);
  }

  const tracked = listTrackedFiles(targetDir);
  const fromDiff = opts.since ? new Set(listChangedFiles(targetDir, opts.since)) : new Set<string>();

  // Load prior file-state snapshot. When absent, we have nothing to compare
  // hashes against; fall back to treating every tracked file as "new".
  const store = new StateStore(join(targetDir, "vigolium-results"));
  const filesIndex = existsSync(join(targetDir, "vigolium-results", "file-state.json"))
    ? (await store.loadFileState().catch(() => null))
    : null;

  // Hash in parallel (IO-bound; tracked file counts run into the tens of
  // thousands), mirroring the producer side in StateStore.recordFileSnapshot.
  // Promise.all preserves order, which the dedup + truncated render rely on.
  const classified = await Promise.all(
    tracked.map(async (rel): Promise<ChangedFile | null> => {
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
      return reason === null ? null : { path: rel, reason, priorPhases: indexed?.last_phases ?? [] };
    }),
  );
  const changed: ChangedFile[] = classified.filter((c): c is ChangedFile => c !== null);

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

  return {
    targetDir,
    since: opts.since ?? null,
    baselinePresent: filesIndex !== null,
    changed,
    phasesPriorlyTouching: uniq(changed.flatMap((c) => c.priorPhases)),
  };
}

export async function incrementalScopeCommand(opts: ScopeOptions = {}): Promise<void> {
  let scope: IncrementalScope;
  try {
    scope = await computeIncrementalScope({
      ...(opts.target !== undefined ? { target: opts.target } : {}),
      ...(opts.since !== undefined ? { since: opts.since } : {}),
    });
  } catch (err) {
    return fail(opts, (err as Error).message);
  }
  const { targetDir, changed, baselinePresent, phasesPriorlyTouching: phasesUnion } = scope;

  if (opts.json) {
    process.stdout.write(
      JSON.stringify({
        kind: "incrementalScope",
        targetDir,
        since: scope.since,
        baselinePresent,
        changed,
        phasesPriorlyTouching: phasesUnion,
      }) + "\n",
    );
    return;
  }

  console.log(chalk.bold(`\nvigolium-audit — incremental scope for ${chalk.cyan(targetDir)}`));
  console.log(`${statusArrow("Baseline")} Baseline:  ${baselinePresent ? chalk.green("file-state.json present") : chalk.yellow("none — first run")}`);
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
