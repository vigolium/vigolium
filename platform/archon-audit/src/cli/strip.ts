import { existsSync, statSync } from "fs";
import { resolve, basename, join } from "path";
import chalk from "chalk";
import { stripRawArtifacts } from "../engine/orchestrator.js";

export interface StripOptions {
  json?: boolean;
}

/**
 * `archon strip <path>` — apply the same post-audit pruning that the
 * orchestrator's `--strip-raw` flag does, on demand. Accepts either the
 * project directory (containing `archon/`) or the `archon/` directory itself.
 *
 * Always preserved: durable state JSON (`audit-state.json`, `file-state.json`,
 * revisit state), `findings/`, `findings-theoretical/`, `attack-surface/`,
 * `confirm-workspace/`, `quarantine/`, and any top-level `*.md` reports.
 * Drafts in `findings-draft/` are promoted into `findings/` before deletion
 * (without clobbering same-named finals).
 */
export async function stripCommand(targetPath: string, opts: StripOptions): Promise<void> {
  const json = !!opts.json;
  const fail = (msg: string, exit = 2): never => {
    if (json) process.stdout.write(JSON.stringify({ ok: false, error: msg }) + "\n");
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(exit);
  };

  const resolved = resolve(targetPath);
  if (!existsSync(resolved)) {
    return fail(`path does not exist: ${resolved}`);
  }
  if (!statSync(resolved).isDirectory()) {
    return fail(`path is not a directory: ${resolved}`);
  }

  // Accept either `archon/` directly (audit-state.json sibling) or a project
  // dir that contains an `archon/` subdir. We refuse to operate on directories
  // that look like neither, to avoid nuking unrelated trees.
  const looksLikeArchonDir =
    basename(resolved) === "archon" || existsSync(join(resolved, "audit-state.json"));
  const archonDir = looksLikeArchonDir ? resolved : join(resolved, "archon");

  if (!existsSync(archonDir)) {
    return fail(`no archon/ directory found at ${archonDir}`);
  }
  if (!existsSync(join(archonDir, "audit-state.json"))) {
    return fail(
      `${archonDir} doesn't look like an archon audit folder (no audit-state.json) — refusing to strip`,
    );
  }

  await stripRawArtifacts(archonDir);

  if (json) {
    process.stdout.write(JSON.stringify({ ok: true, archonDir }) + "\n");
  } else {
    console.log(chalk.green(`[archon] stripped raw artifacts from ${archonDir}`));
  }
}
