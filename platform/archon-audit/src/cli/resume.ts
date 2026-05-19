import { existsSync } from "fs";
import { resolve, join } from "path";
import chalk from "chalk";
import { StateStore } from "../engine/state.js";
import { failCli } from "./util.js";
import type { AgentPlatform, AuditRecord, AuditMode, RunOptions } from "../engine/types.js";

/**
 * Subset of run flags that `archon resume` accepts and forwards to
 * `runCommand`. Everything else is derived from the prior audit record
 * (mode, target's archon/ contents). We intentionally don't expose
 * --modes, --mode, --interactive, --from-archon-dir, --parallel-modes, or
 * --dry-run on `resume` — those don't make sense for picking up an
 * interrupted audit in place.
 */
export interface ResumeOptions {
  target?: string;
  agent?: string;
  strict?: boolean;
  maxCost?: number | string;
  output?: string;
  oauthToken?: string;
  oauthCredFile?: string;
  apiKey?: string;
  stripRaw?: boolean;
  focusFile?: string;
  expectedBehaviorsFile?: string;
  serial?: boolean;
  json?: boolean;
  debug?: boolean;
  streaming?: boolean;
  git?: boolean;
}

/**
 * Pick the most recent audit in `audits` that did not reach `complete`.
 * Order of preference: `in_progress` (process-killed, quota hit, SIGKILL)
 * → `aborted` (cost cap, strict failure, SIGINT) → `failed` (one or more
 * phases failed but the run finished cleanly). Returns null when every
 * audit is `complete` or the list is empty.
 *
 * Exposed for unit tests; the CLI just calls `resumeCommand`.
 */
export function pickResumableAudit(audits: AuditRecord[]): AuditRecord | null {
  const ordered = [...audits].reverse();
  return (
    ordered.find((a) => a.status === "in_progress") ??
    ordered.find((a) => a.status === "aborted") ??
    ordered.find((a) => a.status === "failed") ??
    null
  );
}

export async function resumeCommand(
  targetPath: string,
  opts: ResumeOptions = {},
): Promise<void> {
  const targetDir = resolve(targetPath || opts.target || ".");
  const archonDir = join(targetDir, "archon");

  if (!existsSync(archonDir)) {
    return failCli(opts, "resume", `no archon/ directory at ${targetDir} — nothing to resume`);
  }

  const store = new StateStore(archonDir);
  let state: { audits: AuditRecord[] };
  try {
    state = await store.load();
  } catch (err) {
    return failCli(opts, "resume", `cannot read audit-state.json: ${(err as Error).message}`);
  }

  const picked = pickResumableAudit(state.audits);
  if (!picked) {
    const total = state.audits.length;
    const msg =
      total === 0
        ? `no audits recorded in ${archonDir}/audit-state.json — start one with \`archon run --mode <mode>\``
        : `every audit in ${archonDir}/audit-state.json is already complete; nothing to resume`;
    return failCli(opts, "resume", msg);
  }

  const completedPhases = Object.values(picked.phases).filter((p) => p.status === "complete").length;
  const totalPhases = Object.keys(picked.phases).length;

  if (!opts.json) {
    console.log(
      chalk.green("[resume]") +
        ` audit ${chalk.cyan(picked.audit_id)} mode=${chalk.cyan(picked.mode)} status=${chalk.yellow(picked.status)} ` +
        chalk.dim(`(${completedPhases}/${totalPhases} phases complete)`),
    );
  }

  const runOpts = buildRunOptions({ mode: picked.mode, targetDir, opts });
  const { runCommand } = await import("./run.js");
  await runCommand(runOpts);
}

function buildRunOptions(args: {
  mode: AuditMode;
  targetDir: string;
  opts: ResumeOptions;
}): RunOptions {
  const { mode, targetDir, opts } = args;
  const runOpts: RunOptions = {
    mode,
    target: targetDir,
    resume: true,
  };
  if (opts.agent !== undefined) runOpts.agent = opts.agent as AgentPlatform;
  if (opts.strict !== undefined) runOpts.strict = opts.strict;
  if (opts.maxCost !== undefined) {
    const n = typeof opts.maxCost === "number" ? opts.maxCost : Number(opts.maxCost);
    if (!Number.isNaN(n)) runOpts.maxCost = n;
  }
  if (opts.output !== undefined) runOpts.output = opts.output;
  if (opts.oauthToken !== undefined) runOpts.oauthToken = opts.oauthToken;
  if (opts.oauthCredFile !== undefined) runOpts.oauthCredFile = opts.oauthCredFile;
  if (opts.apiKey !== undefined) runOpts.apiKey = opts.apiKey;
  if (opts.stripRaw !== undefined) runOpts.stripRaw = opts.stripRaw;
  if (opts.focusFile !== undefined) runOpts.focusFile = opts.focusFile;
  if (opts.expectedBehaviorsFile !== undefined) runOpts.expectedBehaviorsFile = opts.expectedBehaviorsFile;
  if (opts.serial !== undefined) runOpts.serial = opts.serial;
  if (opts.json !== undefined) runOpts.json = opts.json;
  if (opts.debug !== undefined) runOpts.debug = opts.debug;
  if (opts.streaming !== undefined) runOpts.streaming = opts.streaming;
  if (opts.git !== undefined) runOpts.git = opts.git;
  return runOpts;
}
