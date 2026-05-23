import { existsSync } from "fs";
import { resolve, join } from "path";
import chalk from "chalk";
import { StateStore } from "../engine/state.js";
import { failCli, parsePositiveUsd } from "./util.js";
import type { AgentPlatform, AuditRecord, AuditMode, RunOptions } from "../engine/types.js";

/**
 * Subset of run flags that `vigolium-audit resume` accepts and forwards to
 * `runCommand`. Everything else is derived from the prior audit record
 * (mode, target's vigolium-results/ contents). We intentionally don't expose
 * --modes, --mode, --interactive, --from-results-dir, --parallel-modes, or
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
  keepRaw?: boolean;
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
  const resultsDir = join(targetDir, "vigolium-results");

  if (!existsSync(resultsDir)) {
    return failCli(opts, "resume", `no vigolium-results/ directory at ${targetDir} — nothing to resume`);
  }

  const store = new StateStore(resultsDir);
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
        ? `no audits recorded in ${resultsDir}/audit-state.json — start one with \`vigolium-audit run --mode <mode>\``
        : `every audit in ${resultsDir}/audit-state.json is already complete; nothing to resume`;
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
    const n = parsePositiveUsd(opts.maxCost);
    if (n === null) {
      failCli(opts, "resume", `--max-cost must be a positive number (got ${JSON.stringify(opts.maxCost)})`);
    }
    runOpts.maxCost = n;
  }
  if (opts.output !== undefined) runOpts.output = opts.output;
  if (opts.oauthToken !== undefined) runOpts.oauthToken = opts.oauthToken;
  if (opts.oauthCredFile !== undefined) runOpts.oauthCredFile = opts.oauthCredFile;
  if (opts.apiKey !== undefined) runOpts.apiKey = opts.apiKey;
  if (opts.stripRaw !== undefined) runOpts.stripRaw = opts.stripRaw;
  if (opts.keepRaw !== undefined) runOpts.keepRaw = opts.keepRaw;
  if (opts.focusFile !== undefined) runOpts.focusFile = opts.focusFile;
  if (opts.expectedBehaviorsFile !== undefined) runOpts.expectedBehaviorsFile = opts.expectedBehaviorsFile;
  if (opts.serial !== undefined) runOpts.serial = opts.serial;
  if (opts.json !== undefined) runOpts.json = opts.json;
  if (opts.debug !== undefined) runOpts.debug = opts.debug;
  if (opts.streaming !== undefined) runOpts.streaming = opts.streaming;
  if (opts.git !== undefined) runOpts.git = opts.git;
  return runOpts;
}
