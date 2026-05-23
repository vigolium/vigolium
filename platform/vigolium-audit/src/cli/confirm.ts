import { resolve } from "path";
import { failCli, parsePositiveUsd } from "./util.js";
import type { AgentPlatform, RunOptions } from "../engine/types.js";

/**
 * Subset of `run` flags that `vigolium-audit confirm` accepts and forwards to
 * `runCommand` with mode pinned to `confirm`. Drops --mode/--modes/--baseline/
 * --parallel-modes (irrelevant for a single-mode entry point) but keeps every
 * flag that confirm actually uses, including --live-target (confirm-only),
 * --from-audit (consume a prior audit), --from-results-dir/--keep-clone
 * (replay an archived results dir), and the audit-context inputs.
 */
export interface ConfirmOptions {
  agent?: string;
  model?: string;
  interactive?: boolean;
  fromAudit?: string;
  maxCost?: number | string;
  strict?: boolean;
  output?: string;
  oauthToken?: string;
  oauthCredFile?: string;
  apiKey?: string;
  stripRaw?: boolean;
  keepRaw?: boolean;
  focusFile?: string;
  expectedBehaviorsFile?: string;
  liveTarget?: string;
  dryRun?: boolean;
  serial?: boolean;
  resume?: boolean;
  fromResultsDir?: string;
  keepClone?: boolean;
  json?: boolean;
  debug?: boolean;
  streaming?: boolean;
  git?: boolean;
}

export async function confirmCommand(
  targetPath: string,
  opts: ConfirmOptions = {},
): Promise<void> {
  const runOpts = buildRunOptions({ targetDir: resolve(targetPath || "."), opts });
  const { runCommand } = await import("./run.js");
  await runCommand(runOpts);
}

function buildRunOptions(args: { targetDir: string; opts: ConfirmOptions }): RunOptions {
  const { targetDir, opts } = args;
  const runOpts: RunOptions = {
    mode: "confirm",
    target: targetDir,
  };
  if (opts.agent !== undefined) runOpts.agent = opts.agent as AgentPlatform;
  if (opts.model !== undefined) runOpts.model = opts.model;
  if (opts.interactive !== undefined) runOpts.interactive = opts.interactive;
  if (opts.fromAudit !== undefined) runOpts.fromAudit = opts.fromAudit;
  if (opts.maxCost !== undefined) {
    const n = parsePositiveUsd(opts.maxCost);
    if (n === null) {
      failCli(opts, "confirm", `--max-cost must be a positive number (got ${JSON.stringify(opts.maxCost)})`);
    }
    runOpts.maxCost = n;
  }
  if (opts.strict !== undefined) runOpts.strict = opts.strict;
  if (opts.output !== undefined) runOpts.output = opts.output;
  if (opts.oauthToken !== undefined) runOpts.oauthToken = opts.oauthToken;
  if (opts.oauthCredFile !== undefined) runOpts.oauthCredFile = opts.oauthCredFile;
  if (opts.apiKey !== undefined) runOpts.apiKey = opts.apiKey;
  if (opts.stripRaw !== undefined) runOpts.stripRaw = opts.stripRaw;
  if (opts.keepRaw !== undefined) runOpts.keepRaw = opts.keepRaw;
  if (opts.focusFile !== undefined) runOpts.focusFile = opts.focusFile;
  if (opts.expectedBehaviorsFile !== undefined) runOpts.expectedBehaviorsFile = opts.expectedBehaviorsFile;
  if (opts.liveTarget !== undefined) runOpts.liveTarget = opts.liveTarget;
  if (opts.dryRun !== undefined) runOpts.dryRun = opts.dryRun;
  if (opts.serial !== undefined) runOpts.serial = opts.serial;
  if (opts.resume !== undefined) runOpts.resume = opts.resume;
  if (opts.fromResultsDir !== undefined) runOpts.fromResultsDir = opts.fromResultsDir;
  if (opts.keepClone !== undefined) runOpts.keepClone = opts.keepClone;
  if (opts.json !== undefined) runOpts.json = opts.json;
  if (opts.debug !== undefined) runOpts.debug = opts.debug;
  if (opts.streaming !== undefined) runOpts.streaming = opts.streaming;
  if (opts.git !== undefined) runOpts.git = opts.git;
  return runOpts;
}
