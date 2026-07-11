import chalk from "chalk";
import { premergeResults, type PremergeResult } from "../engine/premerge.js";
import type { AgentPlatform, AgentTransport } from "../engine/types.js";
import { compact } from "../engine/util.js";
import { emitJsonEvent } from "./run-render.js";

export interface MergeOptions {
  /** Repeatable `--dir` inputs. cac hands a single flag through as a string. */
  dir?: string | string[];
  /** Non-destructive destination dir; default is to merge into the first --dir. */
  output?: string;
  /** Allow merging into a non-empty --output destination. */
  force?: boolean;
  /**
   * Stop after the deterministic consolidation and skip the LLM normalization
   * pass — emits the `next:` hint instead. Restores the pre-pipeline behavior
   * (no tokens spent; inspect the consolidated folder before normalizing).
   */
  premergeOnly?: boolean;
  // --- forwarded to the `run --mode merge` normalization pass ---------------
  /** Agent platform for the normalization pass (claude|codex). */
  agent?: AgentPlatform;
  /** Headless adapter transport for the normalization pass. */
  transport?: AgentTransport;
  /** Model name forwarded to the normalization pass. */
  model?: string;
  /** Hard cost cap (USD) for the normalization pass. cac delivers a string. */
  maxCost?: number;
  /** Abort the normalization pass on first phase failure. */
  strict?: boolean;
  oauthToken?: string;
  oauthCredFile?: string;
  apiKey?: string;
  json?: boolean;
  debug?: boolean;
  streaming?: boolean;
}

/** Normalize cac's `--dir` value (string for one flag, array for many) to a list. */
export function normalizeDirInputs(dir: string | string[] | undefined): string[] {
  if (dir === undefined) return [];
  return Array.isArray(dir) ? dir : [dir];
}

/**
 * `vigolium-audit merge --dir A --dir B [--dir C…]` — consolidate two-or-more
 * `vigolium-results/` folders into one and normalize the result in a single
 * invocation:
 *
 *   1. The deterministic file-merge (`premergeResults`): collision-safe copy of
 *      every source's findings + unified attack-surface, stamping
 *      `merge_metadata` into the destination's `audit-state.json`.
 *   2. The LLM normalization pass (`run --mode merge`): validate every finding
 *      against the standard format, semantically dedup by root cause,
 *      renumber per severity, regenerate summaries, write `merge-report.md`.
 *
 * Pass `--premerge-only` to stop after step 1 (no tokens spent) and inspect the
 * consolidated folder before normalizing — step 2 is then
 * `vigolium-audit run --mode merge --target <dest>`.
 */
export async function mergeCommand(opts: MergeOptions): Promise<void> {
  const json = !!opts.json;
  const fail = (msg: string, exit = 2): never => {
    if (json) process.stdout.write(JSON.stringify({ ok: false, error: msg }) + "\n");
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(exit);
  };

  const inputs = normalizeDirInputs(opts.dir);
  if (inputs.length < 2) {
    return fail(`merge needs at least two --dir inputs (e.g. \`--dir ./auditA --dir ./auditB\`)`);
  }

  let result: PremergeResult;
  try {
    result = await premergeResults({
      inputs,
      ...compact({ output: opts.output, force: opts.force || undefined }),
    });
  } catch (err) {
    return fail((err as Error).message);
  }

  // Premerge-only: stop here, point the user at the normalization step. JSON
  // mode keeps the historical single terminal object `{ ok: true, … }`.
  if (opts.premergeOnly) {
    if (json) {
      process.stdout.write(JSON.stringify({ ok: true, ...result }) + "\n");
      return;
    }
    printPremergeSummary(result);
    console.log(
      `\n${chalk.cyan("next:")} normalize + dedup the consolidated folder with\n` +
        `  ${chalk.bold(`vigolium-audit run --mode merge --target ${result.destProjectDir}`)}`,
    );
    return;
  }

  // Full pipeline: hand the consolidated folder to the LLM normalization pass.
  // Point `run` at the consolidated project dir via --target (NOT --dir, so it
  // skips a redundant second pre-merge) and forward the agent/model/cost/auth
  // flags. runCommand owns the rest of the lifecycle (and the process exit).
  if (json) {
    emitJsonEvent({ kind: "premerge", ...result });
  } else {
    printPremergeSummary(result);
    console.log(`\n${chalk.cyan("normalizing")} the consolidated folder via ${chalk.bold("run --mode merge")}…\n`);
  }
  const { runCommand } = await import("./run.js");
  await runCommand({
    mode: "merge",
    target: result.destProjectDir,
    ...compact({
      agent: opts.agent,
      transport: opts.transport,
      model: opts.model,
      maxCost: opts.maxCost,
      strict: opts.strict || undefined,
      oauthToken: opts.oauthToken,
      oauthCredFile: opts.oauthCredFile,
      apiKey: opts.apiKey,
      json: opts.json || undefined,
      debug: opts.debug || undefined,
      streaming: opts.streaming,
    }),
  });
}

/** Render the deterministic merge result as a human log (JSON handled by caller). */
function printPremergeSummary(result: PremergeResult): void {
  console.log(chalk.green(`[vigolium-audit] merged ${result.sources.length} audit folders`));
  console.log(`  ${chalk.dim("destination:")} ${result.destResultsDir}${result.destinationInPlace ? chalk.yellow(" (in place)") : ""}`);
  for (const s of result.sourceInfo) {
    const attribution = [s.agents.join("/") || "?", s.models.join("/") || "?"].join(" · ");
    console.log(`  ${chalk.dim("source:")} ${s.dir} ${chalk.dim(`(${attribution})`)}`);
  }
  console.log(`  ${chalk.dim("findings copied in:")} ${result.findingsCopied}`);
  if (result.idRemap.length > 0) {
    console.log(`  ${chalk.dim("collisions renamed:")} ${result.idRemap.length}`);
    for (const r of result.idRemap.slice(0, 10)) {
      console.log(`    ${chalk.dim(`${r.bucket}/`)}${r.from} ${chalk.dim("→")} ${r.to}`);
    }
    if (result.idRemap.length > 10) console.log(chalk.dim(`    … and ${result.idRemap.length - 10} more`));
  }
  if (result.attackSurfaceSources.length > 0) {
    console.log(
      `  ${chalk.dim("attack-surface unified:")} ${result.attackSurfaceCopied} file(s) from ` +
        `${result.attackSurfaceSources.length} source(s)`,
    );
    for (const r of result.attackSurfaceRenamed.slice(0, 10)) {
      console.log(`    ${chalk.dim("attack-surface/")}${r.from} ${chalk.dim("→")} ${r.to}`);
    }
    if (result.attackSurfaceRenamed.length > 10) {
      console.log(chalk.dim(`    … and ${result.attackSurfaceRenamed.length - 10} more renamed`));
    }
  }
  if (result.backup) console.log(`  ${chalk.dim("state backed up:")} ${result.backup}`);
  for (const note of result.skipped) console.log(chalk.dim(`  skipped: ${note}`));
}
