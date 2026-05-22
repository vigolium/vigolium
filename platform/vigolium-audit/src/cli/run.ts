import { mkdtempSync } from "fs";
import { readFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { resolve, join } from "path";
import { OutputSyncer, assertOutputNotNested } from "../engine/output-sync.js";
import { writeCache as writeRateLimitsCache, readCache as readRateLimitsCache, ageMs, formatResetsIn } from "../engine/rate-limits-cache.js";
import { spawn } from "child_process";
import chalk from "chalk";
import type { Adapter } from "../adapters/adapter.js";
import { ClaudeCliAdapter } from "../adapters/claude-cli.js";
import { ClaudeSdkAdapter } from "../adapters/claude-sdk.js";
import { CodexCliAdapter } from "../adapters/codex-cli.js";
import { CodexSdkAdapter } from "../adapters/codex-sdk.js";
import { chooseAdapter, probeClaudeBinary, probeCodexBinary } from "../adapters/detect.js";
import { getContentLoader } from "../content-loader.js";
import { Orchestrator, stripRawArtifacts, type OrchestratorResult } from "../engine/orchestrator.js";
import { ClaudeHandoff } from "../engine/claude-handoff.js";
import { CodexHandoff, isCodexHandoffMode } from "../engine/codex-handoff.js";
import type { OrchestratorEvent } from "../engine/events.js";
import { applyAuthOverrides, type AuthOverrideHandle } from "../engine/auth-overrides.js";
import { writeAuditContext } from "../engine/audit-context.js";
import {
  claudePluginDir,
  codexAgentsDir,
  registerEphemeralHarness,
  type EphemeralHarnessHandle,
} from "../engine/harness.js";
import { probeGit } from "../engine/git.js";
import { StateStore } from "../engine/state.js";
import type { AgentPlatform, AuditMode, RunOptions } from "../engine/types.js";
import {
  TRIGGERED_VIA_REFRESH,
  detectRefreshRoute,
  findInProgressRefreshAudit,
} from "./refresh-detect.js";
import { resolveResultsDirSeed, type ResultsDirSeedHandle } from "./seed.js";
import { cloneRemoteTarget, isRemoteTargetUrl } from "./clone-target.js";
import type { ResumeOptions } from "./resume.js";
import { compact, round2 } from "../engine/util.js";
import { severityColor, statusArrow } from "./util.js";

const MAX_CONTEXT_BYTES = 32 * 1024;

const VALID_MODES: AuditMode[] = ["lite", "balanced", "deep", "diff", "confirm", "merge", "revisit", "reinvest", "longshot", "refresh"];

/**
 * Per-platform default model. Overridable via `--model`. The `[1m]` suffix on
 * the Claude default selects the 1M-context Opus 4.7 variant. The codex
 * default also gets `xhigh` reasoning effort applied to the adapter; both
 * pieces are dropped when `--model` is set so a custom model isn't silently
 * paired with a default reasoning policy.
 */
const DEFAULT_CLAUDE_MODEL = "claude-opus-4-7[1m]";
const DEFAULT_CODEX_MODEL = "gpt-5.5";
const DEFAULT_CODEX_REASONING_EFFORT = "xhigh" as const;

function resolveDefaultModel(platform: AgentPlatform, override?: string): string {
  if (override !== undefined && override.length > 0) return override;
  return platform === "claude" ? DEFAULT_CLAUDE_MODEL : DEFAULT_CODEX_MODEL;
}

/**
 * Routing decision produced when `--mode refresh` is invoked. The
 * underlying `mode` the orchestrator runs is `revisit` or `deep`; the
 * router carries the user's original intent through `triggeredVia` so
 * `audit-state.json` records both.
 */
interface RefreshRouting {
  excludePhases?: string[];
  triggeredVia: string;
  resume?: boolean;
}

export async function runCommand(opts: RunOptions): Promise<void> {
  const json = !!opts.json;
  const fail = (msg: string, exit = 2): never => {
    if (json) emitJsonEvent({ kind: "fatal", error: msg });
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(exit);
  };

  // --target / --source: when it's a remote git URL (https://github.com/...,
  // https://gitlab.com/..., git@host:..., etc.), clone it into
  // ./<repo-slug>/ under the current working directory and continue against
  // that path. Reuses an existing same-remote checkout in-place; refuses to
  // clobber a foreign directory. Rejects flag combinations that don't make
  // sense against a fresh clone.
  if (opts.target !== undefined && isRemoteTargetUrl(opts.target)) {
    if (opts.git === false) {
      fail(`--no-git is incompatible with a remote --target (cloning requires git).`);
    }
    if (opts.fromResultsDir !== undefined) {
      fail(`--from-results-dir is incompatible with a remote --target (it does its own clone).`);
    }
    if (opts.resume === true) {
      fail(`--resume is incompatible with a remote --target (a fresh clone has no resume state).`);
    }
    try {
      const cloned = cloneRemoteTarget(opts.target);
      opts.target = cloned.clonedTargetDir;
      if (!json) console.log(chalk.blue("[clone]") + ` ${cloned.summary}`);
    } catch (err) {
      fail((err as Error).message);
    }
  }

  // `--mode resume` / `--modes resume` is an alias for the standalone
  // `vigolium-audit resume`: it ignores the named mode, auto-detects the latest
  // non-complete audit from <target>/vigolium-results/audit-state.json, and continues
  // it (mode is read back from the audit record). Short-circuit before mode
  // resolution / dry-run so it behaves exactly like `vigolium-audit resume <target>`.
  if (isResumeAlias(opts)) {
    const { resumeCommand } = await import("./resume.js");
    return resumeCommand(opts.target ?? ".", toResumeOptions(opts));
  }
  if (opts.dryRun) {
    const { dryRunCommand } = await import("./dry-run.js");
    return dryRunCommand(opts);
  }

  let requestedModes: AuditMode[];
  try {
    requestedModes = resolveRequestedModes(opts);
  } catch (err) {
    return fail((err as Error).message);
  }
  const isChain = requestedModes.length > 1;
  const platform = (opts.agent ?? "claude") as AgentPlatform;
  if (platform !== "claude" && platform !== "codex") {
    fail(`--agent must be "claude" or "codex"`);
  }

  // Tell Claude Code it's running in a sandboxed context so it doesn't refuse
  // to start as root. Inherited by every claude child (CLI adapter spawn,
  // SDK query, interactive exec) via process.env.
  if (platform === "claude" && process.env.IS_SANDBOX === undefined) {
    process.env.IS_SANDBOX = "1";
  }

  if (opts.liveTarget !== undefined) {
    if (requestedModes.length !== 1 || requestedModes[0] !== "confirm") {
      fail(`--live-target is only supported with --mode confirm (got modes ${requestedModes.join(",")})`);
    }
    if (!/^https?:\/\//i.test(opts.liveTarget)) {
      fail(`--live-target must be an http:// or https:// URL (got ${opts.liveTarget})`);
    }
  }

  if (opts.keepRaw === true && opts.stripRaw === true) {
    fail(`--keep-raw and --strip-raw are mutually exclusive`);
  }

  if (opts.interactive && isChain) {
    fail(
      `--modes (chain) is headless-only — interactive runs hand off to the underlying CLI for a single mode. ` +
        `Run without -i, or invoke modes one at a time.`,
    );
  }
  if (opts.interactive && requestedModes[0] === "refresh") {
    fail(
      `--mode refresh is headless-only (it dispatches to revisit or deep at startup). ` +
        `Run without -i, or invoke the resolved mode directly.`,
    );
  }
  const noGit = opts.git === false;
  if (opts.parallelModes) {
    if (requestedModes.length < 2) {
      fail(`--parallel requires --modes with at least two modes (got ${requestedModes.length})`);
    }
    if (requestedModes.includes("refresh")) {
      fail(`--parallel doesn't support 'refresh' (it depends on prior modes' output). Drop refresh or run sequentially.`);
    }
    if (opts.interactive) {
      fail(`--parallel is headless-only.`);
    }
  }

  if (opts.resume) {
    if (isChain) {
      fail(`--resume is a single-audit operation; pass --mode <mode>, not --modes`);
    }
    if (requestedModes[0] === "refresh") {
      fail(`--mode refresh has its own resume detection; drop --resume or pass the underlying mode`);
    }
    if (opts.fromResultsDir !== undefined) {
      fail(`--resume is incompatible with --from-results-dir (resume operates on the target's existing vigolium-results/ dir)`);
    }
    if (opts.parallelModes) {
      fail(`--resume is incompatible with --parallel-modes`);
    }
  }

  // --from-results-dir: clone the recorded repo at the recorded commit, copy
  // the seed vigolium-results/ into the clone, and run against that. The seed
  // handle's cleanup() syncs the result back to the original input dir on exit.
  let seedHandle: ResultsDirSeedHandle | null = null;
  if (opts.fromResultsDir !== undefined) {
    if (opts.interactive) {
      fail(`--from-results-dir is headless-only (drop -i). Interactive seed flow is not yet supported.`);
    }
    if (opts.git === false) {
      fail(`--no-git is incompatible with --from-results-dir (the clone is a git repo by definition).`);
    }
    try {
      seedHandle = await resolveResultsDirSeed({
        fromResultsDir: opts.fromResultsDir,
        keepClone: !!opts.keepClone,
        ...compact({ targetOverride: opts.target, fromAuditId: opts.fromAudit }),
      });
    } catch (err) {
      fail((err as Error).message);
    }
    if (!json) {
      console.log(chalk.blue("[seed]") + ` ${seedHandle!.summary}`);
    }
  }

  const targetDir = seedHandle ? seedHandle.clonedTargetDir : resolve(opts.target ?? ".");

  // Auth overrides must be applied before any adapter / subprocess work — env
  // vars and file swaps must be in place when the SDK reads them or when
  // claude/codex gets spawned.
  let authHandle: AuthOverrideHandle | null = null;
  try {
    authHandle = applyAuthOverrides({
      platform,
      ...compact({
        oauthToken: opts.oauthToken,
        oauthCredFile: opts.oauthCredFile,
        apiKey: opts.apiKey,
      }),
    });
  } catch (err) {
    fail(`auth override: ${(err as Error).message}`, 2);
  }
  if (authHandle && !json && (opts.oauthToken || opts.oauthCredFile || opts.apiKey)) {
    console.log(`[auth] applied: ${authHandle.summary()}`);
  }

  try {
    if (opts.interactive) {
      // Resolve focus/expected-behaviors here too so the interactive path
      // writes the same `vigolium-results/audit-context.md` the handoff drivers do —
      // that file carries the auto-confirm directive plus user-supplied
      // context, and command-def Context blocks inline it via `!cat`.
      let interactiveAuditContext: { focus?: string; expectedBehaviors?: string } = {};
      try {
        interactiveAuditContext = await resolveAuditContext({ targetDir, opts, json });
      } catch (err) {
        const msg = (err as Error).message;
        if (json) emitJsonEvent({ kind: "fatal", error: msg });
        else console.error(chalk.red(`error: ${msg}`));
        process.exit(2);
      }
      // Validation above guarantees exactly one mode here.
      return await runInteractive({
        platform,
        mode: requestedModes[0]!,
        targetDir,
        noGit,
        ...compact({
          liveTarget: opts.liveTarget,
          model: opts.model,
          focus: interactiveAuditContext.focus,
          expectedBehaviors: interactiveAuditContext.expectedBehaviors,
        }),
      });
    }
    return await runHeadless({
      platform,
      modes: requestedModes,
      targetDir,
      opts,
      noGit,
    });
  } finally {
    authHandle?.restore();
    if (seedHandle) {
      try {
        await seedHandle.cleanup();
        if (!json) {
          console.log(chalk.blue("[seed]") + ` synced vigolium-results/ back to ${opts.fromResultsDir}`);
        }
      } catch (err) {
        const msg = `failed to sync vigolium-results/ back to ${opts.fromResultsDir}: ${(err as Error).message}`;
        if (json) emitJsonEvent({ kind: "seedSyncError", error: msg });
        else console.error(chalk.red(`[seed] ${msg}`));
      }
    }
  }
}

/**
 * Resolve --mode / --modes into a non-empty list, with mutual-exclusion
 * checks. Throws with a user-facing message on invalid input.
 */
export function resolveRequestedModes(opts: RunOptions): AuditMode[] {
  if (opts.modes !== undefined && opts.mode !== undefined) {
    throw new Error(`--mode and --modes are mutually exclusive; pass one or the other`);
  }
  if (opts.modes !== undefined) {
    const list = opts.modes
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (list.length === 0) {
      throw new Error(`--modes is empty; pass a comma-separated list (e.g. deep,refresh,confirm)`);
    }
    for (const m of list) {
      if (!VALID_MODES.includes(m as AuditMode)) {
        throw new Error(`--modes contains invalid mode "${m}"; must be one of ${VALID_MODES.join(", ")}`);
      }
    }
    return list as AuditMode[];
  }
  const single = (opts.mode ?? "lite") as AuditMode;
  if (!VALID_MODES.includes(single)) {
    throw new Error(`--mode must be one of ${VALID_MODES.join(", ")}`);
  }
  return [single];
}

/**
 * True when the user asked for the `resume` pseudo-mode via `--mode resume`
 * or `--modes resume`. `resume` is not a phase-graph mode (it has no
 * command-def); it's sugar for the standalone `vigolium-audit resume` entry point,
 * so it's intercepted before `resolveRequestedModes` ever sees it. A `resume`
 * mixed into a multi-mode `--modes` list is *not* an alias — it falls through
 * to `resolveRequestedModes` and produces the usual "invalid mode" error.
 */
export function isResumeAlias(opts: RunOptions): boolean {
  if ((opts.mode as string | undefined) === "resume") return true;
  if (opts.modes !== undefined) {
    const list = opts.modes
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    return list.length === 1 && list[0] === "resume";
  }
  return false;
}

/**
 * Project the run flags that `vigolium-audit resume` understands out of a RunOptions.
 * Mode/modes/interactive/from-results-dir/parallel-modes/dry-run are
 * intentionally dropped — they don't apply to picking up an interrupted
 * audit in place (the mode is read back from the audit record).
 */
function toResumeOptions(opts: RunOptions): ResumeOptions {
  return compact({
    agent: opts.agent,
    strict: opts.strict,
    maxCost: opts.maxCost,
    output: opts.output,
    oauthToken: opts.oauthToken,
    oauthCredFile: opts.oauthCredFile,
    apiKey: opts.apiKey,
    stripRaw: opts.stripRaw,
    focusFile: opts.focusFile,
    expectedBehaviorsFile: opts.expectedBehaviorsFile,
    serial: opts.serial,
    json: opts.json,
    debug: opts.debug,
    streaming: opts.streaming,
    git: opts.git,
  });
}

function emitJsonEvent(payload: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(payload) + "\n");
}

/**
 * Interactive mode (`-i` / `--interactive`).
 *
 * Drops the user into the underlying coding agent (claude / codex) with our
 * vigolium-audit plugin attached. We don't drive the SDK loop; we just hand off to
 * the native CLI in interactive mode so the user can drive the audit
 * (resume, edit prompts, run multiple modes) as themselves.
 */
async function runInteractive(args: {
  platform: AgentPlatform;
  mode: AuditMode;
  targetDir: string;
  noGit: boolean;
  liveTarget?: string;
  model?: string;
  focus?: string;
  expectedBehaviors?: string;
}): Promise<void> {
  const { platform, mode, targetDir, noGit, liveTarget } = args;
  const effectiveModel = resolveDefaultModel(platform, args.model);
  // Match the headless rule: only apply the codex reasoning default when the
  // user didn't pick a custom model.
  const codexReasoning =
    platform === "codex" && args.model === undefined ? DEFAULT_CODEX_REASONING_EFFORT : undefined;
  const probe = platform === "claude" ? probeClaudeBinary() : probeCodexBinary();
  if (!probe.path) {
    const installHint =
      platform === "claude"
        ? "`npm i -g @anthropic-ai/claude-code` (or set VIGOLIUM_AUDIT_CLAUDE_PATH)"
        : "`npm i -g @openai/codex` (or set VIGOLIUM_AUDIT_CODEX_PATH)";
    console.error(chalk.red(`error: no \`${platform}\` binary found. Install via ${installHint}.`));
    process.exit(2);
  }

  const git = noGit
    ? { available: false, branch: null, commit: null, repository: null }
    : probeGit(targetDir);
  const tempDir = mkdtempSync(
    join(tmpdir(), `vigolium-audit-${new Date().toISOString().replace(/[:.]/g, "").slice(0, 15)}-`),
  );

  // Write `vigolium-results/audit-context.md` before the agent starts so the auto-confirm
  // directive (plus user-supplied focus / expected behaviors) lands in the
  // file the command-def Context block inlines via `!cat`. Matches the
  // headless ClaudeHandoff / CodexHandoff path. Without this, the agent never
  // sees the directive in interactive mode and is free to freelance text
  // confirmation prompts ("Two options: 1. Proceed / 2. Downshift…").
  await writeAuditContext(join(targetDir, "vigolium-results"), {
    ...(args.focus !== undefined ? { focus: args.focus } : {}),
    ...(args.expectedBehaviors !== undefined ? { expectedBehaviors: args.expectedBehaviors } : {}),
  });

  // Install the harness fresh for this run; remove it on exit (natural,
  // process.exit, default-SIGINT all fire `exit`). Leave-no-trace.
  const harness = await registerEphemeralHarness(platform);
  console.log(
    `[setup] installed ${harness.installResult.agentsInstalled} agents to ${harness.installResult.installPath} (cleaned up on exit)`,
  );

  if (platform === "claude") {
    const pluginDir = claudePluginDir();
    const slashArgs = liveTarget !== undefined ? ` ${liveTarget}` : "";
    const slash = `/vigolium-audit:vigolium-audit:${mode}${slashArgs}`;
    const cmdArgs = ["--plugin-dir", pluginDir, "--dangerously-skip-permissions", "--model", effectiveModel];

    printBanner({
      platform,
      mode,
      targetDir,
      gitAvailable: git.available,
      noGit,
      tempDir,
      command: `printf "${slash}" | ${probe.path} ${cmdArgs.map(quote).join(" ")}`,
    });

    await execInteractiveWithStdin({
      bin: probe.path,
      args: cmdArgs,
      cwd: targetDir,
      stdinPayload: slash,
    });
    return;
  }

  // Codex: agents installed under ~/.codex/agents/vigolium-audit-*.toml. Codex has
  // no plugin-dir nor /slash-command system, so we just exec interactively
  // and instruct the user how to invoke the audit.
  const codexAgents = codexAgentsDir();
  const cmdArgs: string[] = ["--model", effectiveModel];
  if (codexReasoning) {
    cmdArgs.push("-c", `model_reasoning_effort="${codexReasoning}"`);
  }

  printBanner({
    platform,
    mode,
    targetDir,
    gitAvailable: git.available,
    noGit,
    tempDir,
    command: `${probe.path}    # then invoke @vigolium-audit:* agents in the session`,
    extraNotes: [
      `Codex agents available at ${codexAgents} (prefix: vigolium-audit:*)`,
      `For "${mode}" mode, ask the agent: "Run an vigolium-audit ${mode} audit on this codebase."`,
    ],
  });

  await execInteractiveWithStdin({
    bin: probe.path,
    args: cmdArgs,
    cwd: targetDir,
    stdinPayload: null,
  });
}

interface BannerArgs {
  platform: AgentPlatform;
  mode: AuditMode;
  targetDir: string;
  gitAvailable: boolean;
  noGit?: boolean;
  tempDir: string;
  command: string;
  extraNotes?: string[];
}

function printBanner(args: BannerArgs): void {
  const gitLabel = args.noGit
    ? "skipped (--no-git)"
    : args.gitAvailable
      ? "available"
      : "not available";
  console.log(`${statusArrow("Platform")} Platform:  ${args.platform}`);
  console.log(`${statusArrow("Mode")} Mode:      ${args.mode}`);
  console.log(`${statusArrow("Target")} Target:    ${args.targetDir}`);
  console.log(`${statusArrow("Git")} Git:       ${gitLabel}`);
  console.log(`${statusArrow("Temp")} Temp:      ${args.tempDir}`);
  console.log(`${statusArrow("Command")} Command:`);
  console.log(`  ${args.command}`);
  for (const note of args.extraNotes ?? []) {
    console.log(`  ${note}`);
  }
  console.log("");
}

function quote(s: string): string {
  return /[\s"$`!]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s;
}

async function execInteractiveWithStdin(args: {
  bin: string;
  args: string[];
  cwd: string;
  /**
   * If set, write this string to the child's stdin then close it. Use null to
   * inherit the parent's stdin (full TTY interactive).
   */
  stdinPayload: string | null;
}): Promise<void> {
  const child = spawn(args.bin, args.args, {
    cwd: args.cwd,
    stdio: [args.stdinPayload === null ? "inherit" : "pipe", "inherit", "inherit"],
    env: process.env,
  });
  if (args.stdinPayload !== null && child.stdin) {
    child.stdin.write(args.stdinPayload);
    child.stdin.end();
  }
  const code: number = await new Promise((res, rej) => {
    child.on("error", rej);
    child.on("close", (c) => res(c ?? 0));
  });
  process.exit(code);
}

/**
 * Resolve `--mode refresh` to its underlying mode. Prefers resuming an
 * in-progress refresh-triggered audit (so a partial run doesn't get
 * re-routed to a different lane); otherwise inspects the vigolium-results/ folder.
 */
async function resolveRefreshRouting(
  targetDir: string,
): Promise<{ mode: AuditMode; routing: RefreshRouting; logLine: string }> {
  const inProgress = await findInProgressRefreshAudit(targetDir);
  if (inProgress) {
    return {
      mode: inProgress.mode,
      routing: { triggeredVia: TRIGGERED_VIA_REFRESH, resume: true },
      logLine: `resuming in-progress audit ${inProgress.auditId} (mode=${inProgress.mode})`,
    };
  }
  const decision = await detectRefreshRoute(targetDir);
  if (decision.route === "revisit") {
    return {
      mode: "revisit",
      routing: { triggeredVia: TRIGGERED_VIA_REFRESH },
      logLine: `routing to revisit — ${decision.reason}`,
    };
  }
  return {
    mode: "deep",
    routing: {
      triggeredVia: TRIGGERED_VIA_REFRESH,
      excludePhases: decision.excludePhases,
    },
    logLine: `routing to deep (skipping ${decision.excludePhases.join(", ")}) — ${decision.reason}`,
  };
}

function shouldPruneCompletedArtifacts(args: { mode: AuditMode; opts: RunOptions }): boolean {
  // Deep/confirm handoff modes are expected to leave a delivery-ready vigolium-results/
  // tree. Enforce that at the CLI layer as well as in agent prompts, because
  // handoff agents can skip their own cleanup on resumes or quota handoffs.
  // Resume inherits the same policy from its resolved underlying mode; avoid
  // stripping modes with mode-specific durable trees such as longshot.
  // --keep-raw overrides the default deep/confirm auto-prune so the user can
  // manually review raw scanner output and intermediate workspaces.
  if (args.opts.keepRaw === true) return false;
  if (args.opts.stripRaw === true) return true;
  return args.mode === "deep" || args.mode === "confirm";
}

async function pruneCompletedArtifacts(args: {
  resultsDir: string;
  mode: AuditMode;
  opts: RunOptions;
  json: boolean;
}): Promise<void> {
  if (!shouldPruneCompletedArtifacts({ mode: args.mode, opts: args.opts })) return;
  await stripRawArtifacts(args.resultsDir, {
    // Only lite needs historical draft promotion. Deep/balanced/confirm have
    // canonical finalized finding directories; promoting raw drafts would
    // pollute `findings/` with intermediate chamber output.
    promoteDrafts: args.mode === "lite",
    // A confirm run's workspace is part of the deliverable (verdict staging,
    // env logs, test fallback output). For other modes, remove stale prior
    // confirm workspaces so the output reflects the just-finished mode.
    keepConfirmWorkspace: args.mode === "confirm",
  });
  if (args.json) {
    emitJsonEvent({ kind: "cleanup", mode: args.mode, resultsDir: args.resultsDir });
  } else {
    console.log(chalk.blue("[cleanup]") + ` pruned raw artifacts under ${chalk.dim(args.resultsDir)}`);
  }
}

async function runHeadless(args: {
  platform: AgentPlatform;
  modes: AuditMode[];
  targetDir: string;
  opts: RunOptions;
  noGit: boolean;
}): Promise<void> {
  const { platform, modes, targetDir, opts, noGit } = args;
  const json = !!opts.json;
  const isChain = modes.length > 1;
  const choice = chooseAdapter(platform);

  if (!json) {
    const git = noGit
      ? { available: false, branch: null, commit: null, repository: null }
      : probeGit(targetDir);
    const modeLabel = isChain ? modes.join(" → ") : modes[0];
    const adapterLabel = `${chalk.cyan(choice.flavor)} ${chalk.dim(`(${choice.authSource})`)}`;
    const gitLabel = noGit
      ? chalk.yellow("skipped (--no-git)")
      : git.available
        ? chalk.green(`${git.branch ?? "(detached)"} @ ${(git.commit ?? "").slice(0, 7)}`)
        : chalk.yellow("unavailable (plain directory target)");
    console.log(`${statusArrow("Platform")} Platform:  ${chalk.cyan(platform)}`);
    console.log(`${statusArrow("Adapter")} Adapter:   ${adapterLabel}`);
    console.log(`${statusArrow("Mode")} Mode:      ${chalk.cyan(modeLabel)}`);
    console.log(`${statusArrow("Target")} Target:    ${chalk.cyan(targetDir)}`);
    console.log(`${statusArrow("Git")} Git:       ${gitLabel}`);
    if (opts.resume) {
      console.log(`${statusArrow("Resume")} Resume:    ${chalk.green("on")} ${chalk.dim("(continuing latest non-complete audit for this mode)")}`);
    }
  }

  if (choice.binaryPath === null) {
    const installHint =
      platform === "claude"
        ? "`npm i -g @anthropic-ai/claude-code`, or set VIGOLIUM_AUDIT_CLAUDE_PATH"
        : "`npm i -g @openai/codex`, or set VIGOLIUM_AUDIT_CODEX_PATH";
    const msg = `no \`${platform}\` binary found. Install via ${installHint}.`;
    if (json) emitJsonEvent({ kind: "fatal", error: msg });
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(2);
  }

  const effectiveModel = resolveDefaultModel(platform, opts.model);
  // Reasoning effort is only meaningful for codex; only apply the xhigh
  // default when the user hasn't picked a custom model, so a non-gpt-5.5
  // model isn't silently paired with the default policy.
  const codexReasoning =
    platform === "codex" && opts.model === undefined ? DEFAULT_CODEX_REASONING_EFFORT : undefined;

  const adapter: Adapter =
    platform === "claude"
      ? choice.flavor === "cli"
        ? new ClaudeCliAdapter({ pathToClaudeCodeExecutable: choice.binaryPath, defaultModel: effectiveModel })
        : new ClaudeSdkAdapter({ pathToClaudeCodeExecutable: choice.binaryPath, defaultModel: effectiveModel })
      : choice.flavor === "cli"
        ? new CodexCliAdapter({
            pathToCodexExecutable: choice.binaryPath,
            defaultModel: effectiveModel,
            ...(codexReasoning ? { defaultReasoningEffort: codexReasoning } : {}),
          })
        : new CodexSdkAdapter({
            codexPathOverride: choice.binaryPath,
            defaultModel: effectiveModel,
            ...(codexReasoning ? { defaultReasoningEffort: codexReasoning } : {}),
          });

  if (!json) {
    const modelLabel = chalk.cyan(effectiveModel) +
      (codexReasoning ? chalk.dim(` (reasoning=${codexReasoning})`) : "") +
      (opts.model === undefined ? chalk.dim(" (default)") : "");
    console.log(`${statusArrow("Model")} Model:     ${modelLabel}`);
  }

  let auditContext: { focus?: string; expectedBehaviors?: string };
  try {
    auditContext = await resolveAuditContext({ targetDir, opts, json });
  } catch (err) {
    const msg = (err as Error).message;
    if (json) emitJsonEvent({ kind: "fatal", error: msg });
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(2);
  }

  // Install the vigolium-audit harness once for the entire chain. Both platforms
  // get an ephemeral install with a process-exit cleanup hook so Ctrl-C /
  // fatal throws also undo the install:
  //   - claude → plugin dir at ~/.config/vigolium-results/harness-claude/ + slash cmds.
  //   - codex  → ~/.codex/agents/vigolium-audit-*.toml + skills + AGENTS.md splice.
  let harness: EphemeralHarnessHandle | null = null;
  harness = await registerEphemeralHarness(platform);
  if (!json) {
    const r = harness.installResult;
    console.log(
      chalk.blue("[setup]") +
        ` installed ${chalk.cyan(r.agentsInstalled)} agents, ` +
        `${chalk.cyan(r.commandsInstalled)} ${platform === "codex" ? "dispatch" : "commands"}, ` +
        `${chalk.cyan(r.skillsInstalled)} skills to ${chalk.dim(r.installPath)} ` +
        chalk.dim("(cleaned up on exit)"),
    );
    if (platform === "codex") {
      // Codex has no `system: init` event, so the renderer can't print a
      // Loaded: line sourced from inside the session like it does for claude.
      // Echo the install-side facts here so the user has at least the
      // write-side confirmation.
      console.log(
        `${statusArrow("Loaded")} Loaded:    ${[
          `agents=${chalk.cyan(r.agentsInstalled)}`,
          `skills=${chalk.cyan(r.skillsInstalled)}`,
          `dispatch=${chalk.cyan(r.commandsInstalled > 0 ? "AGENTS.md" : "(missing)")}`,
          `sandbox=${chalk.cyan("danger-full-access")}`,
          `approvalPolicy=${chalk.cyan("never")}`,
        ].join(chalk.dim(" · "))}`,
      );
    }
  }

  // Show account-wide Claude Code usage as a preflight gauge. Claude only
  // (Codex usage isn't tracked in ~/.claude/projects/). Strictly advisory —
  // never blocks, never aborts. Skipped silently on any failure.
  if (platform === "claude") {
    try {
      const { loadUsageEntries, summarize } = await import("./usage.js");
      const sevenDays = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const entries = await loadUsageEntries({ since: sevenDays });
      const s = summarize(entries);
      const d = s.windows["24h"]!;
      const w = s.windows["7d"]!;
      if (json) {
        emitJsonEvent({
          kind: "usagePreflight",
          last24h: { usd: d.usd, count: d.count },
          last7d: { usd: w.usd, count: w.count },
        });
      } else {
        console.log(
          chalk.blue("[usage]") +
            `    last 24h: ${chalk.magenta(`~$${d.usd.toFixed(2)}`)} ${chalk.dim(`(${d.count} msg)`)}  ` +
            `· last 7d: ${chalk.magenta(`~$${w.usd.toFixed(2)}`)} ${chalk.dim(`(${w.count} msg)`)}  ` +
            chalk.dim("( subscription users: relative gauge, not a bill)"),
        );
      }
    } catch {
      /* usage preflight is advisory — never block a run on it */
    }

    // Show /usage-style quota from the rate_limits snapshot we harvested in
    // prior runs (Anthropic returns it inside response bodies but doesn't
    // persist it). Absent on first run or for non-subscribers.
    try {
      const cached = await readRateLimitsCache();
      if (cached !== null) {
        const ageMin = Math.round(ageMs(cached) / 60_000);
        const parts: string[] = [];
        if (cached.data.five_hour) {
          parts.push(
            `5h: ${chalk.magenta(`${cached.data.five_hour.used_percentage.toFixed(0)}%`)} ${chalk.dim(`(resets ${formatResetsIn(cached.data.five_hour.resets_at)})`)}`,
          );
        }
        if (cached.data.seven_day) {
          parts.push(
            `7d: ${chalk.magenta(`${cached.data.seven_day.used_percentage.toFixed(0)}%`)} ${chalk.dim(`(resets ${formatResetsIn(cached.data.seven_day.resets_at)})`)}`,
          );
        }
        if (cached.data.seven_day_opus) {
          parts.push(`7d opus: ${chalk.magenta(`${cached.data.seven_day_opus.used_percentage.toFixed(0)}%`)}`);
        }
        const staleNote = ageMin > 60 ? chalk.yellow(` stale ${ageMin}m`) : chalk.dim(` ${ageMin}m ago`);
        if (parts.length > 0) {
          if (json) emitJsonEvent({ kind: "quotaPreflight", fetched_at: cached.fetched_at, data: cached.data });
          else console.log(chalk.blue("[quota]") + `    ${parts.join(" · ")}${staleNote}`);
        }
      }
    } catch {
      /* quota preflight is advisory */
    }
  }

  // One AbortController + one SIGINT handler for the whole chain. Ctrl-C
  // aborts the current mode and prevents the next one from starting.
  const abortController = new AbortController();
  const onSigint = (): void => {
    console.error(chalk.blue("\n[vigolium-audit] received SIGINT — aborting after current phase…"));
    abortController.abort();
  };
  process.on("SIGINT", onSigint);

  // --output: mirror <targetDir>/vigolium-results/ → <outputDir> after every phaseEnd,
  // and rm -rf <targetDir>/vigolium-results/ at the end iff the whole run completed.
  const resultsDir = join(targetDir, "vigolium-results");
  let outputSyncer: OutputSyncer | null = null;
  if (opts.output !== undefined) {
    const outputDir = resolve(opts.output);
    try {
      assertOutputNotNested(outputDir, resultsDir);
    } catch (err) {
      const msg = (err as Error).message;
      if (json) emitJsonEvent({ kind: "fatal", error: msg });
      else console.error(chalk.red(`error: ${msg}`));
      process.exit(2);
    }
    outputSyncer = new OutputSyncer(resultsDir, outputDir, (err) => {
      const msg = `[output-sync] failed: ${err.message}`;
      if (json) emitJsonEvent({ kind: "outputSyncError", error: msg });
      else console.error(chalk.yellow(msg));
    });
    if (!json) {
      console.log(chalk.blue("[output]") + ` syncing vigolium-results/ → ${chalk.cyan(outputDir)} (cleanup on success)`);
    }
  }
  const onPhaseEnd = (ev: OrchestratorEvent): void => {
    if (outputSyncer !== null && ev.kind === "phaseEnd") void outputSyncer.sync();
  };

  // Harvest rate-limits snapshots from API responses (Claude only). Writes
  // to ~/.config/vigolium-results/rate-limits-cache.json so the next `vigolium-audit usage`
  // call can show `/usage`-style quota without a probe.
  let lastQuotaLogged = false;
  const onRateLimits = (ev: OrchestratorEvent): void => {
    if (ev.kind !== "rateLimits") return;
    void writeRateLimitsCache(ev.data).catch(() => {
      /* cache write is best-effort */
    });
    if (lastQuotaLogged) return;
    lastQuotaLogged = true;
    if (json) {
      emitJsonEvent({ kind: "rateLimits", data: ev.data });
      return;
    }
    const parts: string[] = [];
    if (ev.data.five_hour) {
      parts.push(
        `5h: ${chalk.magenta(`${ev.data.five_hour.used_percentage.toFixed(0)}%`)} ${chalk.dim(`(resets ${formatResetsIn(ev.data.five_hour.resets_at)})`)}`,
      );
    }
    if (ev.data.seven_day) {
      parts.push(
        `7d: ${chalk.magenta(`${ev.data.seven_day.used_percentage.toFixed(0)}%`)} ${chalk.dim(`(resets ${formatResetsIn(ev.data.seven_day.resets_at)})`)}`,
      );
    }
    if (ev.data.seven_day_opus) {
      parts.push(`7d opus: ${chalk.magenta(`${ev.data.seven_day_opus.used_percentage.toFixed(0)}%`)}`);
    }
    if (parts.length > 0) {
      console.log(chalk.blue("[quota]") + `    ${parts.join(" · ")} ${chalk.dim("(live)")}`);
    }
  };

  const maxCost = opts.maxCost !== undefined ? Number(opts.maxCost) : undefined;
  let aggUsd = 0;
  const stepResults: Array<{
    requested: AuditMode;
    resolved: AuditMode;
    result: OrchestratorResult;
  }> = [];
  let fatalError: Error | null = null;
  let stoppedReason: "complete" | "non-complete" | "fatal" | "budget" | "aborted" = "complete";

  try {
    if (opts.parallelModes) {
      const perModeBudget = maxCost !== undefined ? maxCost / modes.length : undefined;
      if (!json) {
        console.log(
          chalk.green(`\n[parallel-modes] launching ${modes.length} modes concurrently`) +
            (perModeBudget !== undefined ? chalk.dim(` (≈ $${perModeBudget.toFixed(2)} per mode)`) : ""),
        );
      }
      const results = await Promise.all(
        modes.map(async (m) => {
          const lineLogger = json
            ? null
            : makeLineLogger({ debug: !!opts.debug, streaming: !!opts.streaming });
          const resultsDir = join(targetDir, "vigolium-results", `parallel-${m}`);
          const useCodexHandoffM = platform === "codex" && isCodexHandoffMode(m);
          const sharedHandoff = compact({
            debug: opts.debug || undefined,
            focus: auditContext.focus,
            expectedBehaviors: auditContext.expectedBehaviors,
            liveTarget: opts.liveTarget,
          });
          const driver: { on: typeof Orchestrator.prototype.on; run: () => Promise<OrchestratorResult> } =
            platform === "claude"
              ? new ClaudeHandoff({
                  adapter,
                  targetDir,
                  mode: m,
                  pluginDir: harness!.installResult.installPath,
                  abortSignal: abortController.signal,
                  ...sharedHandoff,
                })
              : useCodexHandoffM
                ? new CodexHandoff({
                    adapter,
                    targetDir,
                    mode: m,
                    abortSignal: abortController.signal,
                    ...sharedHandoff,
                  })
                : new Orchestrator({
                    adapter,
                    loader: getContentLoader(),
                    targetDir,
                    resultsDir,
                    mode: m,
                    defaultModel: effectiveModel,
                    failurePolicy: opts.strict ? "strict" : "skip-and-continue",
                    interactive: false,
                    abortSignal: abortController.signal,
                    modeTag: m,
                    ...sharedHandoff,
                    ...compact({
                      maxCost: perModeBudget,
                      stripRaw: opts.stripRaw || undefined,
                      parallel: opts.serial ? false : undefined,
                      noGit: noGit || undefined,
                    }),
                  });
          driver.on(lineLogger ?? makeJsonLogger());
          driver.on(onPhaseEnd);
          driver.on(onRateLimits);
          try {
            const r = await driver.run();
            if (r.status === "complete") {
              await pruneCompletedArtifacts({
                resultsDir,
                mode: m,
                opts,
                json,
              });
            }
            if (lineLogger) await lineLogger.drain();
            return { requested: m, resolved: m, result: r };
          } catch (err) {
            if (lineLogger) await lineLogger.drain();
            throw err;
          }
        }),
      ).catch((err: Error) => {
        fatalError = err;
        stoppedReason = "fatal";
        return [];
      });
      for (const step of results) stepResults.push(step);
      aggUsd = stepResults.reduce((s, r) => s + r.result.totalUsd, 0);
      for (const step of stepResults) {
        emitStepSummary({ json, requested: step.requested, resolved: step.resolved, result: step.result, isChain });
      }
      if (abortController.signal.aborted) stoppedReason = "aborted";
    } else for (let i = 0; i < modes.length; i++) {
      const requestedMode = modes[i]!;

      // Resolve --mode refresh per-iteration so the routing sees artifacts
      // produced by the previous mode in the chain (e.g. deep → refresh
      // resolves to revisit because deep just wrote findings + KB).
      let mode: AuditMode = requestedMode;
      let refreshRouting: RefreshRouting | undefined;
      if (requestedMode === "refresh") {
        const routed = await resolveRefreshRouting(targetDir);
        mode = routed.mode;
        refreshRouting = routed.routing;
        if (!json) {
          console.log(chalk.green("[refresh]") + ` ${routed.logLine}`);
        }
      }

      // Aggregate cost cap: each driver gets the remaining budget.
      let remainingBudget: number | undefined;
      if (maxCost !== undefined) {
        remainingBudget = maxCost - aggUsd;
        if (remainingBudget <= 0) {
          if (!json) {
            console.log(
              chalk.blue(
                `[chain] budget exhausted ($${aggUsd.toFixed(2)} of $${maxCost.toFixed(2)}); skipping remaining modes: ${modes.slice(i).join(", ")}`,
              ),
            );
          }
          stoppedReason = "budget";
          break;
        }
      }

      if (isChain && !json) {
        console.log(
          chalk.green(`\n[chain ${i + 1}/${modes.length}]`) +
            ` mode=${requestedMode}${requestedMode !== mode ? ` → ${mode}` : ""}`,
        );
      }

      // Preflight cost estimate. Reads prior audits in vigolium-results/audit-state.json
      // for this mode and warns when the projection exceeds the remaining
      // budget. Strictly advisory — never aborts, never gates execution.
      try {
        const runnable = await countRunnablePhases({
          mode,
          targetDir,
          platform,
          excludePhases: refreshRouting?.excludePhases ?? [],
          noGit,
        });
        const { estimateCost } = await import("./cost-preflight.js");
        const est = await estimateCost({ targetDir, mode, runnablePhases: runnable });
        if (est) emitCostPreflight({ json, est, remainingBudget, aggUsd, maxCost });
      } catch {
        /* preflight is advisory — never block a run on it */
      }

      // Pick the audit driver. Both platforms hand off the whole mode to a
      // single CLI/SDK call when the runtime can dispatch sub-agents itself:
      //   - claude → `/vigolium-audit:vigolium-audit:<mode>` slash command + plugin.
      //   - codex  → AGENTS.md dispatch + ~/.codex/agents/* + ~/.codex/skills/*.
      // Codex's dispatch fragment only covers lite/balanced/deep/revisit/
      // confirm — for diff/merge/reinvest/longshot we fall back to the
      // per-phase Orchestrator since there's no codex-shaped methodology
      // for those yet.
      const useCodexHandoff = platform === "codex" && isCodexHandoffMode(mode);
      if (platform === "codex" && !useCodexHandoff && !json) {
        console.log(
          chalk.yellow("[codex]") +
            ` mode "${mode}" has no codex dispatch; running per-phase orchestrator instead`,
        );
      }
      const sharedHandoff = compact({
        debug: opts.debug || undefined,
        focus: auditContext.focus,
        expectedBehaviors: auditContext.expectedBehaviors,
        liveTarget: opts.liveTarget,
        excludePhases: refreshRouting?.excludePhases,
        triggeredVia: refreshRouting?.triggeredVia,
      });
      const driver: { on: typeof Orchestrator.prototype.on; run: () => Promise<OrchestratorResult> } =
        platform === "claude"
          ? new ClaudeHandoff({
              adapter,
              targetDir,
              mode,
              pluginDir: harness!.installResult.installPath,
              abortSignal: abortController.signal,
              ...sharedHandoff,
            })
          : useCodexHandoff
            ? new CodexHandoff({
                adapter,
                targetDir,
                mode,
                abortSignal: abortController.signal,
                ...sharedHandoff,
              })
            : new Orchestrator({
                adapter,
                loader: getContentLoader(),
                targetDir,
                mode,
                defaultModel: effectiveModel,
                failurePolicy: opts.strict ? "strict" : "skip-and-continue",
                interactive: false,
                abortSignal: abortController.signal,
                ...sharedHandoff,
                ...compact({
                  maxCost: remainingBudget,
                  stripRaw: opts.stripRaw || undefined,
                  resume:
                    opts.resume === true || refreshRouting?.resume === true
                      ? true
                      : undefined,
                  parallel: opts.serial ? false : undefined,
                  noGit: noGit || undefined,
                }),
              });

      const lineLogger = json
        ? null
        : makeLineLogger({ debug: !!opts.debug, streaming: !!opts.streaming });
      driver.on(lineLogger ?? makeJsonLogger());
      driver.on(onPhaseEnd);
      driver.on(onRateLimits);

      let result: OrchestratorResult | null = null;
      try {
        result = await driver.run();
      } catch (err) {
        fatalError = err as Error;
        stoppedReason = "fatal";
        if (lineLogger) await lineLogger.drain();
        break;
      }
      if (lineLogger) await lineLogger.drain();
      if (result === null) {
        fatalError = new Error("audit driver did not produce a result");
        stoppedReason = "fatal";
        break;
      }

      if (result.status === "complete") {
        await pruneCompletedArtifacts({
          resultsDir,
          mode,
          opts,
          json,
        });
      }

      stepResults.push({ requested: requestedMode, resolved: mode, result });
      aggUsd += result.totalUsd;

      emitStepSummary({ json, requested: requestedMode, resolved: mode, result, isChain });

      if (result.status !== "complete") {
        stoppedReason = abortController.signal.aborted ? "aborted" : "non-complete";
        break;
      }
      if (abortController.signal.aborted) {
        stoppedReason = "aborted";
        break;
      }
    }
  } finally {
    process.off("SIGINT", onSigint);
    harness?.cleanup();
  }

  const allComplete = stepResults.length === modes.length && stepResults.every((s) => s.result.status === "complete");

  // Final output sync + (on success) wipe of <targetDir>/vigolium-results/. Runs on
  // every exit path: fatal, non-complete, aborted, and complete. Cleanup is
  // gated on allComplete so a failed run preserves resume state.
  if (outputSyncer !== null) {
    await outputSyncer.sync();
    await outputSyncer.drain();
    if (allComplete && outputSyncer.getLastError() === null) {
      try {
        await rm(resultsDir, { recursive: true, force: true });
        if (json) emitJsonEvent({ kind: "outputCleanup", removed: resultsDir });
        else console.log(chalk.blue("[output]") + ` removed ${chalk.dim(resultsDir)} (results live in --output dir)`);
      } catch (err) {
        const msg = `[output] failed to remove ${resultsDir}: ${(err as Error).message}`;
        if (json) emitJsonEvent({ kind: "outputCleanupError", error: msg });
        else console.error(chalk.yellow(msg));
      }
    } else if (!json) {
      const reason = outputSyncer.getLastError() !== null
        ? "sync had errors"
        : "run did not complete";
      console.log(chalk.blue("[output]") + chalk.dim(` keeping ${resultsDir} (${reason})`));
    }
  }

  if (fatalError) {
    if (json) emitJsonEvent({ kind: "fatal", error: fatalError.message });
    else console.error(chalk.red(`\n[vigolium-audit] fatal: ${opts.debug && fatalError.stack ? fatalError.stack : fatalError.message}`));
    process.exit(1);
  }

  if (isChain) {
    emitChainSummary({ json, modes, stepResults, stoppedReason, aggUsd, maxCost });
  }
  process.exit(allComplete ? 0 : 1);
}

function emitStepSummary(args: {
  json: boolean;
  requested: AuditMode;
  resolved: AuditMode;
  result: OrchestratorResult;
  isChain: boolean;
}): void {
  const { json, requested, resolved, result: r, isChain } = args;
  if (json) {
    emitJsonEvent({
      kind: "result",
      auditId: r.auditId,
      requestedMode: requested,
      resolvedMode: resolved,
      status: r.status,
      totalUsd: r.totalUsd,
      totalTokens: r.totalTokens,
      findings: r.findings,
      failedPhases: r.failedPhases,
      skippedPhases: r.skippedPhases,
    });
    return;
  }
  const color = r.status === "complete" ? chalk.green : r.status === "failed" ? chalk.red : chalk.blue;
  const tag = isChain ? `[vigolium-audit ${requested}]` : `[vigolium-audit]`;
  console.log(
    color(
      `\n${tag} ${r.status} — audit ${chalk.magenta(r.auditId)} — ${chalk.yellow(`$${r.totalUsd.toFixed(2)}`)} ` +
        `— ${chalk.magenta(formatTokens(r.totalTokens.input))} token in / ${chalk.magenta(formatTokens(r.totalTokens.output))} token out ` +
        (r.failedPhases.length > 0 ? `failed: ${r.failedPhases.join(", ")} ` : "") +
        (r.skippedPhases.length > 0 ? `skipped: ${r.skippedPhases.join(", ")}` : ""),
    ),
  );
  console.log(`${color(`${tag} findings:`)} ${formatFindings(r.findings)}`);
}

function emitChainSummary(args: {
  json: boolean;
  modes: AuditMode[];
  stepResults: Array<{ requested: AuditMode; resolved: AuditMode; result: OrchestratorResult }>;
  stoppedReason: "complete" | "non-complete" | "fatal" | "budget" | "aborted";
  aggUsd: number;
  maxCost: number | undefined;
}): void {
  const { json, modes, stepResults, stoppedReason, aggUsd, maxCost } = args;
  const ranCount = stepResults.length;
  const allComplete = ranCount === modes.length && stepResults.every((s) => s.result.status === "complete");
  const aggIn = stepResults.reduce((s, r) => s + r.result.totalTokens.input, 0);
  const aggOut = stepResults.reduce((s, r) => s + r.result.totalTokens.output, 0);
  const aggFindings = stepResults.reduce((s, r) => s + r.result.findings.total, 0);
  if (json) {
    emitJsonEvent({
      kind: "chainResult",
      modes,
      ran: ranCount,
      stoppedReason,
      allComplete,
      totalUsd: round2(aggUsd),
      totalTokens: { input: aggIn, output: aggOut },
      totalFindings: aggFindings,
      ...(maxCost !== undefined ? { maxCost } : {}),
      steps: stepResults.map((s) => ({
        requestedMode: s.requested,
        resolvedMode: s.resolved,
        auditId: s.result.auditId,
        status: s.result.status,
        usd: s.result.totalUsd,
        findings: s.result.findings.total,
      })),
    });
    return;
  }
  const color = allComplete ? chalk.green : stoppedReason === "aborted" || stoppedReason === "budget" ? chalk.blue : chalk.red;
  const stepLine = stepResults
    .map((s) => `${s.requested}${s.requested !== s.resolved ? `→${s.resolved}` : ""}:${s.result.status}`)
    .join(" ");
  const skipped = modes.slice(ranCount);
  const skippedLine = skipped.length > 0 ? ` skipped: ${skipped.join(",")}` : "";
  console.log(
    color(
      `\n[chain] ${allComplete ? "complete" : stoppedReason} — ${ranCount}/${modes.length} modes — ` +
        `$${aggUsd.toFixed(2)}${maxCost !== undefined ? ` of $${maxCost.toFixed(2)}` : ""} — ${formatTokenPair({ input: aggIn, output: aggOut })} tok — ${aggFindings} findings`,
    ),
  );
  console.log(color(`[chain] ${stepLine}${skippedLine}`));
}


function formatFindings(findings: { total: number; bySeverity: Record<string, number> }): string {
  if (findings.total === 0) return "0";
  const parts = Object.entries(findings.bySeverity).map(
    ([sev, n]) => severityColor(sev)(`${sev}: ${n}`),
  );
  return `${findings.total} total — ${parts.join(", ")}`;
}

/**
 * Compact human-readable token count. Long-running deep audits chew through
 * tens of millions of tokens — `12345678` is unreadable mid-stream where
 * everything else is colorized and tight. Conventions:
 *   < 1k   → raw integer ("523")
 *   < 10k  → "1.2k"  (one decimal, useful when the order of magnitude shifts)
 *   < 1M   → "234k"  (integer — the decimal is noise)
 *   < 10M  → "1.5M"
 *   >= 10M → "23M"
 * Always non-negative; negative inputs are treated as 0 (defensive — the
 * adapter shouldn't emit negatives but we don't want to format "-NaN").
 */
export function formatTokens(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0";
  if (n < 1_000) return String(Math.round(n));
  if (n < 10_000) return `${(n / 1_000).toFixed(1)}k`;
  if (n < 1_000_000) return `${Math.round(n / 1_000)}k`;
  if (n < 10_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  return `${Math.round(n / 1_000_000)}M`;
}

function formatTokenPair(t: { input: number; output: number }): string {
  return `${formatTokens(t.input)}/${formatTokens(t.output)}`;
}

/**
 * Compact human-readable duration. Phase ends and audit ends print
 * `durationMs` directly off the wire, which for a multi-hour deep-mode run
 * looks like `8421319ms` — useless at a glance. Conventions:
 *   < 1s    → "234ms"
 *   < 60s   → "12.3s"   (one decimal, since seconds resolution matters)
 *   < 60m   → "5m 30s"
 *   >= 60m  → "2h 15m"
 */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "0ms";
  if (ms < 1_000) return `${Math.round(ms)}ms`;
  const totalSeconds = ms / 1_000;
  if (totalSeconds < 60) return `${totalSeconds.toFixed(1)}s`;
  const totalMinutes = Math.floor(totalSeconds / 60);
  const seconds = Math.round(totalSeconds - totalMinutes * 60);
  if (totalMinutes < 60) return `${totalMinutes}m ${seconds}s`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes - hours * 60;
  return `${hours}h ${minutes}m`;
}

/**
 * NDJSON event logger: each OrchestratorEvent becomes one JSON line on stdout.
 * Phases get serialized as { id, title, agent } so consumers don't have to
 * track schema-version of internal types.
 */
function makeJsonLogger(): (e: OrchestratorEvent) => void {
  const phaseSummary = (p: { id: string; title: string; agent: string | null }): {
    id: string;
    title: string;
    agent: string | null;
  } => ({ id: p.id, title: p.title, agent: p.agent });

  return (event: OrchestratorEvent) => {
    switch (event.kind) {
      case "auditStart":
        emitJsonEvent({
          kind: "auditStart",
          auditId: event.auditId,
          mode: event.mode,
          totalPhases: event.totalPhases,
          runnablePhases: event.runnablePhases,
        });
        return;
      case "phaseStart":
        emitJsonEvent({
          kind: "phaseStart",
          auditId: event.auditId,
          phase: phaseSummary(event.phase),
          index: event.index,
          total: event.total,
        });
        return;
      case "phaseSkip":
        emitJsonEvent({
          kind: "phaseSkip",
          auditId: event.auditId,
          phase: phaseSummary(event.phase),
          reason: event.reason,
        });
        return;
      case "phaseAdapterEvent":
        emitJsonEvent({
          kind: "phaseAdapterEvent",
          auditId: event.auditId,
          phaseId: event.phase.id,
          event: serializeAdapterEvent(event.event),
        });
        return;
      case "phaseEnd":
        emitJsonEvent({
          kind: "phaseEnd",
          auditId: event.auditId,
          phase: phaseSummary(event.phase),
          ok: event.ok,
          usd: event.usd,
          tokens: event.tokens,
          durationMs: event.durationMs,
          ...(event.error !== undefined ? { error: event.error } : {}),
          ...(event.synthetic ? { synthetic: true } : {}),
        });
        return;
      case "findingDiscovered":
        emitJsonEvent({
          kind: "findingDiscovered",
          auditId: event.auditId,
          phaseId: event.phaseId,
          path: event.path,
          relPath: event.relPath,
        });
        return;
      case "costWarn":
        emitJsonEvent({ kind: "costWarn", auditId: event.auditId, usd: event.usd, cap: event.cap });
        return;
      case "auditEnd":
        emitJsonEvent({
          kind: "auditEnd",
          auditId: event.auditId,
          status: event.status,
          usd: event.usd,
          tokens: event.tokens,
          findings: event.findings,
        });
        return;
    }
  };
}

function serializeAdapterEvent(e: import("../adapters/adapter.js").AdapterEvent): Record<string, unknown> {
  switch (e.kind) {
    case "error":
      return { kind: "error", message: e.cause.message, transient: e.transient ?? false };
    default:
      return { ...e } as Record<string, unknown>;
  }
}

type LineLogger = ((e: OrchestratorEvent) => void) & { drain: () => Promise<void> };

function makeLineLogger(opts: { debug: boolean; streaming?: boolean } = { debug: false }): LineLogger {
  const { debug, streaming = false } = opts;
  // Default truncation lengths; --debug widens them.
  const inputCap = debug ? 300 : 100;
  const outputCap = debug ? 500 : 120;
  const thinkingCap = debug ? 500 : 160;
  const streamCharDelayMs = 5; // ~200 chars/sec — brisk but visibly typewriter

  // Async output queue: only used when streaming is on. Tool calls and other
  // non-text events go through it too, so they appear AFTER any in-flight
  // typewriter animation (preserving chronological order).
  const tasks: Array<() => Promise<void>> = [];
  let pumping = false;
  const pumpStart = (): void => {
    if (pumping) return;
    pumping = true;
    void (async () => {
      while (tasks.length > 0) {
        const t = tasks.shift()!;
        try {
          await t();
        } catch {
          /* swallow — render-path errors shouldn't crash the run */
        }
      }
      pumping = false;
    })();
  };
  const enqueue = (t: () => Promise<void>): void => {
    tasks.push(t);
    pumpStart();
  };
  const drain = async (): Promise<void> => {
    if (!streaming) return;
    while (pumping || tasks.length > 0) await new Promise<void>((r) => setTimeout(r, 5));
  };

  // Print a complete line. Routes through the queue when streaming so it
  // doesn't jump ahead of in-flight typewriter output.
  const printLine = (s: string): void => {
    if (streaming) enqueue(async () => void process.stdout.write(s + "\n"));
    else process.stdout.write(s + "\n");
  };

  // Track active phases so we can prefix concurrent output with the phase id.
  // When only one phase is running, the prefix is omitted to keep the log
  // identical to the historical serial layout.
  const activePhases = new Set<string>();
  const phaseTextBuffers = new Map<string, string>();
  const phaseTag = (phaseId: string): string =>
    activePhases.size > 1 ? chalk.dim(`[${phaseId}] `) : "";

  const writeAgentLine = (phaseId: string, line: string): void => {
    const prefix = `  ${chalk.magenta("●")} ${phaseTag(phaseId)}`;
    if (line.length === 0) {
      printLine("");
      return;
    }
    if (streaming) {
      enqueue(async () => {
        process.stdout.write(prefix);
        for (const ch of line) {
          process.stdout.write(ch);
          await new Promise<void>((r) => setTimeout(r, streamCharDelayMs));
        }
        process.stdout.write("\n");
      });
    } else {
      process.stdout.write(`${prefix}${line}\n`);
    }
  };
  const writeAgentLines = (phaseId: string, chunk: string): void => {
    const body = chunk.endsWith("\n") ? chunk.slice(0, -1) : chunk;
    if (body.length === 0) {
      printLine("");
      return;
    }
    for (const line of body.split("\n")) writeAgentLine(phaseId, line);
  };
  const flushBuffer = (phaseId: string): void => {
    const buf = phaseTextBuffers.get(phaseId) ?? "";
    if (buf.length === 0) return;
    const chunk = buf.endsWith("\n") ? buf : buf + "\n";
    phaseTextBuffers.set(phaseId, "");
    writeAgentLines(phaseId, chunk);
  };
  const flushAllBuffers = (): void => {
    for (const id of phaseTextBuffers.keys()) flushBuffer(id);
  };

  // The session event arrives from the adapter after phaseStart fires, so we
  // defer the first phase header until session lands — that lets us print
  // session between [audit …] and [phase L1] instead of under the phase.
  let sessionPrinted = false;
  let deferredPhaseHeader: string | null = null;
  const flushDeferredHeader = (): void => {
    if (deferredPhaseHeader === null) return;
    printLine(deferredPhaseHeader);
    deferredPhaseHeader = null;
  };

  // Render the session-id line plus a one-line summary of what the session
  // actually loaded (plugins / agents / commands / skills / model / perm).
  // Called from both the deferred-header path and the regular switch branch
  // so the formatting stays in lockstep.
  const printSessionAndLoaded = (
    e: Extract<import("../adapters/adapter.js").AdapterEvent, { kind: "session" }>,
  ): void => {
    printLine(`${statusArrow("Session")} Session:   ${chalk.cyan(e.sessionId)}`);
    const parts: string[] = [];
    if (e.plugins && e.plugins.length > 0) {
      parts.push(`plugin=${chalk.cyan(e.plugins.map((p) => p.name).join(","))}`);
    }
    if (e.agents) parts.push(`agents=${chalk.cyan(e.agents.length)}`);
    if (e.commands) parts.push(`commands=${chalk.cyan(e.commands.length)}`);
    if (e.skills) parts.push(`skills=${chalk.cyan(e.skills.length)}`);
    if (e.model) parts.push(`model=${chalk.cyan(e.model)}`);
    if (e.permissionMode) parts.push(`perm=${chalk.cyan(e.permissionMode)}`);
    if (parts.length > 0) {
      printLine(`${statusArrow("Loaded")} Loaded:    ${parts.join(chalk.dim(" · "))}`);
    }
  };

  const handle = (event: OrchestratorEvent): void => {
    switch (event.kind) {
      case "auditStart":
        printLine(
          `${statusArrow("Audit")} Audit:     ${chalk.cyan(event.auditId)} ` +
            chalk.dim(`(${event.runnablePhases}/${event.totalPhases} phases)`),
        );
        break;
      case "phaseStart": {
        activePhases.add(event.phase.id);
        phaseTextBuffers.set(event.phase.id, "");
        const header =
          chalk.blue(`\n[phase ${event.phase.id}] ${event.phase.title} (${event.index}/${event.total})`) +
          ` agent=${event.phase.agent ?? "(inline)"}`;
        if (!sessionPrinted) deferredPhaseHeader = header;
        else printLine(header);
        break;
      }
      case "phaseSkip":
        flushDeferredHeader();
        printLine(`[phase ${event.phase.id}] skipped — ${event.reason}`);
        break;
      case "phaseAdapterEvent": {
        const e = event.event;
        const phaseId = event.phase.id;
        if (e.kind === "session" && !sessionPrinted) {
          printSessionAndLoaded(e);
          sessionPrinted = true;
          flushDeferredHeader();
          break;
        }
        flushDeferredHeader();
        // Flush this phase's pending text before non-text events so messages
        // appear interleaved with tool calls in chronological order. Codex
        // emits `agent_message` items as a single textDelta with no trailing
        // newline, so this is the only chance to print them in-flow.
        if (e.kind !== "textDelta") flushBuffer(phaseId);
        switch (e.kind) {
          case "textDelta": {
            const buf = (phaseTextBuffers.get(phaseId) ?? "") + e.text;
            const lastNl = buf.lastIndexOf("\n");
            if (lastNl >= 0) {
              writeAgentLines(phaseId, buf.slice(0, lastNl + 1));
              phaseTextBuffers.set(phaseId, buf.slice(lastNl + 1));
            } else {
              phaseTextBuffers.set(phaseId, buf);
            }
            break;
          }
          case "toolCall": {
            const param = debug ? truncate(JSON.stringify(e.input), inputCap) : truncate(toolHeadline(e.input), inputCap);
            printLine(`  ${phaseTag(phaseId)}` + chalk.green(`ƒ ${e.tool}`) + (param ? chalk.dim(" · ") + chalk.cyan(param) : ""));
            break;
          }
          case "toolResult": {
            const out = typeof e.output === "string" ? e.output : JSON.stringify(e.output);
            const preview = truncate(oneLine(out), outputCap);
            if (preview) {
              const arrowSym = e.isError ? chalk.red("✗") : chalk.dim("←");
              const body = e.isError ? chalk.red(preview) : chalk.gray(preview);
              printLine(`    ${phaseTag(phaseId)}${arrowSym} ${body}`);
            }
            break;
          }
          case "thinking": {
            const lines = e.text.split("\n").map((l) => l.trimEnd()).filter((l) => l.length > 0);
            for (const line of lines) {
              printLine(chalk.dim(`  ${phaseTag(phaseId)}⏚ `) + chalk.dim(truncate(line, thinkingCap)));
            }
            break;
          }
          case "session":
            printSessionAndLoaded(e);
            break;
          case "error":
            printLine(
              chalk.red(
                `  ${phaseTag(phaseId)}! adapter error${e.transient ? " [transient]" : ""}: ${debug && e.cause.stack ? e.cause.stack : e.cause.message}`,
              ),
            );
            break;
          default:
            break;
        }
        break;
      }
      case "phaseEnd":
        flushDeferredHeader();
        flushBuffer(event.phase.id);
        activePhases.delete(event.phase.id);
        phaseTextBuffers.delete(event.phase.id);
        if (event.ok) {
          if (event.synthetic) {
            printLine(chalk.green(`  ✓ ${event.phase.id} done ${chalk.dim("(handoff — usage tallied at run end)")}`));
          } else {
            printLine(
              chalk.green(
                `  ✓ ${event.phase.id} done — ${chalk.magenta(`$${event.usd.toFixed(2)}`)} — ${chalk.magenta(formatTokenPair(event.tokens))} tok — ${chalk.magenta(formatDuration(event.durationMs))}`,
              ),
            );
          }
        } else if (event.synthetic) {
          printLine(chalk.red(`  ✗ ${event.phase.id} failed — ${event.error ?? "(no message)"} ${chalk.dim("(handoff)")}`));
        } else {
          printLine(
            chalk.red(`  ✗ ${event.phase.id} failed — ${event.error ?? "(no message)"} — $${event.usd.toFixed(2)}`),
          );
        }
        break;
      case "findingDiscovered":
        flushDeferredHeader();
        printLine(chalk.green(`  + finding: ${event.relPath}`));
        break;
      case "costWarn":
        flushDeferredHeader();
        printLine(`  ! cost ${event.usd.toFixed(2)} of cap ${event.cap.toFixed(2)}`);
        break;
      case "auditEnd":
        flushDeferredHeader();
        flushAllBuffers();
        if (debug)
          printLine(
            `[audit ${event.auditId}] ${event.status} (cost $${event.usd.toFixed(2)}, ` +
              `${formatTokenPair(event.tokens)} tok, ${event.findings.total} findings)`,
          );
        break;
    }
  };
  return Object.assign(handle, { drain });
}

/**
 * Pull a single human-friendly headline from a tool call's input — the
 * one piece of context most worth reading in a fast-scrolling log.
 *   Bash   → input.command
 *   Read   → input.file_path
 *   Edit   → input.file_path
 *   Write  → input.file_path
 *   Glob   → input.pattern
 *   Grep   → input.pattern
 *   WebFetch → input.url
 *   WebSearch → input.query
 *   Task   → input.subagent_type / input.description
 * Falls back to compact JSON for unknown tool shapes.
 */
function toolHeadline(input: unknown): string {
  if (input === null || input === undefined) return "";
  if (typeof input !== "object") return String(input);
  const i = input as Record<string, unknown>;
  for (const key of ["command", "file_path", "path", "pattern", "url", "query", "subagent_type", "description"]) {
    const v = i[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  const compact = JSON.stringify(input);
  return compact === "{}" ? "" : compact;
}

function oneLine(s: string): string {
  return s.replace(/\r?\n/g, " ⏎ ").replace(/\s{2,}/g, " ");
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n) + `…(+${s.length - n}b)`;
}

/**
 * Resolve focus + expected-behaviors strings for this run.
 *
 * Precedence per field:
 *   1. Explicit flag (--focus-file / --expected-behaviors-file)  — file is read,
 *      validated against the 32 KB cap, and used as-is.
 *   2. Inheritance from the most recent prior audit's `context` block in
 *      `vigolium-results/audit-state.json` — logged so the user knows what's in scope.
 *   3. Undefined (no block injected into prompts).
 *
 * Pass an empty file to opt out of inheritance for a given field without
 * inheriting prior context.
 *
 * Throws (caught by caller for fatal exit) on missing file or oversize file.
 */
export async function resolveAuditContext(args: {
  targetDir: string;
  opts: RunOptions;
  json: boolean;
}): Promise<{ focus?: string; expectedBehaviors?: string }> {
  const { targetDir, opts, json } = args;
  const out: { focus?: string; expectedBehaviors?: string } = {};

  let priorAudit: Awaited<ReturnType<StateStore["latestAudit"]>> | null = null;
  const needInheritance =
    opts.focusFile === undefined || opts.expectedBehaviorsFile === undefined;
  if (needInheritance) {
    try {
      priorAudit = await new StateStore(join(targetDir, "vigolium-results")).latestAudit("any");
    } catch {
      priorAudit = null;
    }
  }

  if (opts.focusFile !== undefined) {
    out.focus = await readContextFile("--focus-file", opts.focusFile);
  } else if (priorAudit?.context?.focus) {
    out.focus = priorAudit.context.focus;
    if (!json) {
      console.log(`[vigolium-audit] inheriting --focus-file from audit ${priorAudit.audit_id}`);
    }
  }

  if (opts.expectedBehaviorsFile !== undefined) {
    out.expectedBehaviors = await readContextFile(
      "--expected-behaviors-file",
      opts.expectedBehaviorsFile,
    );
  } else if (priorAudit?.context?.expected_behaviors) {
    out.expectedBehaviors = priorAudit.context.expected_behaviors;
    if (!json) {
      console.log(
        `[vigolium-audit] inheriting --expected-behaviors-file from audit ${priorAudit.audit_id}`,
      );
    }
  }

  return out;
}

/** Count phases the orchestrator would actually run for a mode/platform combo. */
async function countRunnablePhases(args: {
  mode: AuditMode;
  targetDir: string;
  platform: AgentPlatform;
  excludePhases: string[];
  noGit?: boolean;
}): Promise<number> {
  const loader = getContentLoader();
  const variant = args.platform === "codex" ? "sdk" : "default";
  const command = await loader.loadCommand(args.mode, { variant });
  const gitAvailable = args.noGit ? false : probeGit(args.targetDir).available;
  const exclude = new Set(args.excludePhases);
  return command.phases.filter((p) => {
    if (p.requires_git && !gitAvailable) return false;
    if (exclude.has(p.id)) return false;
    return true;
  }).length;
}

function emitCostPreflight(args: {
  json: boolean;
  est: import("./cost-preflight.js").PreflightEstimate;
  remainingBudget: number | undefined;
  aggUsd: number;
  maxCost: number | undefined;
}): void {
  const { json, est, remainingBudget, maxCost } = args;
  const overBudget = remainingBudget !== undefined && est.estimatedUsd > remainingBudget;
  if (json) {
    emitJsonEvent({
      kind: "costPreflight",
      mode: est.mode,
      avgPerPhase: est.avgPerPhase,
      expectedRunnablePhases: est.expectedRunnablePhases,
      estimatedUsd: est.estimatedUsd,
      sampleSize: est.sampleSize,
      fromBaseline: est.fromBaseline,
      remainingBudget: remainingBudget ?? null,
      overBudget,
    });
    return;
  }
  const tag = chalk.blue("[preflight]");
  const source = est.fromBaseline
    ? chalk.dim(`baseline $${est.avgPerPhase}/phase`)
    : chalk.dim(`avg $${est.avgPerPhase}/phase from ${est.sampleSize} prior run${est.sampleSize === 1 ? "" : "s"}`);
  const projection = `~${chalk.magenta(`$${est.estimatedUsd.toFixed(2)}`)} for ${est.expectedRunnablePhases} phases`;
  if (overBudget && maxCost !== undefined) {
    console.log(
      `${tag} ${chalk.yellow("warn")} ${projection} exceeds remaining budget ` +
        chalk.yellow(`$${remainingBudget?.toFixed(2)} of $${maxCost.toFixed(2)}`) +
        ` — ${source}`,
    );
  } else {
    console.log(`${tag} ${projection} — ${source}`);
  }
}

async function readContextFile(label: string, p: string): Promise<string> {
  const resolved = resolve(p);
  let content: string;
  try {
    content = await readFile(resolved, "utf8");
  } catch (err) {
    throw new Error(`${label}: cannot read ${resolved}: ${(err as Error).message}`);
  }
  const bytes = Buffer.byteLength(content, "utf8");
  if (bytes > MAX_CONTEXT_BYTES) {
    throw new Error(
      `${label}: ${resolved} is ${bytes} bytes, exceeds the ${MAX_CONTEXT_BYTES}-byte cap. ` +
        `Trim or split the file — silent truncation in audit input would be a footgun.`,
    );
  }
  return content;
}

