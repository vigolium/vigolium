import { existsSync } from "fs";
import { join, resolve } from "path";
import chalk from "chalk";
import { getContentLoader, resolveRoots, type ContentVariant } from "../content-loader.js";
import { composeUserPrompt, parseToolsField } from "../engine/orchestrator.js";
import { topologicalOrder } from "../engine/phase.js";
import { probeGit } from "../engine/git.js";
import { compact } from "../engine/util.js";
import type { AgentPlatform, AuditMode, CommandDef, PhaseDef, RunOptions } from "../engine/types.js";
import { resolveRequestedModes, resolveAuditContext } from "./run.js";
import { detectRefreshRoute } from "./refresh-detect.js";
import { failCli, statusArrow } from "./util.js";

/**
 * Render the resolved phase plan, prompts, and content provenance without
 * invoking any adapter. Useful for verifying mode edits or per-user overrides
 * before burning tokens.
 *
 * Refresh routing IS resolved (so users see what mode would actually run),
 * but no in-progress audit is consulted — dry-run never touches state.
 */
export async function dryRunCommand(opts: RunOptions): Promise<void> {
  const json = !!opts.json;
  let requestedModes: AuditMode[];
  try {
    requestedModes = resolveRequestedModes(opts);
  } catch (err) {
    return fail(json, (err as Error).message);
  }
  const platform = (opts.agent ?? "claude") as AgentPlatform;
  if (platform !== "claude" && platform !== "codex") {
    return fail(json, `--agent must be "claude" or "codex"`);
  }
  const targetDir = resolve(opts.target ?? ".");
  const loader = getContentLoader();
  const roots = resolveRoots();
  const variant: ContentVariant = platform === "codex" ? "sdk" : "default";
  const noGit = opts.git === false;
  const git = noGit
    ? { available: false, branch: null, commit: null, repository: null }
    : probeGit(targetDir);

  let auditContext: { focus?: string; expectedBehaviors?: string };
  try {
    auditContext = await resolveAuditContext({ targetDir, opts, json });
  } catch (err) {
    return fail(json, (err as Error).message);
  }

  const plans: ModePlan[] = [];
  for (const requested of requestedModes) {
    let resolvedMode: AuditMode = requested;
    let routingNote: string | undefined;
    let excludePhases: string[] | undefined;
    if (requested === "refresh") {
      const route = await detectRefreshRoute(targetDir);
      if (route.route === "revisit") {
        resolvedMode = "revisit";
        routingNote = `refresh → revisit (${route.reason})`;
      } else {
        resolvedMode = "deep";
        excludePhases = route.excludePhases;
        routingNote = `refresh → deep, excludes [${route.excludePhases.join(",")}] (${route.reason})`;
      }
    }
    plans.push(
      await buildModePlan({
        loader,
        roots,
        variant,
        platform,
        targetDir,
        requestedMode: requested,
        resolvedMode,
        gitAvailable: git.available,
        noGit,
        ...compact({
          routingNote,
          excludePhases,
          focus: auditContext.focus,
          expectedBehaviors: auditContext.expectedBehaviors,
          liveTarget: opts.liveTarget,
        }),
      }),
    );
  }

  if (json) {
    process.stdout.write(
      JSON.stringify({
        kind: "dryRun",
        platform,
        targetDir,
        gitAvailable: git.available,
        noGit,
        focus: auditContext.focus ?? null,
        expectedBehaviors: auditContext.expectedBehaviors ?? null,
        maxCost: opts.maxCost ?? null,
        plans: plans.map(serializePlan),
      }) + "\n",
    );
    return;
  }

  renderPlans({ platform, targetDir, gitAvailable: git.available, noGit, plans, opts });
}

interface ResolvedPhase {
  phase: PhaseDef;
  skipped: boolean;
  skipReason?: string;
  contentOrigin: "override" | "sdk-variant" | "embedded";
  agentSource: string;
  systemPromptChars: number;
  userPromptChars: number;
  tools: string[];
}

interface ModePlan {
  requestedMode: AuditMode;
  resolvedMode: AuditMode;
  routingNote?: string;
  commandSourcePath: string;
  commandOrigin: "override" | "sdk-variant" | "embedded";
  bodyChars: number;
  phases: ResolvedPhase[];
}

async function buildModePlan(args: {
  loader: ReturnType<typeof getContentLoader>;
  roots: ReturnType<typeof resolveRoots>;
  variant: ContentVariant;
  platform: AgentPlatform;
  targetDir: string;
  requestedMode: AuditMode;
  resolvedMode: AuditMode;
  routingNote?: string;
  excludePhases?: string[];
  gitAvailable: boolean;
  noGit?: boolean;
  focus?: string;
  expectedBehaviors?: string;
  liveTarget?: string;
}): Promise<ModePlan> {
  const command = await args.loader.loadCommand(args.resolvedMode, { variant: args.variant });
  const ordered = topologicalOrder(command.phases);
  const excludeSet = new Set(args.excludePhases ?? []);

  const userPromptCtx = compact({
    focus: args.focus,
    expectedBehaviors: args.expectedBehaviors,
    liveTarget: args.liveTarget,
  });

  const phases: ResolvedPhase[] = await Promise.all(
    ordered.map(async (phase) => {
      const skipReason = phase.requires_git && !args.gitAvailable
        ? args.noGit
          ? "requires_git, but git checks disabled via --no-git"
          : "requires_git but target has no git history"
        : excludeSet.has(phase.id)
          ? "excluded by refresh fresh-fallback policy"
          : undefined;

      let agentSource = "(inline)";
      let systemPrompt: string;
      let tools: string[];
      if (phase.agent) {
        const agent = await args.loader.loadAgent(phase.agent, { variant: args.variant });
        systemPrompt = agent.body.trim();
        tools = agent.tools ?? [];
        agentSource = phase.agent;
      } else {
        systemPrompt = command.body;
        tools = parseToolsField(command.allowed_tools_raw);
      }
      const userPrompt = composeUserPrompt(phase, command, "dry-run", args.targetDir, userPromptCtx);
      const contentOrigin = await detectAgentOrigin({
        roots: args.roots,
        variant: args.variant,
        agentName: phase.agent,
      });

      return {
        phase,
        skipped: skipReason !== undefined,
        ...(skipReason !== undefined ? { skipReason } : {}),
        contentOrigin,
        agentSource,
        systemPromptChars: systemPrompt.length,
        userPromptChars: userPrompt.length,
        tools,
      };
    }),
  );

  return {
    requestedMode: args.requestedMode,
    resolvedMode: args.resolvedMode,
    ...(args.routingNote !== undefined ? { routingNote: args.routingNote } : {}),
    commandSourcePath: command.source_path,
    commandOrigin: detectOriginFromPath(command.source_path, args.roots, args.variant),
    bodyChars: command.body.length,
    phases,
  };
}

async function detectAgentOrigin(args: {
  roots: ReturnType<typeof resolveRoots>;
  variant: ContentVariant;
  agentName: string | null;
}): Promise<"override" | "sdk-variant" | "embedded"> {
  if (!args.agentName) return "embedded";
  const overridePath = join(args.roots.overrideRoot, "agents", `${args.agentName}.md`);
  if (existsSync(overridePath)) return "override";
  if (args.variant === "sdk") {
    const variantPath = join(args.roots.contentRoot, "sdk-variants", "agent-defs", `${args.agentName}.md`);
    if (existsSync(variantPath)) return "sdk-variant";
  }
  return "embedded";
}

function detectOriginFromPath(
  sourcePath: string,
  roots: ReturnType<typeof resolveRoots>,
  variant: ContentVariant,
): "override" | "sdk-variant" | "embedded" {
  if (sourcePath.startsWith(roots.overrideRoot)) return "override";
  if (variant === "sdk" && sourcePath.includes(`${join("sdk-variants")}${"/"}`)) return "sdk-variant";
  return "embedded";
}

function serializePlan(p: ModePlan): unknown {
  return {
    requestedMode: p.requestedMode,
    resolvedMode: p.resolvedMode,
    routingNote: p.routingNote ?? null,
    commandSourcePath: p.commandSourcePath,
    commandOrigin: p.commandOrigin,
    bodyChars: p.bodyChars,
    phases: p.phases.map((ph) => ({
      id: ph.phase.id,
      title: ph.phase.title,
      agent: ph.phase.agent,
      requiresGit: ph.phase.requires_git,
      dependsOn: ph.phase.depends_on,
      parallelWith: ph.phase.parallel_with,
      skipped: ph.skipped,
      skipReason: ph.skipReason ?? null,
      contentOrigin: ph.contentOrigin,
      systemPromptChars: ph.systemPromptChars,
      userPromptChars: ph.userPromptChars,
      tools: ph.tools,
    })),
  };
}

function renderPlans(args: {
  platform: AgentPlatform;
  targetDir: string;
  gitAvailable: boolean;
  noGit?: boolean;
  plans: ModePlan[];
  opts: RunOptions;
}): void {
  console.log(chalk.bold(`\narchon — dry run (no adapter calls)`));
  console.log(`${statusArrow("Platform")} Platform:  ${chalk.cyan(args.platform)}`);
  console.log(`${statusArrow("Target")} Target:    ${chalk.cyan(args.targetDir)}`);
  const gitLine = args.noGit
    ? chalk.yellow("skipped (--no-git)")
    : args.gitAvailable
      ? chalk.green("available")
      : chalk.yellow("unavailable");
  console.log(`${statusArrow("Git")} Git:       ${gitLine}`);
  if (args.opts.maxCost !== undefined) console.log(`${statusArrow("Max cost")} Max cost:  ${chalk.cyan(`$${args.opts.maxCost}`)}`);
  if (args.opts.focusFile) console.log(`${statusArrow("Focus")} Focus:     ${chalk.cyan(args.opts.focusFile)}`);
  if (args.opts.expectedBehaviorsFile) console.log(`${statusArrow("Expected")} Expected:  ${chalk.cyan(args.opts.expectedBehaviorsFile)}`);
  if (args.opts.liveTarget) console.log(`${statusArrow("Live")} Live:      ${chalk.cyan(args.opts.liveTarget)}`);

  for (const plan of args.plans) {
    const header = plan.requestedMode === plan.resolvedMode
      ? plan.resolvedMode
      : `${plan.requestedMode} → ${plan.resolvedMode}`;
    console.log(chalk.green(`\n[mode ${header}]`) + (plan.routingNote ? chalk.dim(` ${plan.routingNote}`) : ""));
    console.log(`  source: ${chalk.dim(plan.commandSourcePath)} ${chalk.dim(`(${plan.commandOrigin}, ${plan.bodyChars} body chars)`)}`);

    for (const ph of plan.phases) {
      const status = ph.skipped ? chalk.dim("[skip]") : chalk.green("[run] ");
      const agent = ph.phase.agent ? chalk.cyan(ph.phase.agent) : chalk.dim("(inline)");
      const tools = ph.tools.length > 0 ? chalk.dim(` tools=${ph.tools.length}`) : chalk.dim(" tools=∅");
      const promptInfo = chalk.dim(` sys=${ph.systemPromptChars}c usr=${ph.userPromptChars}c`);
      const origin = chalk.dim(` (${ph.contentOrigin})`);
      console.log(`  ${status} ${ph.phase.id.padEnd(5)} ${ph.phase.title}  · ${agent}${origin}${promptInfo}${tools}`);
      if (ph.skipped && ph.skipReason) {
        console.log(`           ${chalk.dim("→ ")}${chalk.dim(ph.skipReason)}`);
      }
      if (ph.phase.depends_on.length > 0) {
        console.log(`           ${chalk.dim(`depends_on: ${ph.phase.depends_on.join(", ")}`)}`);
      }
      if (ph.phase.parallel_with.length > 0) {
        console.log(`           ${chalk.dim(`parallel_with: ${ph.phase.parallel_with.join(", ")}`)}`);
      }
    }
  }

  console.log(chalk.dim(`\nNothing executed. Drop --dry-run to run for real.`));
}

function fail(json: boolean, msg: string): never {
  return failCli({ json }, "fatal", msg);
}
