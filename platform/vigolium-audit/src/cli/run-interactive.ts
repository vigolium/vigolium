import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawn } from "child_process";
import chalk from "chalk";
import { probeClaudeBinary, probeCodexBinary } from "../adapters/detect.js";
import { probeGit } from "../engine/git.js";
import { writeAuditContext } from "../engine/audit-context.js";
import { claudePluginDir, codexAgentsDir, registerEphemeralHarness } from "../engine/harness.js";
import type { AgentPlatform, AuditMode } from "../engine/types.js";
import { DEFAULT_CODEX_REASONING_EFFORT, resolveDefaultModel } from "./run-models.js";
import { statusArrow } from "./util.js";

/**
 * Interactive mode (`-i` / `--interactive`).
 *
 * Drops the user into the underlying coding agent (claude / codex) with our
 * vigolium-audit plugin attached. We don't drive the SDK loop; we just hand off to
 * the native CLI in interactive mode so the user can drive the audit (resume,
 * edit prompts, run multiple modes) as themselves.
 */
export async function runInteractive(args: {
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
