import { readFileSync } from "fs";
import { resolve } from "path";
import chalk from "chalk";
import type { AuthOverrideHandle } from "../engine/auth-overrides.js";
import {
  applyBridgeAuth,
  buildBridgeAdapter,
  describeInvocation,
  resolveBridgeInvocation,
  runBridge,
  type BridgeOptions,
} from "../engine/bridge.js";
import { listBridgeTasks } from "../engine/bridge-tasks.js";
import { parseToolsField } from "../engine/prompts.js";
import type { AgentPlatform } from "../engine/types.js";
import { makeBridgeHumanRenderer } from "./bridge-render.js";
import { emitJsonEvent, serializeAdapterEvent } from "./run-render.js";
import { resolveModel } from "./run-models.js";
import { serveBridge } from "./bridge-serve.js";
import { failCli, statusArrow } from "./util.js";

/** Flags accepted by `bridge` (in addition to the global --agent/--json/--debug). */
export interface BridgeCliOptions {
  agent?: AgentPlatform;
  json?: boolean;
  debug?: boolean;
  model?: string;
  cwd?: string;
  target?: string;
  prompt?: string;
  promptFile?: string;
  input?: string;
  inputFile?: string;
  systemPrompt?: string;
  systemPromptFile?: string;
  skill?: string | string[];
  allowTools?: string;
  denyTools?: string;
  maxTurns?: number | string;
  resume?: string;
  output?: string;
  bypassPermissions?: boolean; // --no-bypass-permissions sets false
  apiKey?: string;
  oauthToken?: string;
  oauthCredFile?: string;
}

function toArray(v: string | string[] | undefined): string[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return "";
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

/** Resolve prompt text from --prompt, --prompt-file, or piped stdin (in that order). */
async function resolvePromptText(opts: BridgeCliOptions): Promise<string | undefined> {
  if (opts.prompt !== undefined) return opts.prompt;
  if (opts.promptFile !== undefined) return readFileSync(resolve(opts.promptFile), "utf8");
  const stdin = await readStdin();
  return stdin.trim().length > 0 ? stdin : undefined;
}

export async function bridgeCommand(action: string, opts: BridgeCliOptions): Promise<void> {
  if (action === "serve") {
    return serveBridge(opts);
  }
  const json = !!opts.json;

  if (action === "list") {
    const tasks = listBridgeTasks();
    if (json) emitJsonEvent({ kind: "tasks", tasks });
    else {
      console.log(chalk.bold("bridge tasks:"));
      for (const t of tasks) console.log(`  ${chalk.cyan(t)}`);
      console.log(`  ${chalk.cyan("run")} ${chalk.dim("(raw prompt, no preset)")}`);
    }
    return;
  }

  const platform = (opts.agent ?? "claude") as AgentPlatform;
  if (platform !== "claude" && platform !== "codex") {
    failCli({ json }, "bridge", `--agent must be "claude" or "codex"`);
  }

  const cwd = resolve(opts.cwd ?? opts.target ?? ".");

  let promptText: string | undefined;
  try {
    promptText = await resolvePromptText(opts);
  } catch (err) {
    failCli({ json }, "bridge", `failed to read prompt: ${(err as Error).message}`);
  }

  const inputText =
    opts.inputFile !== undefined
      ? readFileSync(resolve(opts.inputFile), "utf8")
      : opts.input;

  const systemPromptOverride =
    opts.systemPromptFile !== undefined
      ? readFileSync(resolve(opts.systemPromptFile), "utf8")
      : opts.systemPrompt;

  // `--model` → VIGOLIUM_AUDIT_MODEL → runtime default (shared with `run`).
  const model = resolveModel(opts.model);

  const bridgeOpts: BridgeOptions = {
    action,
    platform,
    cwd,
    skills: toArray(opts.skill),
    disallowedTools: parseToolsField(opts.denyTools),
    bypassPermissions: opts.bypassPermissions ?? true,
    ...(promptText !== undefined ? { prompt: promptText } : {}),
    ...(inputText !== undefined ? { input: inputText } : {}),
    ...(systemPromptOverride !== undefined ? { systemPrompt: systemPromptOverride } : {}),
    ...(opts.allowTools !== undefined ? { tools: parseToolsField(opts.allowTools) } : {}),
    ...(model !== undefined ? { model } : {}),
    ...(opts.maxTurns !== undefined && Number.isFinite(Number(opts.maxTurns))
      ? { maxTurns: Number(opts.maxTurns) }
      : {}),
    ...(opts.resume !== undefined ? { resume: opts.resume } : {}),
    ...(opts.output === "json" || opts.output === "text" ? { output: opts.output } : {}),
  };

  // Auth overrides live for the whole run and restore on exit / signal.
  let authHandle: AuthOverrideHandle | undefined;
  try {
    authHandle = applyBridgeAuth({
      platform,
      ...(opts.apiKey !== undefined ? { apiKey: opts.apiKey } : {}),
      ...(opts.oauthToken !== undefined ? { oauthToken: opts.oauthToken } : {}),
      ...(opts.oauthCredFile !== undefined ? { oauthCredFile: opts.oauthCredFile } : {}),
    });
  } catch (err) {
    failCli({ json }, "bridge", (err as Error).message);
  }

  const abort = new AbortController();
  const onSigint = (): void => abort.abort(new Error("interrupted"));
  process.once("SIGINT", onSigint);

  try {
    const { adapter, choice } = buildBridgeAdapter(platform, bridgeOpts.model);
    const inv = await resolveBridgeInvocation(bridgeOpts);

    if (json) {
      emitJsonEvent({
        kind: "ready",
        ...describeInvocation(inv, choice),
        cwd,
        ...(inv.resume ? { resume: inv.resume } : {}),
      });
    } else {
      console.log(`${statusArrow("Bridge")} Bridge:   ${chalk.cyan(inv.action)} ${chalk.dim(`(${platform}, sdk)`)}`);
      console.log(`${statusArrow("Target")} Target:   ${chalk.cyan(cwd)}`);
      console.log(`${statusArrow("Skills")} Skills:   ${chalk.cyan(inv.skills.join(", "))}`);
      console.log(
        `${statusArrow("Model")} Model:    ${inv.model ? chalk.cyan(inv.model) : chalk.dim("runtime default")} ` +
          chalk.dim(`· output=${inv.output} · auth=${choice.authSource}`),
      );
      if (inv.resume) console.log(`${statusArrow("Resume")} Resume:   ${chalk.green(inv.resume)}`);
    }

    const renderer = json ? null : makeBridgeHumanRenderer({ debug: !!opts.debug });
    const result = await runBridge(
      inv,
      adapter,
      {
        onEvent: (e) => {
          if (json) emitJsonEvent({ kind: "event", event: serializeAdapterEvent(e) });
          else renderer!.onEvent(e);
        },
      },
      { abortSignal: abort.signal },
    );
    renderer?.flush();

    if (json) {
      // Same framing as the daemon: `result` is nested so a caller can decode
      // one struct for both one-shot and `serve`.
      emitJsonEvent({ kind: "result", result: result as unknown as Record<string, unknown> });
    } else {
      renderBridgeSummary(result);
    }

    process.exitCode = result.ok ? 0 : 1;
  } catch (err) {
    failCli({ json }, "bridge", (err as Error).message);
  } finally {
    process.removeListener("SIGINT", onSigint);
    authHandle?.restore();
  }
}

function renderBridgeSummary(result: {
  ok: boolean;
  action: string;
  usd: number;
  tokens: { input: number; output: number };
  durationMs: number;
  output: unknown;
  outputParseError?: string;
  missingSkills: string[];
  error?: string;
}): void {
  const color = result.ok ? chalk.green : chalk.red;
  console.log(
    color(`\n[bridge ${result.action}] ${result.ok ? "ok" : "failed"}`) +
      chalk.dim(
        ` — $${result.usd.toFixed(2)} · ${result.tokens.input}in/${result.tokens.output}out · ${(result.durationMs / 1000).toFixed(1)}s`,
      ),
  );
  if (result.missingSkills.length > 0) {
    console.log(chalk.yellow(`[bridge] skills not found (skipped): ${result.missingSkills.join(", ")}`));
  }
  if (result.error) console.log(chalk.red(`[bridge] error: ${result.error}`));
  if (result.outputParseError) {
    console.log(chalk.yellow(`[bridge] ${result.outputParseError}`));
  }
  if (result.output !== null && result.output !== undefined) {
    console.log(chalk.bold("\noutput:"));
    console.log(JSON.stringify(result.output, null, 2));
  }
}
