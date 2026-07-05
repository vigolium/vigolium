import type { Adapter, AdapterEvent, AdapterRunInput } from "../adapters/adapter.js";
import { ClaudeSdkAdapter } from "../adapters/claude-sdk.js";
import { CodexSdkAdapter } from "../adapters/codex-sdk.js";
import { chooseAdapter, type ResolvedAdapterChoice } from "../adapters/detect.js";
import { applyAuthOverrides, type AuthOverrideHandle } from "./auth-overrides.js";
import { buildBridgePlugin } from "./bridge-plugin.js";
import { loadBridgeTask } from "./bridge-tasks.js";
import type { AgentPlatform } from "./types.js";

/**
 * The bridge engine: a single, headless SDK-driven agent invocation that the Go
 * `vigolium` binary (or any caller) uses to triage a finding, develop an
 * exploit, or plan an attack. Shared by the one-shot `bridge` command and the
 * long-lived `bridge serve` daemon.
 *
 * It deliberately does NOT go through the orchestrator / phase graph — there is
 * no state store, no findings watcher. It resolves a task preset, assembles an
 * ephemeral plugin (always including `vigolium-scanner`), builds an SDK adapter,
 * runs one turn-loop, and returns a structured result.
 */

/** Task name that means "no preset — run the caller's raw prompt". */
export const GENERIC_ACTION = "run";

/**
 * Whether the platform loads bridge skills. Only Claude has the plugin
 * mechanism the bridge uses; codex runs without them — the single source of
 * truth for both the plugin build (runBridge) and the preamble wording.
 */
export function skillsSupported(platform: AgentPlatform): boolean {
  return platform === "claude";
}

/**
 * Preamble prepended to every bridge system prompt. The scanner-skill line is
 * only stated when skills actually load; codex gets a plain "prefer the vigolium
 * CLI" instruction instead, so the prompt never references a Skill tool the
 * runtime doesn't have.
 */
function basePreamble(skillsLoaded: boolean): string {
  const cliLine = skillsLoaded
    ? "- The `vigolium-scanner` skill is loaded. Consult it (via the Skill tool) whenever you need the correct `vigolium` CLI command or flags, and prefer vigolium's first-class commands over ad-hoc curl/wget."
    : "- Prefer vigolium's first-class CLI commands (`vigolium scan`, `scan-request`, `finding`, `traffic`, `oast`) over ad-hoc curl/wget.";
  return `You are running as an automated sidecar of the Vigolium security scanner, driving a coding agent through the Agent SDK on behalf of an operator conducting an AUTHORIZED security assessment of a target they own or are contracted to test.

- The working directory is the target under assessment; file and command access there is in scope.
${cliLine}
- \`vigolium finding\` and \`vigolium traffic\` emit compact, token-aware output under \`--json --compact\` (bodies bounded, evidence windowed) — survey many records cheaply, then deep-read only the ones worth it with \`--with-records\` / \`--markdown\`.
- You are headless: never ask the operator a question. Make a well-reasoned decision, state your assumptions, and act.
- Be concise and evidence-driven.`;
}

export interface BridgeOptions {
  /** Task preset name (triage/exploit/plan/...) or `run` for a raw prompt. */
  action: string;
  platform: AgentPlatform;
  /** Working directory = the target the agent operates on. */
  cwd: string;
  /** User instruction text (from --prompt / --prompt-file / stdin). */
  prompt?: string;
  /** Structured input context, e.g. a finding JSON blob (from --input-file). */
  input?: string;
  /** Explicit system-prompt override (only honored for the `run` action). */
  systemPrompt?: string;
  /** Extra skills to load on top of the task's defaults. */
  skills?: string[];
  /** Tool allow-list override; empty/undefined = runtime default (all tools). */
  tools?: string[];
  /** Extra tools to deny (AskUserQuestion is always denied). */
  disallowedTools?: string[];
  model?: string;
  maxTurns?: number;
  /** Session id to resume (from a prior run's `session` event). */
  resume?: string;
  /** Override the task's output mode. */
  output?: "json" | "text";
  /** Defaults to true — the agent needs to run tools without prompts. */
  bypassPermissions?: boolean;
}

export interface BridgeInvocation {
  action: string;
  platform: AgentPlatform;
  cwd: string;
  userPrompt: string;
  systemPrompt: string;
  skills: string[];
  tools: string[];
  disallowedTools: string[];
  model?: string;
  maxTurns?: number;
  resume?: string;
  bypassPermissions: boolean;
  output: "json" | "text";
}

export interface BridgeRunResult {
  ok: boolean;
  action: string;
  platform: AgentPlatform;
  sessionId: string | null;
  model: string | null;
  usd: number;
  tokens: { input: number; output: number };
  durationMs: number;
  /** Parsed JSON from the final message when output === "json", else null. */
  output: unknown | null;
  /** The agent's final message text, verbatim. */
  outputRaw: string;
  /** Set when output === "json" but no valid JSON block was found. */
  outputParseError?: string;
  loadedSkills: string[];
  missingSkills: string[];
  error?: string;
}

/** Compose the fully-resolved invocation by merging a task preset with options. */
export async function resolveBridgeInvocation(opts: BridgeOptions): Promise<BridgeInvocation> {
  // Model generic ("run") as a preset with no content so both paths share one
  // resolution body: `run` supplies its skills/tools/output from the caller,
  // presets supply theirs from frontmatter.
  const task =
    opts.action === GENERIC_ACTION
      ? {
          skills: [] as string[],
          tools: [] as string[],
          model: undefined as string | undefined,
          output: "text" as const,
          systemPrompt: opts.systemPrompt ?? "",
          outputSchema: undefined as string | undefined,
        }
      : await loadBridgeTask(opts.action);

  const output = opts.output ?? task.output;
  const model = opts.model ?? task.model;
  const skills = [...new Set([...task.skills, ...(opts.skills ?? [])])].sort();
  const tools = opts.tools ?? task.tools;

  const preamble = basePreamble(skillsSupported(opts.platform));
  let systemPrompt = task.systemPrompt ? `${preamble}\n\n${task.systemPrompt}` : preamble;
  if (output === "json") {
    systemPrompt += task.outputSchema
      ? `\n\n## Required output schema\n\`\`\`\n${task.outputSchema.trim()}\n\`\`\``
      : `\n\nEnd your reply with a single fenced \`\`\`json block containing your structured result, and nothing after it.`;
  }

  const userPrompt = composeUserPrompt(opts.prompt, opts.input);
  if (userPrompt.trim().length === 0) {
    throw new Error("bridge: no prompt or input provided (pass --prompt, --prompt-file, --input-file, or pipe stdin)");
  }

  // AskUserQuestion always deadlocks a headless run — deny it unconditionally.
  const disallowedTools = [...new Set(["AskUserQuestion", ...(opts.disallowedTools ?? [])])];

  return {
    action: opts.action,
    platform: opts.platform,
    cwd: opts.cwd,
    userPrompt,
    systemPrompt,
    skills,
    tools,
    disallowedTools,
    ...(model !== undefined ? { model } : {}),
    ...(opts.maxTurns !== undefined ? { maxTurns: opts.maxTurns } : {}),
    ...(opts.resume !== undefined ? { resume: opts.resume } : {}),
    bypassPermissions: opts.bypassPermissions ?? true,
    output,
  };
}

function composeUserPrompt(prompt: string | undefined, input: string | undefined): string {
  const parts: string[] = [];
  if (input && input.trim().length > 0) {
    parts.push(`# Task input\n${input.trim()}`);
  }
  if (prompt && prompt.trim().length > 0) {
    parts.push(prompt.trim());
  }
  return parts.join("\n\n");
}

export interface BridgeAdapter {
  adapter: Adapter;
  choice: ResolvedAdapterChoice;
}

// Binary probe (spawns `which`) depends only on platform and can't change over
// the process lifetime — cache it so the daemon doesn't re-probe per request.
const adapterChoiceCache = new Map<AgentPlatform, ResolvedAdapterChoice>();
function cachedChoice(platform: AgentPlatform): ResolvedAdapterChoice {
  let choice = adapterChoiceCache.get(platform);
  if (!choice) {
    choice = chooseAdapter(platform);
    adapterChoiceCache.set(platform, choice);
  }
  return choice;
}

/**
 * Build the SDK adapter for the bridge. Unlike `run`, the bridge ALWAYS uses
 * the SDK flavor (never the print-mode CLI) — loading plugin skills and driving
 * the harness headlessly is the whole point. `chooseAdapter` is still used to
 * locate the binary and report the auth source.
 */
export function buildBridgeAdapter(platform: AgentPlatform, model?: string): BridgeAdapter {
  const choice = cachedChoice(platform);
  const modelSpread = model ? { defaultModel: model } : {};
  if (platform === "claude") {
    if (!choice.binaryPath) {
      throw new Error(
        "no `claude` binary found. Install via `npm i -g @anthropic-ai/claude-code`, or set VIGOLIUM_AUDIT_CLAUDE_PATH.",
      );
    }
    return {
      adapter: new ClaudeSdkAdapter({ pathToClaudeCodeExecutable: choice.binaryPath, ...modelSpread }),
      choice,
    };
  }
  return {
    adapter: new CodexSdkAdapter({
      ...(choice.binaryPath ? { codexPathOverride: choice.binaryPath } : {}),
      ...modelSpread,
    }),
    choice,
  };
}

/**
 * The common fields both entrypoints announce after resolving a run (the CLI's
 * `ready` line and the daemon's `accepted` line spread this).
 */
export function describeInvocation(
  inv: BridgeInvocation,
  choice: ResolvedAdapterChoice,
): Record<string, unknown> {
  return {
    action: inv.action,
    platform: inv.platform,
    model: inv.model ?? null,
    output: inv.output,
    skills: inv.skills,
    authSource: choice.authSource,
  };
}

/** Auth override inputs shared by the one-shot and daemon entrypoints. */
export interface BridgeAuthOptions {
  platform: AgentPlatform;
  apiKey?: string;
  oauthToken?: string;
  oauthCredFile?: string;
}

/**
 * Apply per-run auth overrides if any were supplied, else return undefined.
 * Restoration is the caller's job (one-shot restores on exit; the daemon holds
 * the launch identity for its lifetime and relies on the internal exit hook).
 */
export function applyBridgeAuth(opts: BridgeAuthOptions): AuthOverrideHandle | undefined {
  if (!opts.apiKey && !opts.oauthToken && !opts.oauthCredFile) return undefined;
  return applyAuthOverrides({
    platform: opts.platform,
    ...(opts.oauthToken !== undefined ? { oauthToken: opts.oauthToken } : {}),
    ...(opts.oauthCredFile !== undefined ? { oauthCredFile: opts.oauthCredFile } : {}),
    ...(opts.apiKey !== undefined ? { apiKey: opts.apiKey } : {}),
  });
}

export interface BridgeRunHandlers {
  /** Called for every normalized adapter event, in order. */
  onEvent?: (event: AdapterEvent) => void;
}

/**
 * Execute a resolved invocation against an adapter and return a structured
 * result. Streams every adapter event through `handlers.onEvent` so the CLI
 * renderer and the daemon can surface progress live.
 */
export async function runBridge(
  inv: BridgeInvocation,
  adapter: Adapter,
  handlers: BridgeRunHandlers = {},
  opts: { abortSignal?: AbortSignal } = {},
): Promise<BridgeRunResult> {
  // Codex has no plugin mechanism; skills only load for the Claude SDK path.
  // On an unsupported platform we report the requested skills as skipped so the
  // caller sees the degradation rather than a silent no-op.
  let pluginDir: string | undefined;
  let loadedSkills: string[] = [];
  let missingSkills: string[] = inv.skills;
  if (skillsSupported(inv.platform)) {
    const plugin = await buildBridgePlugin(inv.skills);
    pluginDir = plugin.dir;
    loadedSkills = plugin.loadedSkills;
    missingSkills = plugin.missing;
  }

  const runInput: AdapterRunInput = {
    systemPrompt: inv.systemPrompt,
    userPrompt: inv.userPrompt,
    cwd: inv.cwd,
    bypassPermissions: inv.bypassPermissions,
    ...(inv.tools.length > 0 ? { tools: inv.tools } : {}),
    ...(inv.disallowedTools.length > 0 ? { disallowedTools: inv.disallowedTools } : {}),
    ...(inv.model !== undefined ? { model: inv.model } : {}),
    ...(inv.maxTurns !== undefined ? { maxTurns: inv.maxTurns } : {}),
    ...(inv.resume !== undefined ? { resume: inv.resume } : {}),
    ...(pluginDir ? { pluginDir } : {}),
    ...(opts.abortSignal ? { abortSignal: opts.abortSignal } : {}),
    label: inv.action,
  };

  const result: BridgeRunResult = {
    ok: false,
    action: inv.action,
    platform: inv.platform,
    sessionId: null,
    model: inv.model ?? null,
    usd: 0,
    tokens: { input: 0, output: 0 },
    durationMs: 0,
    output: null,
    outputRaw: "",
    loadedSkills,
    missingSkills,
  };

  let accumulatedText = "";
  let finishText = "";

  for await (const event of adapter.run(runInput)) {
    handlers.onEvent?.(event);
    switch (event.kind) {
      case "session":
        result.sessionId = event.sessionId;
        if (event.model) result.model = event.model;
        break;
      case "textDelta":
        accumulatedText += event.text;
        break;
      case "finish":
        result.usd = event.usd;
        result.tokens = event.tokens;
        result.durationMs = event.durationMs;
        if (event.ok) {
          result.ok = true;
          finishText = event.result;
        } else {
          result.error = event.reason;
        }
        break;
      case "error":
        result.error = event.cause.message;
        break;
      default:
        break;
    }
  }

  result.outputRaw = finishText.trim().length > 0 ? finishText : accumulatedText;

  if (inv.output === "json") {
    const parsed = extractJsonBlock(result.outputRaw);
    if ("value" in parsed) result.output = parsed.value;
    else result.outputParseError = parsed.error;
  }

  return result;
}

/**
 * Pull a JSON object out of an agent's final message. Prefers the last fenced
 * ```json block; falls back to the last generic fenced block that parses, then
 * to the whole trimmed message. Returns the parsed value or a describing error.
 */
export function extractJsonBlock(text: string): { value: unknown } | { error: string } {
  const fenceRe = /```(\w+)?\s*\n([\s\S]*?)```/g;
  let lastJson: string | undefined;
  let lastOther: string | undefined;
  let m: RegExpExecArray | null;
  while ((m = fenceRe.exec(text)) !== null) {
    const body = (m[2] ?? "").trim();
    if ((m[1] ?? "").toLowerCase() === "json") lastJson = body;
    else lastOther = body;
  }
  // Prefer the last json fence, then the last generic fence, then the whole message.
  const candidates = [lastJson, lastOther, text.trim()].filter((c): c is string => c !== undefined);
  for (const c of candidates) {
    try {
      return { value: JSON.parse(c) };
    } catch {
      /* try next candidate */
    }
  }
  return { error: "no valid JSON block found in the agent's final message" };
}
