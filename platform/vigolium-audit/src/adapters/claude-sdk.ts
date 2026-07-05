import { query } from "@anthropic-ai/claude-agent-sdk";
import type { Adapter, AdapterEvent, AdapterRunInput } from "./adapter.js";
import { isTransientError, normalizeClaudeMessage } from "./claude-events.js";

export interface ClaudeSdkAdapterOptions {
  /**
   * Absolute path to the `claude` CLI binary. When omitted, the SDK falls back
   * to its bundled @anthropic-ai/claude-agent-sdk-<platform> dep — that path
   * does not survive `bun build --compile`, so callers should resolve and pass
   * an explicit path in production builds.
   */
  pathToClaudeCodeExecutable?: string;
  /** Default model when AdapterRunInput.model is unset. */
  defaultModel?: string;
}

export class ClaudeSdkAdapter implements Adapter {
  readonly id = "claude-sdk";
  readonly platform = "claude" as const;
  readonly description: string;

  constructor(private readonly options: ClaudeSdkAdapterOptions = {}) {
    this.description = options.pathToClaudeCodeExecutable
      ? `Claude (Agent SDK; binary: ${options.pathToClaudeCodeExecutable})`
      : "Claude (Agent SDK; bundled binary auto-resolved)";
  }

  async probe(): Promise<void> {
    let got = false;
    let lastError: Error | null = null;
    try {
      for await (const ev of this.run({
        systemPrompt: "Reply with exactly: pong",
        userPrompt: "ping",
        maxTurns: 1,
        tools: [],
      })) {
        if (ev.kind === "finish") {
          got = ev.ok;
          if (!ev.ok) lastError = new Error(`probe finished non-ok: ${ev.reason}`);
          break;
        }
        if (ev.kind === "error") {
          lastError = ev.cause;
          break;
        }
      }
    } catch (err) {
      lastError = err as Error;
    }
    if (!got) {
      throw lastError ?? new Error("Claude SDK probe did not return a finish event");
    }
  }

  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    const startedAt = Date.now();
    // When the caller doesn't supply a custom systemPrompt, fall back to the
    // Claude Code preset — slash-command resolution and plugin-provided
    // skills/agents are wired into that preset and require it to be active.
    type QueryOptions = NonNullable<Parameters<typeof query>[0]["options"]>;
    const systemPrompt: QueryOptions["systemPrompt"] =
      typeof input.systemPrompt === "string" && input.systemPrompt.length > 0
        ? input.systemPrompt
        : { type: "preset", preset: "claude_code" };
    const sdkOptions: QueryOptions = {
      systemPrompt,
      cwd: input.cwd ?? process.cwd(),
      ...(input.maxTurns !== undefined && { maxTurns: input.maxTurns }),
      ...(input.tools && input.tools.length > 0 && { allowedTools: input.tools }),
      ...(input.tools && input.tools.length === 0 && { allowedTools: [] }),
      ...(input.disallowedTools && input.disallowedTools.length > 0 && {
        disallowedTools: input.disallowedTools,
      }),
      ...(input.model || this.options.defaultModel
        ? { model: input.model ?? this.options.defaultModel! }
        : {}),
      ...(this.options.pathToClaudeCodeExecutable && {
        pathToClaudeCodeExecutable: this.options.pathToClaudeCodeExecutable,
      }),
      ...(input.pluginDir && {
        plugins: [{ type: "local", path: input.pluginDir }],
      }),
      ...(input.resume ? { resume: input.resume } : {}),
      ...(input.bypassPermissions && {
        permissionMode: "bypassPermissions",
        allowDangerouslySkipPermissions: true,
      }),
      ...(input.abortSignal && { abortController: makeAbortController(input.abortSignal) }),
    };

    try {
      for await (const message of query({ prompt: input.userPrompt, options: sdkOptions })) {
        for (const evt of normalizeClaudeMessage(message, startedAt)) yield evt;
      }
    } catch (err) {
      yield {
        kind: "error",
        cause: err instanceof Error ? err : new Error(String(err)),
        transient: isTransientError(err),
      };
    }
  }
}

function makeAbortController(signal: AbortSignal): AbortController {
  const controller = new AbortController();
  if (signal.aborted) controller.abort(signal.reason);
  else signal.addEventListener("abort", () => controller.abort(signal.reason), { once: true });
  return controller;
}
