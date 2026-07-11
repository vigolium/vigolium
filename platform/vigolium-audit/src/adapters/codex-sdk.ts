import {
  Codex,
  type CodexOptions,
  type ModelReasoningEffort,
  type ThreadOptions,
} from "@openai/codex-sdk";
import type { Adapter, AdapterEvent, AdapterRunInput } from "./adapter.js";
import { isTransientError } from "./claude-events.js";
import { createCodexNormalizeState, normalizeCodexEvent } from "./codex-events.js";
import { startCodexSessionTail } from "./codex-session-tail.js";

export type CodexSdkClient = Pick<Codex, "startThread" | "resumeThread">;

export function resolveCodexClientOptions(options: CodexSdkAdapterOptions): CodexOptions {
  const apiKey = options.apiKey ?? process.env.OPENAI_API_KEY;
  return {
    ...(options.codexPathOverride && { codexPathOverride: options.codexPathOverride }),
    ...(apiKey && { apiKey }),
  };
}

export interface CodexSdkAdapterOptions {
  /** Absolute path to the `codex` binary. Falls back to SDK auto-resolve. */
  codexPathOverride?: string;
  /** API key passed to the SDK; defaults to OPENAI_API_KEY when present. */
  apiKey?: string;
  /** Default model (e.g. "gpt-5", "gpt-4.1"). */
  defaultModel?: string;
  /**
   * SandboxMode passed to every thread. Defaults to "workspace-write" so the
   * model can edit files in cwd but not escape it.
   */
  sandboxMode?: "read-only" | "workspace-write" | "danger-full-access";
  /** When true, allow the model to make network requests via Bash. */
  networkAccessEnabled?: boolean;
  /**
   * Default reasoning effort applied via `modelReasoningEffort` on every thread.
   * Codex SDK ModelReasoningEffort: "minimal" | "low" | "medium" | "high" | "xhigh".
   */
  defaultReasoningEffort?: ModelReasoningEffort;
}

/**
 * Codex SDK adapter. The Codex SDK doesn't expose a separate system-prompt
 * field, so we prepend the system prompt to the user input as a labelled
 * context block. Tools are constrained via SandboxMode rather than a name
 * allowlist (Codex sandboxes at the OS layer, not by tool registry).
 *
 * Usage cost is not exposed by the Codex SDK; we report token counts only.
 */
export class CodexSdkAdapter implements Adapter {
  readonly id = "codex-sdk";
  readonly platform = "codex" as const;
  readonly description: string;
  private readonly codex: CodexSdkClient;

  constructor(
    private readonly options: CodexSdkAdapterOptions = {},
    client?: CodexSdkClient,
  ) {
    this.description = options.codexPathOverride
      ? `Codex (SDK; binary: ${options.codexPathOverride})`
      : "Codex (SDK; bundled binary auto-resolved)";
    this.codex = client ?? new Codex(resolveCodexClientOptions(options));
  }

  async probe(): Promise<void> {
    let got = false;
    let lastError: Error | null = null;
    try {
      for await (const ev of this.run({
        systemPrompt: "Reply with exactly: pong",
        userPrompt: "ping",
        maxTurns: 1,
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
    if (!got) throw lastError ?? new Error("Codex SDK probe did not return a finish event");
  }

  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    const startedAt = Date.now();
    const cwd = input.cwd ?? process.cwd();
    const normalizeState = createCodexNormalizeState();

    // Codex bypass = approvalPolicy:'never' + sandboxMode:'danger-full-access'.
    // The CLI exposes this combo as `--dangerously-bypass-approvals-and-sandbox`;
    // the SDK has no single flag, so we set both explicitly when requested.
    // An explicit per-run `sandbox` wins over the bypass-derived default, so a
    // caller can bypass approval prompts yet still confine writes (read-only
    // triage). Falls back to the bypass default, then the constructor default.
    const sandboxMode =
      input.sandbox ??
      (input.bypassPermissions ? "danger-full-access" : (this.options.sandboxMode ?? "workspace-write"));

    // Per-run network scope wins over the constructor default.
    const networkAccessEnabled = input.networkAccessEnabled ?? this.options.networkAccessEnabled;

    const threadOptions: ThreadOptions = {
      ...(input.model || this.options.defaultModel
        ? { model: input.model ?? this.options.defaultModel! }
        : {}),
      ...(this.options.defaultReasoningEffort !== undefined && {
        modelReasoningEffort: this.options.defaultReasoningEffort,
      }),
      sandboxMode,
      workingDirectory: cwd,
      skipGitRepoCheck: true,
      ...(networkAccessEnabled !== undefined && {
        networkAccessEnabled,
      }),
      // Codex defaults to interactive approval on tool calls; in non-interactive
      // we want it to run autonomously inside the sandbox.
      approvalPolicy: "never",
    };
    const thread = input.resume
      ? this.codex.resumeThread(input.resume, threadOptions)
      : this.codex.startThread(threadOptions);

    const composedInput = composeCodexInput(input);
    const tailEvents: AdapterEvent[] = [];
    let sessionTail: ReturnType<typeof startCodexSessionTail> | null = null;

    // A resumed thread may not emit a fresh thread.started event. Prime its
    // existing session log at EOF before starting the new turn so historical
    // subagent records are not replayed as current events.
    if (input.resume) {
      sessionTail = startCodexSessionTail(
        input.resume,
        normalizeState,
        (event) => tailEvents.push(event),
        { startAtEnd: true },
      );
      await sessionTail.ready;
    }

    try {
      try {
        const turn = await thread.runStreamed(composedInput, {
          ...(input.abortSignal && { signal: input.abortSignal }),
        });
        for await (const event of turn.events) {
          for (const evt of normalizeCodexEvent(event, startedAt, normalizeState)) {
            if (evt.kind === "session" && sessionTail === null) {
              sessionTail = startCodexSessionTail(
                evt.sessionId,
                normalizeState,
                (tailEvent) => tailEvents.push(tailEvent),
              );
            }
            if (evt.kind === "finish" && sessionTail) {
              await sessionTail.flush();
              for (const tailEvent of tailEvents.splice(0)) yield tailEvent;
            }
            yield evt;
            if (evt.kind !== "finish") {
              for (const tailEvent of tailEvents.splice(0)) yield tailEvent;
            }
          }
        }
      } catch (err) {
        yield {
          kind: "error",
          cause: err instanceof Error ? err : new Error(String(err)),
          transient: isTransientError(err),
        };
      }
      if (sessionTail) await sessionTail.flush();
      for (const tailEvent of tailEvents.splice(0)) yield tailEvent;
    } finally {
      sessionTail?.stop();
    }
  }
}

function composeCodexInput(input: AdapterRunInput): string {
  return [
    "# System Instructions",
    input.systemPrompt ?? "",
    "",
    "# Task",
    input.userPrompt,
  ].join("\n");
}
