import type { Adapter, AdapterEvent, AdapterRunInput } from "./adapter.js";
import { isTransientError } from "./claude-events.js";
import { spawnAndStream } from "./cli-process.js";
import { createCodexNormalizeState, normalizeCodexEvent } from "./codex-events.js";
import { startCodexSessionTail } from "./codex-session-tail.js";
import type { ThreadEvent } from "@openai/codex-sdk";

export interface CodexCliAdapterOptions {
  /** Absolute path to the `codex` binary. Required. */
  pathToCodexExecutable: string;
  /** Default model passed to `codex exec --model`. */
  defaultModel?: string;
  /** Sandbox mode passed to `codex exec --sandbox`. Default: workspace-write. */
  sandboxMode?: "read-only" | "workspace-write" | "danger-full-access";
  /**
   * Default reasoning effort passed to `codex exec -c model_reasoning_effort=<effort>`.
   * Applied when no per-call override is supplied.
   */
  defaultReasoningEffort?: "minimal" | "low" | "medium" | "high" | "xhigh";
}

/**
 * Drives `codex exec --json` and parses the JSONL output into AdapterEvents.
 * The wire format is the same ThreadEvent union the codex-sdk exposes, so we
 * share the normalization logic.
 */
export class CodexCliAdapter implements Adapter {
  readonly id = "codex-cli";
  readonly platform = "codex" as const;
  readonly description: string;

  constructor(private readonly options: CodexCliAdapterOptions) {
    this.description = `Codex (CLI: ${options.pathToCodexExecutable})`;
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
    if (!got) throw lastError ?? new Error("Codex CLI probe did not return a finish event");
  }

  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    const startedAt = Date.now();
    const cwd = input.cwd ?? process.cwd();
    const normalizeState = createCodexNormalizeState();

    const args = ["exec", "--json", "--skip-git-repo-check"];

    // Bypass takes precedence over the sandbox option — the codex flag implies
    // approval=never and sandbox=danger-full-access in one go, and is mutually
    // exclusive with passing `--sandbox` explicitly. Without bypass we fall
    // back to the configured sandbox mode (default: workspace-write).
    if (input.bypassPermissions) {
      args.push("--dangerously-bypass-approvals-and-sandbox");
    } else {
      args.push("--sandbox", this.options.sandboxMode ?? "workspace-write");
    }

    if (input.debug) args.push("--debug");

    const model = input.model ?? this.options.defaultModel;
    if (model) args.push("--model", model);

    const reasoning = this.options.defaultReasoningEffort;
    if (reasoning) args.push("-c", `model_reasoning_effort="${reasoning}"`);

    // Codex reads the prompt from stdin when "-" is passed as the prompt arg.
    args.push("-");

    const composedInput = `# System Instructions\n${input.systemPrompt ?? ""}\n\n# Task\n${input.userPrompt}\n`;

    // The session-tail poller is created lazily once we see the session event,
    // and stopped in the `finally`. The `onBeforeExit` hook reads this closure
    // variable so trailing session records are flushed before the exit item.
    let sessionTail: { stop: () => void; flush: () => Promise<void> } | null = null;

    const { stream, inject } = spawnAndStream<AdapterEvent>({
      command: this.options.pathToCodexExecutable,
      args,
      cwd,
      stdin: composedInput,
      onBeforeExit: async () => {
        if (sessionTail) await sessionTail.flush();
      },
      ...(input.debug !== undefined ? { debug: input.debug } : {}),
      ...(input.abortSignal !== undefined ? { abortSignal: input.abortSignal } : {}),
    });

    try {
      for await (const item of stream) {
        if (item.kind === "extra") {
          yield item.value;
        } else if (item.kind === "line") {
          let event: unknown;
          try {
            event = JSON.parse(item.line);
          } catch {
            yield { kind: "textDelta", text: item.line + "\n" };
            continue;
          }
          if (!event || typeof event !== "object") continue;
          for (const evt of normalizeCodexEvent(event as ThreadEvent, startedAt, normalizeState)) {
            if (evt.kind === "session" && sessionTail === null) {
              sessionTail = startCodexSessionTail(evt.sessionId, normalizeState, inject);
            }
            yield evt;
          }
        } else if (item.kind === "exit") {
          if (item.crashed) {
            yield { kind: "error", cause: item.crashed, transient: isTransientError(item.crashed) };
          } else if (item.exitCode !== null && item.exitCode !== 0) {
            const cause = new Error(
              `codex CLI exited ${item.exitCode}${item.stderr ? `: ${item.stderr.slice(0, 500)}` : ""}`,
            );
            yield { kind: "error", cause, transient: isTransientError(cause) };
          }
        }
      }
    } finally {
      // Always stop the poller — idempotent, and the setInterval leaks otherwise.
      sessionTail?.stop();
    }
  }
}
