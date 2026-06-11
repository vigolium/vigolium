import type { Adapter, AdapterEvent, AdapterRunInput } from "./adapter.js";
import { isTransientError, normalizeClaudeMessage } from "./claude-events.js";
import { spawnAndStream } from "./cli-process.js";

export interface ClaudeCliAdapterOptions {
  /** Absolute path to the `claude` binary. Required. */
  pathToClaudeCodeExecutable: string;
  /** Default model passed to `claude --model`. */
  defaultModel?: string;
  /** Optional plugin dir passed to `claude --plugin-dir <path>`. */
  pluginDir?: string;
  /** Pass `--add-dir <dir>` for each entry. */
  addDirs?: string[];
}

/**
 * Drives the user's `claude` CLI in non-interactive `--print` mode with
 * `--output-format stream-json`, parsing each NDJSON line as an SDK message.
 * The wire shape matches what the SDK's `query()` yields, so we share the
 * normalization function.
 *
 * Auth: ambient. Whatever the user's `claude` is configured with — API key
 * or Claude Pro/Team/Enterprise subscription — gets used.
 */
export class ClaudeCliAdapter implements Adapter {
  readonly id = "claude-cli";
  readonly platform = "claude" as const;
  readonly description: string;

  constructor(private readonly options: ClaudeCliAdapterOptions) {
    this.description = `Claude (CLI: ${options.pathToClaudeCodeExecutable})`;
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
    if (!got) throw lastError ?? new Error("Claude CLI probe did not return a finish event");
  }

  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    const startedAt = Date.now();
    const args: string[] = [
      "--print",
      "--verbose",
      "--output-format",
      "stream-json",
      "--input-format",
      "stream-json",
    ];

    if (input.debug) args.push("--debug");

    // Only override the system prompt when the caller actually supplies one.
    // Slash-command resolution and plugin-loaded skills/agents require the
    // Claude Code default preset — passing `--system-prompt ""` would replace
    // it and break the handoff flow.
    if (typeof input.systemPrompt === "string" && input.systemPrompt.length > 0) {
      args.push("--system-prompt", input.systemPrompt);
    }

    if (input.tools !== undefined) {
      // Empty array → explicitly allow nothing. Non-empty → comma list.
      if (input.tools.length > 0) {
        args.push("--allowed-tools", input.tools.join(","));
      } else {
        args.push("--allowed-tools", "");
      }
    }

    if (input.disallowedTools && input.disallowedTools.length > 0) {
      args.push("--disallowed-tools", input.disallowedTools.join(","));
    }

    const model = input.model ?? this.options.defaultModel;
    if (model) args.push("--model", model);

    if (input.maxTurns !== undefined) {
      args.push("--max-turns", String(input.maxTurns));
    }

    const pluginDir = input.pluginDir ?? this.options.pluginDir;
    if (pluginDir) {
      args.push("--plugin-dir", pluginDir);
    }

    if (input.bypassPermissions) {
      args.push("--dangerously-skip-permissions");
    }

    for (const dir of this.options.addDirs ?? []) {
      args.push("--add-dir", dir);
    }

    const cwd = input.cwd ?? process.cwd();

    // Send the user prompt as a single stream-json user message.
    const userMessage = {
      type: "user",
      message: { role: "user", content: input.userPrompt },
      session_id: "",
      parent_tool_use_id: null,
    };

    const { stream } = spawnAndStream({
      command: this.options.pathToClaudeCodeExecutable,
      args,
      cwd,
      stdin: JSON.stringify(userMessage) + "\n",
      ...(input.debug !== undefined ? { debug: input.debug } : {}),
      ...(input.abortSignal !== undefined ? { abortSignal: input.abortSignal } : {}),
    });

    for await (const item of stream) {
      if (item.kind === "line") {
        let message: unknown;
        try {
          message = JSON.parse(item.line);
        } catch {
          // Non-JSON line; surface as a text delta so it's visible.
          yield { kind: "textDelta", text: item.line + "\n" };
          continue;
        }
        for (const evt of normalizeClaudeMessage(message, startedAt)) yield evt;
      } else if (item.kind === "exit") {
        if (item.crashed) {
          yield { kind: "error", cause: item.crashed, transient: isTransientError(item.crashed) };
        } else if (item.exitCode !== null && item.exitCode !== 0) {
          const cause = new Error(
            `claude CLI exited ${item.exitCode}${item.stderr ? `: ${item.stderr.slice(0, 500)}` : ""}`,
          );
          yield { kind: "error", cause, transient: isTransientError(cause) };
        }
      }
    }
  }
}
