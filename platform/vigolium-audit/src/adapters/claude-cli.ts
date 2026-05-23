import { spawn } from "child_process";
import type { Adapter, AdapterEvent, AdapterRunInput } from "./adapter.js";
import { isTransientError, normalizeClaudeMessage } from "./claude-events.js";

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

    const child = spawn(this.options.pathToClaudeCodeExecutable, args, {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });

    // Termination plumbing shared with the `finally` below. `abort` sends
    // SIGTERM and arms a SIGKILL escalation so a child that ignores SIGTERM
    // (hung, trapping the signal) still dies. The `finally` removes the abort
    // listener (it lives on a potentially long-lived signal) and force-kills
    // the child if we leave before it exited — e.g. the consumer breaks out of
    // the `for await` early, or a throw unwinds through us.
    const abortSignal = input.abortSignal;
    let childExited = false;
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    const armHardKill = (): void => {
      if (killTimer) return;
      killTimer = setTimeout(() => {
        if (!child.killed) child.kill("SIGKILL");
      }, 5000);
      killTimer.unref?.();
    };
    const abort = (): void => {
      if (!child.killed) child.kill("SIGTERM");
      armHardKill();
    };
    if (abortSignal) {
      if (abortSignal.aborted) abort();
      else abortSignal.addEventListener("abort", abort, { once: true });
    }

    try {
      // Send the user prompt as a single stream-json user message, then close stdin.
      const userMessage = {
        type: "user",
        message: { role: "user", content: input.userPrompt },
        session_id: "",
        parent_tool_use_id: null,
      };
      child.stdin?.write(JSON.stringify(userMessage) + "\n");
      child.stdin?.end();

      const errBuf: string[] = [];
      child.stderr?.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        errBuf.push(text);
        if (input.debug) process.stderr.write(text);
      });

      let pending = "";
      let crashed: Error | null = null;
      const lineQueue: string[] = [];
      let resolveNext: ((v: void) => void) | null = null;
      const wakeup = (): void => {
        if (resolveNext) {
          const r = resolveNext;
          resolveNext = null;
          r();
        }
      };

      let done = false;
      let exitCode: number | null = null;

      child.stdout?.on("data", (chunk: Buffer) => {
        pending += chunk.toString("utf8");
        let nl: number;
        while ((nl = pending.indexOf("\n")) >= 0) {
          const line = pending.slice(0, nl);
          pending = pending.slice(nl + 1);
          if (line.trim().length > 0) lineQueue.push(line);
        }
        wakeup();
      });
      child.stdout?.on("end", () => {
        if (pending.trim().length > 0) lineQueue.push(pending);
        pending = "";
        wakeup();
      });
      child.on("error", (err) => {
        crashed = err;
        done = true;
        childExited = true;
        wakeup();
      });
      child.on("close", (code) => {
        exitCode = code;
        done = true;
        childExited = true;
        wakeup();
      });

      while (true) {
        while (lineQueue.length > 0) {
          const line = lineQueue.shift()!;
          let message: unknown;
          try {
            message = JSON.parse(line);
          } catch {
            // Non-JSON line; surface as a text delta so it's visible.
            yield { kind: "textDelta", text: line + "\n" };
            continue;
          }
          for (const evt of normalizeClaudeMessage(message, startedAt)) yield evt;
        }
        if (done) break;
        await new Promise<void>((r) => {
          resolveNext = r;
        });
      }

      if (crashed) {
        yield {
          kind: "error",
          cause: crashed,
          transient: isTransientError(crashed),
        };
        return;
      }
      if (exitCode !== null && exitCode !== 0) {
        const stderr = errBuf.join("").trim();
        const cause = new Error(`claude CLI exited ${exitCode}${stderr ? `: ${stderr.slice(0, 500)}` : ""}`);
        yield {
          kind: "error",
          cause,
          transient: isTransientError(cause),
        };
      }
    } finally {
      if (abortSignal) abortSignal.removeEventListener("abort", abort);
      if (childExited) {
        if (killTimer) clearTimeout(killTimer);
      } else if (!child.killed) {
        // Left before the child exited (early break by the consumer, or a
        // throw): terminate it instead of orphaning the process.
        child.kill("SIGTERM");
        armHardKill();
      }
      // else: a kill is already in flight (abort path) — leave the SIGKILL
      // timer armed so a child ignoring SIGTERM is still force-killed.
    }
  }
}
