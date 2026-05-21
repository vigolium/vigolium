import { spawn } from "child_process";
import type { Adapter, AdapterEvent, AdapterRunInput } from "./adapter.js";
import { isTransientError } from "./claude-events.js";
import { normalizeCodexEvent } from "./codex-events.js";
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

    const child = spawn(this.options.pathToCodexExecutable, args, {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });

    if (input.abortSignal) {
      const abort = (): void => {
        if (!child.killed) child.kill("SIGTERM");
      };
      if (input.abortSignal.aborted) abort();
      else input.abortSignal.addEventListener("abort", abort, { once: true });
    }

    const composedInput = `# System Instructions\n${input.systemPrompt ?? ""}\n\n# Task\n${input.userPrompt}\n`;
    child.stdin?.write(composedInput);
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
      wakeup();
    });
    child.on("close", (code) => {
      exitCode = code;
      done = true;
      wakeup();
    });

    while (true) {
      while (lineQueue.length > 0) {
        const line = lineQueue.shift()!;
        let event: unknown;
        try {
          event = JSON.parse(line);
        } catch {
          yield { kind: "textDelta", text: line + "\n" };
          continue;
        }
        if (!event || typeof event !== "object") continue;
        for (const evt of normalizeCodexEvent(event as ThreadEvent, startedAt)) yield evt;
      }
      if (done) break;
      await new Promise<void>((r) => {
        resolveNext = r;
      });
    }

    if (crashed) {
      yield { kind: "error", cause: crashed, transient: isTransientError(crashed) };
      return;
    }
    if (exitCode !== null && exitCode !== 0) {
      const stderr = errBuf.join("").trim();
      yield {
        kind: "error",
        cause: new Error(`codex CLI exited ${exitCode}${stderr ? `: ${stderr.slice(0, 500)}` : ""}`),
      };
    }
  }
}

