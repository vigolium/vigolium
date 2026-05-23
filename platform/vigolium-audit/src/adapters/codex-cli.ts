import { spawn } from "child_process";
import { open, readdir, stat } from "fs/promises";
import { homedir } from "os";
import { join } from "path";
import type { Adapter, AdapterEvent, AdapterRunInput } from "./adapter.js";
import { isTransientError } from "./claude-events.js";
import { createCodexNormalizeState, normalizeCodexEvent, normalizeCodexSessionRecord } from "./codex-events.js";
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

    const child = spawn(this.options.pathToCodexExecutable, args, {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });

    // Termination plumbing shared with the `finally` below. `abort` sends
    // SIGTERM and arms a SIGKILL escalation for a child that ignores it. The
    // `finally` removes the abort listener, always stops the session-tail
    // poller (its setInterval would otherwise leak if we leave early), and
    // force-kills the child if we exit before it did — e.g. the consumer
    // breaks out of the `for await`, or a throw unwinds through us.
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

    let sessionTail: { stop: () => void; flush: () => Promise<void> } | null = null;

    try {
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
      const extraQueue: AdapterEvent[] = [];
      const pushExtra = (evt: AdapterEvent): void => {
        extraQueue.push(evt);
        wakeup();
      };
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
        while (extraQueue.length > 0) yield extraQueue.shift()!;
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
          for (const evt of normalizeCodexEvent(event as ThreadEvent, startedAt, normalizeState)) {
            if (evt.kind === "session" && sessionTail === null) {
              sessionTail = startCodexSessionTail(evt.sessionId, normalizeState, pushExtra);
            }
            yield evt;
          }
        }
        while (extraQueue.length > 0) yield extraQueue.shift()!;
        if (done) break;
        await new Promise<void>((r) => {
          resolveNext = r;
        });
      }

      if (sessionTail) {
        await sessionTail.flush().catch(() => {});
        while (extraQueue.length > 0) yield extraQueue.shift()!;
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
    } finally {
      if (abortSignal) abortSignal.removeEventListener("abort", abort);
      // Always stop the poller — idempotent, and the setInterval leaks otherwise.
      sessionTail?.stop();
      if (childExited) {
        if (killTimer) clearTimeout(killTimer);
      } else if (!child.killed) {
        child.kill("SIGTERM");
        armHardKill();
      }
      // else: a kill is already in flight (abort path) — leave the SIGKILL
      // timer armed so a child ignoring SIGTERM is still force-killed.
    }
  }
}

function startCodexSessionTail(
  threadId: string,
  state: ReturnType<typeof createCodexNormalizeState>,
  push: (evt: AdapterEvent) => void,
): { stop: () => void; flush: () => Promise<void> } {
  let stopped = false;
  let tickPromise: Promise<void> | null = null;
  let sessionFile: string | null = null;
  let offset = 0;
  let pending = "";

  const runTick = async (): Promise<void> => {
    if (stopped) return;
    if (sessionFile === null) {
      sessionFile = await findCodexSessionFile(threadId);
      if (sessionFile === null) return;
    }
    const st = await stat(sessionFile).catch(() => null);
    if (!st) {
      sessionFile = null;
      offset = 0;
      pending = "";
      return;
    }
    if (st.size < offset) {
      offset = 0;
      pending = "";
    }
    if (st.size === offset) return;
    const length = st.size - offset;
    if (length <= 0) return;
    const buf = Buffer.allocUnsafe(length);
    const fh = await open(sessionFile, "r");
    let bytesRead = 0;
    try {
      const res = await fh.read(buf, 0, length, offset);
      bytesRead = res.bytesRead;
    } finally {
      await fh.close().catch(() => {});
    }
    if (bytesRead <= 0) return;
    const chunk = buf.subarray(0, bytesRead);
    offset += bytesRead;
    pending += chunk.toString("utf8");
    const lines = pending.split(/\r?\n/);
    pending = lines.pop() ?? "";
    for (const line of lines) {
      if (line.trim().length === 0) continue;
      let record: unknown;
      try {
        record = JSON.parse(line) as unknown;
      } catch {
        continue;
      }
      for (const evt of normalizeCodexSessionRecord(record, state)) push(evt);
    }
  };

  const tick = (): Promise<void> => {
    if (tickPromise) return tickPromise;
    tickPromise = runTick().finally(() => {
      tickPromise = null;
    });
    return tickPromise;
  };

  const timer = setInterval(() => void tick().catch(() => {}), 500);
  void tick().catch(() => {});
  return {
    flush: async () => {
      // If a polling tick is already reading while the Codex child exits, wait
      // for it and then run one more pass. The in-flight tick may have used a
      // file size captured just before Codex appended final session records.
      await tick();
      await tick();
    },
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}

async function findCodexSessionFile(threadId: string): Promise<string | null> {
  const sessionsRoot = join(process.env.CODEX_HOME ?? join(homedir(), ".codex"), "sessions");
  return findFileByNameFragment(sessionsRoot, threadId, 5);
}

async function findFileByNameFragment(dir: string, fragment: string, depth: number): Promise<string | null> {
  if (depth < 0) return null;
  let entries: import("fs").Dirent[];
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isFile() && entry.name.includes(fragment) && entry.name.endsWith(".jsonl")) return full;
  }
  // Search newest-looking directories first; Codex stores sessions as yyyy/mm/dd.
  for (const entry of [...entries].filter((e) => e.isDirectory()).sort((a, b) => b.name.localeCompare(a.name))) {
    const found = await findFileByNameFragment(join(dir, entry.name), fragment, depth - 1);
    if (found) return found;
  }
  return null;
}
