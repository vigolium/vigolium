import { spawn } from "child_process";

/**
 * Shared process plumbing for the two CLI adapters (`claude-cli`, `codex-cli`).
 * Both spawn a child in line-oriented JSON mode, buffer stdout into NDJSON
 * lines, accumulate stderr, and tear the child down on abort / early break.
 * The only per-adapter differences are how each line is parsed and how stdin
 * is composed — those stay in the adapters; everything mechanical lives here.
 *
 * The stream yields a discriminated union so the caller can pattern-match:
 *   - `line`  — one non-empty stdout line, ready to JSON.parse
 *   - `extra` — a side-channel item injected via `inject()` (e.g. the codex
 *               session-file tail), interleaved with `line` items in order
 *   - `exit`  — terminal item carrying the child's exit code / crash / stderr
 */
export type CliStreamItem<T> =
  | { kind: "line"; line: string }
  | { kind: "extra"; value: T }
  | { kind: "exit"; exitCode: number | null; crashed: Error | null; stderr: string };

export interface SpawnAndStreamOptions<T> {
  command: string;
  args: string[];
  cwd: string;
  /** Written to the child's stdin in one shot; stdin is then closed. */
  stdin: string;
  /** Forward child stderr to the parent stderr live. */
  debug?: boolean;
  /** Externally-driven abort — sends SIGTERM, escalates to SIGKILL after 5s. */
  abortSignal?: AbortSignal;
  /**
   * Runs after the child closes but before the terminal `exit` item, letting a
   * caller flush trailing side-channel events (e.g. a final read of a session
   * file). Items injected during the hook are emitted before `exit`. Errors
   * thrown here are swallowed — the hook is best-effort cleanup.
   */
  onBeforeExit?: () => Promise<void> | void;
}

export interface CliStream<T> {
  stream: AsyncGenerator<CliStreamItem<T>>;
  /** Inject a side-channel item to be interleaved into the stream in order. */
  inject: (value: T) => void;
}

// Backpressure thresholds: pause stdout once this many lines are buffered,
// resume once the buffer drains below the low mark. Guards against unbounded
// memory growth when the consumer is slower than the child's output.
const HIGH_WATER_MARK = 5000;
const LOW_WATER_MARK = HIGH_WATER_MARK / 2;

export function spawnAndStream<T = never>(opts: SpawnAndStreamOptions<T>): CliStream<T> {
  const child = spawn(opts.command, opts.args, {
    cwd: opts.cwd,
    stdio: ["pipe", "pipe", "pipe"],
    env: process.env,
  });

  // Termination plumbing shared with the `finally` in the generator. `abort`
  // sends SIGTERM and arms a SIGKILL escalation so a child that ignores SIGTERM
  // (hung, trapping the signal) still dies. The `finally` removes the abort
  // listener (it lives on a potentially long-lived signal) and force-kills the
  // child if we leave before it exited — e.g. the consumer breaks out of the
  // `for await` early, or a throw unwinds through us.
  const abortSignal = opts.abortSignal;
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

  const lineQueue: string[] = [];
  const extraQueue: T[] = [];
  const errBuf: string[] = [];
  let pending = "";
  let crashed: Error | null = null;
  let done = false;
  let exitCode: number | null = null;
  let paused = false;

  let resolveNext: ((v: void) => void) | null = null;
  const wakeup = (): void => {
    if (resolveNext) {
      const r = resolveNext;
      resolveNext = null;
      r();
    }
  };

  const maybePause = (): void => {
    if (!paused && lineQueue.length >= HIGH_WATER_MARK) {
      paused = true;
      child.stdout?.pause?.();
    }
  };
  const maybeResume = (): void => {
    if (paused && lineQueue.length <= LOW_WATER_MARK) {
      paused = false;
      child.stdout?.resume?.();
    }
  };

  child.stderr?.on("data", (chunk: Buffer) => {
    const text = chunk.toString("utf8");
    errBuf.push(text);
    if (opts.debug) process.stderr.write(text);
  });
  child.stdout?.on("data", (chunk: Buffer) => {
    pending += chunk.toString("utf8");
    let nl: number;
    while ((nl = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, nl);
      pending = pending.slice(nl + 1);
      if (line.trim().length > 0) lineQueue.push(line);
    }
    maybePause();
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

  const inject = (value: T): void => {
    extraQueue.push(value);
    wakeup();
  };

  async function* stream(): AsyncGenerator<CliStreamItem<T>> {
    try {
      child.stdin?.write(opts.stdin);
      child.stdin?.end();

      while (true) {
        while (extraQueue.length > 0) yield { kind: "extra", value: extraQueue.shift()! };
        while (lineQueue.length > 0) {
          yield { kind: "line", line: lineQueue.shift()! };
          maybeResume();
        }
        while (extraQueue.length > 0) yield { kind: "extra", value: extraQueue.shift()! };
        if (done) break;
        await new Promise<void>((r) => {
          resolveNext = r;
        });
      }

      // Belt-and-suspenders: drain anything that landed alongside `close`.
      while (lineQueue.length > 0) {
        yield { kind: "line", line: lineQueue.shift()! };
        maybeResume();
      }

      if (opts.onBeforeExit) {
        try {
          await opts.onBeforeExit();
        } catch {
          // best-effort flush; never block the exit on it.
        }
        while (extraQueue.length > 0) yield { kind: "extra", value: extraQueue.shift()! };
      }

      yield { kind: "exit", exitCode, crashed, stderr: errBuf.join("").trim() };
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

  return { stream: stream(), inject };
}
