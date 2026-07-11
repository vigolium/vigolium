import { createInterface } from "readline";
import { resolve } from "path";
import {
  applyBridgeAuth,
  buildBridgeAdapter,
  describeInvocation,
  resolveBridgeInvocation,
  runBridge,
  type BridgeOptions,
  type BridgeRunResult,
} from "../engine/bridge.js";
import { listBridgeTasks } from "../engine/bridge-tasks.js";
import type { AgentPlatform } from "../engine/types.js";
import { parseIntEnv } from "../engine/util.js";
import { emitJsonEvent, serializeAdapterEvent } from "./run-render.js";
import { resolveModel } from "./run-models.js";
import type { BridgeCliOptions } from "./bridge.js";
import { parseWireRequest, PROTOCOL_VERSION, type BridgeErrorCode, type RunParams, type WireRequest } from "./bridge-protocol.js";

/**
 * `bridge serve` — the long-lived daemon. Reads newline-delimited JSON requests
 * on stdin and writes newline-delimited JSON responses on stdout, keeping the
 * Node process (and the loaded SDK / content) warm across calls so the caller
 * avoids cold-start on every triage/exploit/plan.
 *
 * Wire protocol (one JSON object per line; see `bridge-protocol.ts`):
 *
 *   → { "id": "r1", "method": "run", "params": { "action": "triage", ... } }
 *   ← { "id": "r1", "kind": "accepted", ... }
 *   ← { "id": "r1", "kind": "event", "event": { ... } }        (many)
 *   ← { "id": "r1", "kind": "result", "result": { ... } }
 *
 *   → { "id": "r1", "method": "cancel" }        // aborts run r1
 *   → { "method": "ping" }   ← { "kind": "pong" }
 *   → { "method": "shutdown" }   ← { "kind": "bye" }
 *
 * The lifecycle logic lives in {@link BridgeScheduler}, which is pure over its
 * injected `emit` / `runTask` deps so it can be unit-tested with a scripted
 * adapter and no real stdout/exit. {@link serveBridge} is the thin I/O shell.
 *
 * Guarantees:
 *   - Every request is schema-validated before dispatch; a malformed one yields
 *     a structured `{ kind:"error", code:"invalid_request" }` instead of a crash.
 *   - Concurrency is bounded (`maxConcurrent`); excess work queues up to
 *     `maxQueued`, beyond which new runs are rejected with `queue_full`.
 *   - Each accepted run emits exactly one terminal message (`result`,
 *     `cancelled`, or `error`), even under cancel/deadline/shutdown races.
 *   - `bye` is flushed to the pipe before the process exits.
 */

/** Bounded-scheduler limits, from env with conservative defaults. */
export interface DaemonLimits {
  maxConcurrent: number;
  maxQueued: number;
  /** Default per-run wall-clock deadline (ms); 0 = no default (per-run only). */
  defaultTimeoutMs: number;
}

export function resolveLimits(env: NodeJS.ProcessEnv = process.env): DaemonLimits {
  return {
    // Each run spawns an SDK subprocess (heavy); keep the default conservative.
    maxConcurrent: Math.max(1, parseIntEnv(env.VIGOLIUM_AUDIT_BRIDGE_MAX_CONCURRENT, 4)),
    maxQueued: Math.max(0, parseIntEnv(env.VIGOLIUM_AUDIT_BRIDGE_MAX_QUEUED, 64)),
    defaultTimeoutMs: Math.max(0, parseIntEnv(env.VIGOLIUM_AUDIT_BRIDGE_TIMEOUT_MS, 0)),
  };
}

type AbortCause = "cancel" | "deadline" | "shutdown";

/** Per-run state: the abort controller plus why it was aborted (for the terminal). */
class RunHandle {
  readonly abort = new AbortController();
  cause: AbortCause | null = null;
  fire(cause: AbortCause): void {
    if (this.cause === null) {
      this.cause = cause;
      this.abort.abort(new Error(cause));
    }
  }
}

/** Deps the scheduler needs from the outside world (all mockable in tests). */
export interface SchedulerDeps {
  emit: (payload: Record<string, unknown>) => void;
  /**
   * Execute one accepted run to completion under `signal`. Owns emitting the
   * run's `accepted` + `event` lines; returns the result (or throws on setup
   * failure). The scheduler decides the single terminal from the outcome.
   */
  runTask: (id: string, params: RunParams, signal: AbortSignal) => Promise<BridgeRunResult>;
  limits: DaemonLimits;
  /** Called once, when draining and no run is active or queued. */
  onIdle: () => void;
}

/**
 * The daemon's run lifecycle: bounded concurrency + FIFO queue, per-run
 * deadlines, cancellation, and the exactly-one-terminal-per-run invariant.
 * Deterministic and side-effect-free apart from its injected deps.
 */
export class BridgeScheduler {
  private readonly active = new Map<string, RunHandle>();
  private readonly queue: Array<{ id: string; params: RunParams }> = [];
  private readonly queuedIds = new Set<string>();
  private draining = false;

  constructor(private readonly deps: SchedulerDeps) {}

  /** Dispatch a validated request. */
  handle(req: WireRequest): void {
    switch (req.method) {
      case "run":
        if (this.draining) {
          this.emitError(req.id, "cancelled", "daemon is shutting down");
          return;
        }
        this.handleRun(req.id, req.params ?? {});
        break;
      case "cancel":
        this.handleCancel(req.params?.id ?? req.id);
        break;
      case "ping":
        this.deps.emit({ kind: "pong" });
        break;
      case "shutdown":
        this.shutdown();
        break;
    }
  }

  /** stdin closed: finish in-flight + queued runs, then go idle. */
  drainAndFinish(): void {
    this.draining = true;
    this.maybeIdle();
  }

  private emitError(id: string | undefined, code: BridgeErrorCode, error: string, retryable = false): void {
    this.deps.emit({ ...(id ? { id } : {}), kind: "error", code, retryable, error });
  }

  private handleRun(id: string, params: RunParams): void {
    if (this.active.has(id) || this.queuedIds.has(id)) {
      this.emitError(id, "invalid_request", `duplicate run id: ${id}`);
      return;
    }
    const { maxConcurrent, maxQueued } = this.deps.limits;
    if (this.active.size + this.queue.length >= maxConcurrent + maxQueued) {
      this.emitError(id, "queue_full", `daemon at capacity (${maxConcurrent} running + ${maxQueued} queued)`, true);
      return;
    }
    this.queue.push({ id, params });
    this.queuedIds.add(id);
    this.tryDispatch();
    // Still queued after a dispatch pass → tell the caller where it landed. It
    // was just pushed to the tail and dispatch only shifts the front, so a
    // still-queued item is the last element: its 1-based position is the length.
    if (this.queuedIds.has(id)) {
      this.deps.emit({ id, kind: "queued", position: this.queue.length });
    }
  }

  private handleCancel(target: string | undefined): void {
    if (!target) {
      this.emitError(undefined, "invalid_request", "cancel requires an id");
      return;
    }
    if (this.queuedIds.has(target)) {
      // Not yet started — drop it and emit its single terminal here.
      const idx = this.queue.findIndex((q) => q.id === target);
      if (idx >= 0) this.queue.splice(idx, 1);
      this.queuedIds.delete(target);
      this.deps.emit({ id: target, kind: "cancelled" });
    } else if (this.active.has(target)) {
      // Running — the run's own completion path emits the terminal.
      this.active.get(target)!.fire("cancel");
    } else {
      this.emitError(target, "invalid_request", "no such active run");
    }
  }

  private shutdown(): void {
    this.draining = true;
    // Reject not-yet-started work with its terminal, then abort in-flight.
    for (const item of this.queue.splice(0)) {
      this.queuedIds.delete(item.id);
      this.deps.emit({ id: item.id, kind: "cancelled", reason: "shutdown" });
    }
    for (const handle of this.active.values()) handle.fire("shutdown");
    this.maybeIdle();
  }

  private tryDispatch(): void {
    while (this.active.size < this.deps.limits.maxConcurrent && this.queue.length > 0) {
      const item = this.queue.shift()!;
      this.queuedIds.delete(item.id);
      this.startRun(item.id, item.params);
    }
  }

  private startRun(id: string, params: RunParams): void {
    const handle = new RunHandle();
    this.active.set(id, handle);
    const timeoutMs = params.timeoutMs ?? this.deps.limits.defaultTimeoutMs;
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (timeoutMs > 0) {
      timer = setTimeout(() => handle.fire("deadline"), timeoutMs);
      timer.unref?.();
    }
    void (async () => {
      let result: BridgeRunResult | undefined;
      let caught: Error | undefined;
      try {
        result = await this.deps.runTask(id, params, handle.abort.signal);
      } catch (err) {
        caught = err as Error;
      } finally {
        if (timer) clearTimeout(timer);
        this.active.delete(id);
        this.emitTerminal(id, handle, result, caught, timeoutMs);
        this.tryDispatch();
        this.maybeIdle();
      }
    })();
  }

  /** Emit the single terminal message an accepted run is entitled to. */
  private emitTerminal(
    id: string,
    handle: RunHandle,
    result: BridgeRunResult | undefined,
    caught: Error | undefined,
    timeoutMs: number,
  ): void {
    if (handle.cause === "deadline") {
      this.emitError(id, "deadline_exceeded", `run exceeded its ${timeoutMs}ms deadline`, true);
    } else if (handle.cause === "cancel") {
      this.deps.emit({ id, kind: "cancelled" });
    } else if (handle.cause === "shutdown") {
      this.deps.emit({ id, kind: "cancelled", reason: "shutdown" });
    } else if (caught) {
      this.emitError(id, "internal_error", caught.message);
    } else if (result) {
      this.deps.emit({ id, kind: "result", result: result as unknown as Record<string, unknown> });
    } else {
      // Unreachable in practice, but never leave a run without a terminal.
      this.emitError(id, "internal_error", "run produced no result");
    }
  }

  private maybeIdle(): void {
    if (this.draining && this.active.size === 0 && this.queue.length === 0) {
      this.deps.onIdle();
    }
  }
}

function toBridgeOptions(params: RunParams, defaults: { platform: AgentPlatform; cwd: string }): BridgeOptions {
  const platform: AgentPlatform = params.agent ?? defaults.platform;
  const model = resolveModel(params.model); // request model → VIGOLIUM_AUDIT_MODEL → default
  return {
    action: params.action ?? "run",
    platform,
    cwd: resolve(params.cwd ?? defaults.cwd),
    skills: params.skills ?? [],
    disallowedTools: params.denyTools ?? params.disallowedTools ?? [],
    ...(params.prompt !== undefined ? { prompt: params.prompt } : {}),
    ...(params.input !== undefined ? { input: params.input } : {}),
    ...(params.systemPrompt !== undefined ? { systemPrompt: params.systemPrompt } : {}),
    ...(params.tools !== undefined ? { tools: params.tools } : {}),
    ...(model !== undefined ? { model } : {}),
    ...(params.maxTurns !== undefined ? { maxTurns: params.maxTurns } : {}),
    ...(params.resume !== undefined ? { resume: params.resume } : {}),
    ...(params.output !== undefined ? { output: params.output } : {}),
    ...(params.permission !== undefined ? { permission: params.permission } : {}),
    ...(params.network !== undefined ? { network: params.network } : {}),
    ...(params.bypassPermissions !== undefined ? { bypassPermissions: params.bypassPermissions } : {}),
  };
}

export async function serveBridge(opts: BridgeCliOptions): Promise<void> {
  const defaults = {
    platform: (opts.agent ?? "claude") as AgentPlatform,
    cwd: resolve(opts.cwd ?? opts.target ?? "."),
  };
  const limits = resolveLimits();

  // One global auth context for the daemon's lifetime.
  applyBridgeAuth({
    platform: defaults.platform,
    ...(opts.apiKey !== undefined ? { apiKey: opts.apiKey } : {}),
    ...(opts.oauthToken !== undefined ? { oauthToken: opts.oauthToken } : {}),
    ...(opts.oauthCredFile !== undefined ? { oauthCredFile: opts.oauthCredFile } : {}),
  });

  let exiting = false;
  // Flush buffered NDJSON to a (possibly piped, back-pressured) consumer before
  // exiting, so the terminal `bye` and any preceding results are not truncated.
  const flushAndExit = (): void => {
    try {
      process.stdout.write("", () => process.exit(0));
    } catch {
      process.exit(0);
    }
  };

  const scheduler = new BridgeScheduler({
    emit: emitJsonEvent,
    limits,
    onIdle: () => {
      if (exiting) return;
      exiting = true;
      emitJsonEvent({ kind: "bye" });
      flushAndExit();
    },
    runTask: async (id, params, signal) => {
      const bo = toBridgeOptions(params, defaults);
      const { adapter, choice } = buildBridgeAdapter(bo.platform, bo.model);
      const inv = await resolveBridgeInvocation(bo);
      emitJsonEvent({ id, kind: "accepted", protocolVersion: PROTOCOL_VERSION, ...describeInvocation(inv, choice) });
      return runBridge(
        inv,
        adapter,
        { onEvent: (e) => emitJsonEvent({ id, kind: "event", event: serializeAdapterEvent(e) }) },
        { abortSignal: signal },
      );
    },
  });

  const dispatch = (line: string): void => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;
    let raw: unknown;
    try {
      raw = JSON.parse(trimmed);
    } catch {
      emitJsonEvent({ kind: "error", code: "invalid_request", retryable: false, error: "malformed request (invalid JSON)" });
      return;
    }
    const parsed = parseWireRequest(raw);
    if (!parsed.ok) {
      emitJsonEvent({ ...(parsed.id ? { id: parsed.id } : {}), kind: "error", code: "invalid_request", retryable: false, error: parsed.error });
      return;
    }
    scheduler.handle(parsed.req);
  };

  // A dead consumer (EPIPE) can't receive anything more — exit quietly.
  process.stdout.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EPIPE") process.exit(0);
  });

  emitJsonEvent({
    kind: "ready-daemon",
    protocolVersion: PROTOCOL_VERSION,
    tasks: listBridgeTasks(),
    defaultPlatform: defaults.platform,
    cwd: defaults.cwd,
    limits,
  });

  const rl = createInterface({ input: process.stdin });
  rl.on("line", dispatch);
  rl.on("close", () => scheduler.drainAndFinish());

  // Keep the process alive until an explicit exit.
  await new Promise<void>(() => {});
}
