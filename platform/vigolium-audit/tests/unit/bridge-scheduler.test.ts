import { describe, expect, test } from "bun:test";
import { BridgeScheduler, type DaemonLimits } from "../../src/cli/bridge-serve.js";
import type { BridgeRunResult } from "../../src/engine/bridge.js";
import type { WireRequest } from "../../src/cli/bridge-protocol.js";

const TERMINALS = new Set(["result", "cancelled", "error"]);
const tick = (ms = 5): Promise<void> => new Promise((r) => setTimeout(r, ms));

function fakeResult(id: string): BridgeRunResult {
  return {
    ok: true,
    transportOk: true,
    contractOk: null,
    action: "run",
    platform: "claude",
    sessionId: id,
    model: null,
    usd: 0,
    tokens: { input: 0, output: 0 },
    durationMs: 0,
    attempts: 1,
    output: null,
    outputRaw: "",
    loadedSkills: [],
    missingSkills: [],
  };
}

/** A scheduler wired to a controllable fake runTask that captures emissions. */
function harness(limits: Partial<DaemonLimits> = {}) {
  const emitted: Record<string, unknown>[] = [];
  const started: string[] = [];
  const pending = new Map<string, { resolve: (r: BridgeRunResult) => void; signal: AbortSignal }>();
  let idleCalls = 0;

  const scheduler = new BridgeScheduler({
    emit: (p) => emitted.push(p),
    limits: { maxConcurrent: 4, maxQueued: 64, defaultTimeoutMs: 0, ...limits },
    onIdle: () => {
      idleCalls += 1;
    },
    runTask: (id, _params, signal) =>
      new Promise<BridgeRunResult>((resolve) => {
        started.push(id);
        pending.set(id, { resolve, signal });
        // Auto-settle on abort so the scheduler reaches its terminal decision
        // (the abort *cause* — not this value — decides what it emits).
        signal.addEventListener("abort", () => resolve(fakeResult(id)), { once: true });
      }),
  });

  const terminalsFor = (id: string): Record<string, unknown>[] =>
    emitted.filter((e) => e.id === id && typeof e.kind === "string" && TERMINALS.has(e.kind as string));

  return { scheduler, emitted, started, pending, terminalsFor, idle: () => idleCalls };
}

const run = (id: string, params?: Record<string, unknown>): WireRequest =>
  ({ method: "run", id, ...(params ? { params } : {}) }) as WireRequest;

describe("BridgeScheduler — one terminal per run", () => {
  test("happy path emits exactly one result", async () => {
    const h = harness();
    h.scheduler.handle(run("r1"));
    h.pending.get("r1")!.resolve(fakeResult("r1"));
    await tick();
    const terms = h.terminalsFor("r1");
    expect(terms).toHaveLength(1);
    expect(terms[0]!.kind).toBe("result");
  });

  test("cancel of a running run yields a single cancelled (no result)", async () => {
    const h = harness();
    h.scheduler.handle(run("r1"));
    h.scheduler.handle({ method: "cancel", params: { id: "r1" } } as WireRequest);
    await tick();
    const terms = h.terminalsFor("r1");
    expect(terms).toHaveLength(1);
    expect(terms[0]!.kind).toBe("cancelled");
  });

  test("deadline yields a single deadline_exceeded error", async () => {
    const h = harness();
    h.scheduler.handle(run("r1", { timeoutMs: 5 }));
    await tick(25);
    const terms = h.terminalsFor("r1");
    expect(terms).toHaveLength(1);
    expect(terms[0]).toMatchObject({ kind: "error", code: "deadline_exceeded", retryable: true });
  });

  test("setup failure (runTask throws) yields a single internal_error", async () => {
    const emitted: Record<string, unknown>[] = [];
    const scheduler = new BridgeScheduler({
      emit: (p) => emitted.push(p),
      limits: { maxConcurrent: 4, maxQueued: 64, defaultTimeoutMs: 0 },
      onIdle: () => {},
      runTask: () => Promise.reject(new Error("no claude binary")),
    });
    scheduler.handle(run("r1"));
    await tick();
    const terms = emitted.filter((e) => e.id === "r1" && TERMINALS.has(e.kind as string));
    expect(terms).toHaveLength(1);
    expect(terms[0]).toMatchObject({ kind: "error", code: "internal_error", error: "no claude binary" });
  });
});

describe("BridgeScheduler — bounded queue", () => {
  test("queues past maxConcurrent and rejects past capacity with queue_full", async () => {
    const h = harness({ maxConcurrent: 1, maxQueued: 1 });
    h.scheduler.handle(run("r1")); // active
    h.scheduler.handle(run("r2")); // queued
    h.scheduler.handle(run("r3")); // over capacity
    await tick();

    expect(h.started).toEqual(["r1"]); // only r1 actually started
    expect(h.emitted.find((e) => e.id === "r2" && e.kind === "queued")).toMatchObject({ position: 1 });
    const r3 = h.terminalsFor("r3");
    expect(r3).toHaveLength(1);
    expect(r3[0]).toMatchObject({ kind: "error", code: "queue_full", retryable: true });

    // finishing r1 pulls r2 off the queue
    h.pending.get("r1")!.resolve(fakeResult("r1"));
    await tick();
    expect(h.started).toEqual(["r1", "r2"]);
  });

  test("cancelling a queued run drops it without starting", async () => {
    const h = harness({ maxConcurrent: 1, maxQueued: 4 });
    h.scheduler.handle(run("r1")); // active
    h.scheduler.handle(run("r2")); // queued
    h.scheduler.handle({ method: "cancel", params: { id: "r2" } } as WireRequest);
    await tick();
    expect(h.terminalsFor("r2")).toMatchObject([{ kind: "cancelled" }]);

    h.pending.get("r1")!.resolve(fakeResult("r1"));
    await tick();
    expect(h.started).toEqual(["r1"]); // r2 never ran
  });

  test("duplicate in-flight id is rejected", async () => {
    const h = harness();
    h.scheduler.handle(run("r1"));
    h.scheduler.handle(run("r1"));
    await tick();
    expect(h.emitted.find((e) => e.kind === "error" && e.id === "r1")).toMatchObject({
      code: "invalid_request",
      error: "duplicate run id: r1",
    });
  });

  test("cancel of an unknown id is a structured error", () => {
    const h = harness();
    h.scheduler.handle({ method: "cancel", params: { id: "ghost" } } as WireRequest);
    expect(h.emitted).toMatchObject([{ id: "ghost", kind: "error", code: "invalid_request", error: "no such active run" }]);
  });
});

describe("BridgeScheduler — shutdown & drain", () => {
  test("shutdown cancels active + queued and then goes idle exactly once", async () => {
    const h = harness({ maxConcurrent: 1, maxQueued: 4 });
    h.scheduler.handle(run("r1")); // active
    h.scheduler.handle(run("r2")); // queued
    h.scheduler.handle({ method: "shutdown" } as WireRequest);
    await tick();

    expect(h.terminalsFor("r1")).toMatchObject([{ kind: "cancelled", reason: "shutdown" }]);
    expect(h.terminalsFor("r2")).toMatchObject([{ kind: "cancelled", reason: "shutdown" }]);
    expect(h.idle()).toBe(1);
  });

  test("run after shutdown is refused", async () => {
    const h = harness();
    h.scheduler.handle({ method: "shutdown" } as WireRequest);
    await tick();
    h.scheduler.handle(run("r9"));
    expect(h.emitted.find((e) => e.id === "r9")).toMatchObject({ kind: "error", code: "cancelled" });
  });

  test("ping answers pong", () => {
    const h = harness();
    h.scheduler.handle({ method: "ping" } as WireRequest);
    expect(h.emitted).toMatchObject([{ kind: "pong" }]);
  });
});
