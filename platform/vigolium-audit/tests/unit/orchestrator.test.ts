import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { Orchestrator } from "../../src/engine/orchestrator.js";
import { makeContentLoader, resolveRoots } from "../../src/content-loader.js";
import type { Adapter, AdapterEvent, AdapterRunInput } from "../../src/adapters/adapter.js";
import type { OrchestratorEvent } from "../../src/engine/events.js";
import { StateStore } from "../../src/engine/state.js";

class FakeAdapter implements Adapter {
  readonly id = "fake";
  readonly platform = "claude" as const;
  readonly description = "FakeAdapter (tests)";
  calls: AdapterRunInput[] = [];
  shouldFail: Set<string> = new Set();
  /** Map of label → number of remaining transient errors to emit before success. */
  transientFailuresLeft: Map<string, number> = new Map();
  /** Map of label → number of remaining quota-limit failures to emit before success. */
  quotaFailuresLeft: Map<string, number> = new Map();
  /** Emit textDelta before transient error to test "saw progress" gating. */
  emitProgressBeforeTransient = false;
  async probe(): Promise<void> {}
  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    this.calls.push(input);
    const label = input.label ?? "";
    const quotaLeft = this.quotaFailuresLeft.get(label) ?? 0;
    if (quotaLeft > 0) {
      this.quotaFailuresLeft.set(label, quotaLeft - 1);
      yield { kind: "textDelta", text: "You've hit your limit · resets 4am (Asia/Singapore)" };
      yield { kind: "error", cause: new Error("claude CLI exited 1") };
      yield {
        kind: "finish",
        ok: false,
        reason: "usage limit reached",
        usd: 0,
        tokens: { input: 0, output: 0 },
        durationMs: 1,
      };
      return;
    }
    const transientLeft = this.transientFailuresLeft.get(label) ?? 0;
    if (transientLeft > 0) {
      this.transientFailuresLeft.set(label, transientLeft - 1);
      if (this.emitProgressBeforeTransient) {
        yield { kind: "textDelta", text: "partial output before transient" };
      }
      yield { kind: "error", cause: new Error("simulated 429"), transient: true };
      yield {
        kind: "finish",
        ok: false,
        reason: "simulated 429",
        usd: 0,
        tokens: { input: 0, output: 0 },
        durationMs: 1,
      };
      return;
    }
    yield { kind: "textDelta", text: `running ${label}` };
    const fail = label && this.shouldFail.has(label);
    if (fail) {
      yield {
        kind: "finish",
        ok: false,
        reason: "synthetic failure",
        usd: 0.05,
        tokens: { input: 100, output: 50 },
        durationMs: 10,
      };
    } else {
      yield {
        kind: "finish",
        ok: true,
        result: "ok",
        usd: 0.10,
        tokens: { input: 200, output: 80 },
        durationMs: 12,
      };
    }
  }
}

function makeTarget(): string {
  const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-target-"));
  return dir;
}

describe("Orchestrator", () => {
  test("runs all 3 lite phases sequentially in topo order; writes audit-state.json", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
    });
    const events: OrchestratorEvent[] = [];
    orch.on((e) => {
      events.push(e);
    });
    const result = await orch.run();
    expect(result.status).toBe("complete");
    expect(result.failedPhases).toEqual([]);
    expect(adapter.calls.length).toBe(3);
    expect(adapter.calls.map((c) => c.label)).toEqual(["lite:L1", "lite:L2", "lite:L3"]);

    const state = await new StateStore(join(target, "vigolium-results")).load();
    expect(state.audits.length).toBe(1);
    const audit = state.audits[0]!;
    expect(audit.status).toBe("complete");
    for (const id of ["L1", "L2", "L3"]) {
      expect(audit.phases[id]?.status).toBe("complete");
    }
    const usd = audit.usage?.cost_usd ?? 0;
    expect(usd).toBeGreaterThan(0);
  });

  test("strict failure aborts after first failed phase", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    adapter.shouldFail.add("balanced:B1");
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "balanced",
      failurePolicy: "strict",
    });
    const result = await orch.run();
    expect(result.status).toBe("aborted");
    expect(result.failedPhases).toEqual(["B1"]);
    expect(adapter.calls.length).toBe(1);
  });

  test("skip-and-continue keeps going past failures", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    adapter.shouldFail.add("balanced:B1");
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "balanced",
      failurePolicy: "skip-and-continue",
    });
    const result = await orch.run();
    expect(result.failedPhases).toContain("B1");
    expect(result.status).toBe("failed");
    expect(adapter.calls.length).toBe(9);
  });

  test("max-cost aborts mid-run", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "balanced",
      maxCost: 0.25,
    });
    const result = await orch.run();
    expect(result.status).toBe("aborted");
    expect(result.totalUsd).toBeGreaterThanOrEqual(0.25);
    expect(adapter.calls.length).toBeLessThan(8);
  });

  test("git-required phases are skipped on no-git target", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "deep",
    });
    const result = await orch.run();
    expect(result.skippedPhases).toContain("D2");
    expect(result.skippedPhases).toContain("D3");
    const labels = adapter.calls.map((c) => c.label);
    expect(labels).not.toContain("deep:D2");
    expect(labels).not.toContain("deep:D3");
  });

  test("noGit forces requires_git phases to skip and nulls audit git fields", async () => {
    const target = makeTarget();
    // Fake a .git dir so probeGit would otherwise report available; noGit
    // must short-circuit the probe and force git-gated phases to skip.
    mkdirSync(join(target, ".git"), { recursive: true });
    const adapter = new FakeAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "deep",
      noGit: true,
    });
    const result = await orch.run();
    expect(result.skippedPhases).toContain("D2");
    expect(result.skippedPhases).toContain("D3");
    const state = await new StateStore(join(target, "vigolium-results")).load();
    const audit = state.audits[state.audits.length - 1]!;
    expect(audit.commit).toBeNull();
    expect(audit.branch).toBeNull();
    expect(audit.repository).toBeNull();
  });

  test("transient errors before progress retry up to maxRetries", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    adapter.transientFailuresLeft.set("lite:L1", 2);
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      transientRetries: 3,
    });
    const result = await orch.run();
    expect(result.status).toBe("complete");
    // L1 was attempted 3x (2 transient + 1 success); plus L2, L3 once each.
    const q0Calls = adapter.calls.filter((c) => c.label === "lite:L1").length;
    expect(q0Calls).toBe(3);
  });

  test("quota-limit errors retry past sawProgress with the configured backoff", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    adapter.quotaFailuresLeft.set("lite:L1", 2);
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      transientRetries: 0, // prove this is NOT the path being taken
      quotaMaxRetries: 3,
      quotaBackoffMs: 1, // 1ms so the test doesn't actually sleep an hour
    });
    const result = await orch.run();
    expect(result.status).toBe("complete");
    // L1: 2 quota failures (with textDelta progress) + 1 success.
    const q0Calls = adapter.calls.filter((c) => c.label === "lite:L1").length;
    expect(q0Calls).toBe(3);
  });

  test("quota-limit errors give up after quotaMaxRetries", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    adapter.quotaFailuresLeft.set("lite:L1", 10);
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      quotaMaxRetries: 2,
      quotaBackoffMs: 1,
      failurePolicy: "skip-and-continue",
    });
    const result = await orch.run();
    const q0Calls = adapter.calls.filter((c) => c.label === "lite:L1").length;
    expect(q0Calls).toBe(3); // initial attempt + 2 retries
    expect(result.failedPhases).toContain("L1");
  });

  test("transient errors after progress are NOT retried (mid-stream)", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    adapter.transientFailuresLeft.set("lite:L1", 5);
    adapter.emitProgressBeforeTransient = true;
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      transientRetries: 3,
      failurePolicy: "skip-and-continue",
    });
    const result = await orch.run();
    const q0Calls = adapter.calls.filter((c) => c.label === "lite:L1").length;
    expect(q0Calls).toBe(1); // No retry because progress was emitted before the error.
    expect(result.failedPhases).toContain("L1");
  });

  test("phase failure quarantines findings-draft files matching phase prefix", async () => {
    const target = makeTarget();
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(join(resultsDir, "findings-draft"), { recursive: true });
    writeFileSync(join(resultsDir, "findings-draft", "l1-001-foo.md"), "## L1-001\n");
    writeFileSync(join(resultsDir, "findings-draft", "l1-002-bar.md"), "## L1-002\n");
    writeFileSync(join(resultsDir, "findings-draft", "l2-001-keep.md"), "## L2-001\n");

    const adapter = new FakeAdapter();
    adapter.shouldFail.add("lite:L1");
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      failurePolicy: "skip-and-continue",
    });
    const result = await orch.run();
    expect(result.failedPhases).toContain("L1");

    const archiveDir = join(resultsDir, ".archive", result.auditId, "L1");
    const { existsSync: exists, readdirSync } = await import("fs");
    expect(exists(archiveDir)).toBe(true);
    const archived = readdirSync(archiveDir).sort();
    expect(archived).toEqual(["l1-001-foo.md", "l1-002-bar.md"]);
    // L2 file should still be in findings-draft (different phase prefix).
    const drafts = readdirSync(join(resultsDir, "findings-draft"));
    expect(drafts).toContain("l2-001-keep.md");
    expect(drafts).not.toContain("l1-001-foo.md");
  });

  test("liveTarget injects header + substitutes $ARGUMENTS in command body", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "confirm",
      liveTarget: "https://staging.example.com",
    });
    await orch.run();
    expect(adapter.calls.length).toBeGreaterThan(0);
    const prompt = adapter.calls[0]!.userPrompt;
    expect(prompt).toContain("Live target: https://staging.example.com");
    // confirm.md body references $ARGUMENTS — verify it was substituted.
    expect(prompt).not.toContain("$ARGUMENTS");
    expect(prompt).toContain("https://staging.example.com");
  });

  test("liveTarget unset → no Live target line and $ARGUMENTS scrubbed to empty", async () => {
    const target = makeTarget();
    const adapter = new FakeAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "confirm",
    });
    await orch.run();
    const prompt = adapter.calls[0]!.userPrompt;
    expect(prompt).not.toContain("Live target:");
    expect(prompt).not.toContain("$ARGUMENTS");
  });

  test("resume picks up an in-progress audit and skips completed phases", async () => {
    const target = makeTarget();
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(resultsDir, { recursive: true });
    // Pre-seed audit-state with one in-progress audit, L1 already complete.
    writeFileSync(
      join(resultsDir, "audit-state.json"),
      JSON.stringify(
        {
          schema_version: 1,
          audits: [
            {
              audit_id: "2026-05-09T00:00:00.000Z",
              commit: null,
              branch: null,
              repository: null,
              mode: "lite",
              model: null,
              agent_sdk: "fake",
              started_at: "2026-05-09T00:00:00.000Z",
              completed_at: null,
              status: "in_progress",
              phases: {
                L1: { status: "complete", completed_at: "2026-05-09T00:00:01.000Z" },
                L2: { status: "pending" },
                L3: { status: "pending" },
              },
            },
          ],
        },
        null,
        2,
      ),
    );

    const adapter = new FakeAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      resume: true,
    });
    const result = await orch.run();
    expect(result.status).toBe("complete");
    expect(adapter.calls.map((c) => c.label)).toEqual(["lite:L2", "lite:L3"]);
  });
});
