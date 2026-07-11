import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { Orchestrator } from "../../src/engine/orchestrator.js";
import { makeContentLoader, resolveRoots } from "../../src/content-loader.js";
import { StateStore } from "../../src/engine/state.js";
import { writeAuditContext } from "../../src/engine/audit-context.js";
import { resolveAuditContext } from "../../src/cli/run.js";
import type { Adapter, AdapterEvent, AdapterRunInput } from "../../src/adapters/adapter.js";

class CapturingAdapter implements Adapter {
  readonly id = "capture";
  readonly platform = "claude" as const;
  readonly description = "CapturingAdapter (tests)";
  calls: AdapterRunInput[] = [];
  async probe(): Promise<void> {}
  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    this.calls.push(input);
    if (input.cwd) {
      const attackSurface = join(input.cwd, "vigolium-results", "attack-surface");
      mkdirSync(attackSurface, { recursive: true });
      if (input.label?.startsWith("lite:L1")) {
        writeFileSync(join(attackSurface, "lite-recon.md"), "## Lite Recon\n\nFixture recon completed.\n");
        writeFileSync(
          join(attackSurface, "unauthenticated-surface.md"),
          "# Unauthenticated Attack Surface\n\nNo fixture surface.\n",
        );
      } else if (input.label?.startsWith("lite:L2")) {
        writeFileSync(join(attackSurface, "lite-secrets-scan.md"), "## Lite Secrets Scan\n\nNo fixture secrets.\n");
      } else if (input.label?.startsWith("lite:L3")) {
        writeFileSync(join(attackSurface, "lite-sast-summary.md"), "## Lite SAST Summary\n\nNo fixture findings.\n");
        const drafts = join(input.cwd, "vigolium-results", "findings-draft");
        mkdirSync(drafts, { recursive: true });
        writeFileSync(join(drafts, "consolidation-manifest.json"), '{"findings":[],"theoretical":[],"dropped":[]}\n');
      }
    }
    yield { kind: "textDelta", text: "ok" };
    yield {
      kind: "finish",
      ok: true,
      result: "ok",
      usd: 0.01,
      tokens: { input: 10, output: 5 },
      durationMs: 1,
    };
  }
}

function makeTarget(): string {
  return mkdtempSync(join(tmpdir(), "vigolium-audit-target-"));
}

describe("audit context — prompt injection + persistence", () => {
  test("focus + expected-behaviors blocks land in every phase's user prompt", async () => {
    const target = makeTarget();
    const adapter = new CapturingAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      focus: "Look hard at src/auth/** and src/api/handlers/**.",
      expectedBehaviors: "/healthz returns 200 unauthenticated by design.",
    });
    await orch.run();
    expect(adapter.calls.length).toBe(3);
    for (const call of adapter.calls) {
      expect(call.userPrompt).toContain("--- AUDIT FOCUS (user-supplied) ---");
      expect(call.userPrompt).toContain("Look hard at src/auth/**");
      expect(call.userPrompt).toContain("--- EXPECTED BEHAVIORS (user-supplied) ---");
      expect(call.userPrompt).toContain("/healthz returns 200");
    }
  });

  test("blocks are omitted entirely when context is empty/unset", async () => {
    const target = makeTarget();
    const adapter = new CapturingAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
    });
    await orch.run();
    for (const call of adapter.calls) {
      expect(call.userPrompt).not.toContain("--- AUDIT FOCUS");
      expect(call.userPrompt).not.toContain("--- EXPECTED BEHAVIORS");
    }
  });

  test("only one block renders when only one field is supplied", async () => {
    const target = makeTarget();
    const adapter = new CapturingAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      focus: "JUST FOCUS",
    });
    await orch.run();
    const prompt = adapter.calls[0]!.userPrompt;
    expect(prompt).toContain("--- AUDIT FOCUS");
    expect(prompt).toContain("JUST FOCUS");
    expect(prompt).not.toContain("--- EXPECTED BEHAVIORS");
  });

  test("context is persisted into the new audit record", async () => {
    const target = makeTarget();
    const adapter = new CapturingAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      focus: "FOCUS PROSE",
      expectedBehaviors: "EXPECTED PROSE",
    });
    await orch.run();
    const state = await new StateStore(join(target, "vigolium-results")).load();
    const audit = state.audits[0]!;
    expect(audit.context).toBeDefined();
    expect(audit.context?.focus).toBe("FOCUS PROSE");
    expect(audit.context?.expected_behaviors).toBe("EXPECTED PROSE");
  });

  test("empty strings are NOT persisted (no spurious context block on disk)", async () => {
    const target = makeTarget();
    const adapter = new CapturingAdapter();
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
      focus: "",
      expectedBehaviors: "",
    });
    await orch.run();
    const state = await new StateStore(join(target, "vigolium-results")).load();
    const audit = state.audits[0]!;
    expect(audit.context).toBeUndefined();
  });
});

describe("audit context — handoff auto-confirm policy", () => {
  test("fresh context leaves stale artifact lifecycle to the trusted CLI", async () => {
    const target = makeTarget();
    const resultsDir = join(target, "vigolium-results");
    await writeAuditContext(resultsDir, {});
    const body = readFileSync(join(resultsDir, "audit-context.md"), "utf8");
    expect(body).toContain("trusted CLI handles stale core artifacts");
    expect(body).toContain("do not delete retained state");
    expect(body).not.toContain("Clean up stale working state");
  });

  test("resume context tells agents to continue, not start fresh", async () => {
    const target = makeTarget();
    const resultsDir = join(target, "vigolium-results");
    await writeAuditContext(resultsDir, { resume: true });
    const body = readFileSync(join(resultsDir, "audit-context.md"), "utf8");
    expect(body).toContain("Explicit Resume Requested");
    expect(body).toContain("Resume from last checkpoint");
    expect(body).toContain("Do NOT start fresh");
    expect(body).not.toContain("pick **\"Start fresh\"**");
  });
});

describe("audit context — resolveAuditContext (CLI helper)", () => {
  test("reads --focus-file from disk", async () => {
    const target = makeTarget();
    const focusPath = join(target, "focus.md");
    writeFileSync(focusPath, "FOCUS BODY\n");
    const ctx = await resolveAuditContext({
      targetDir: target,
      opts: { target, focusFile: focusPath },
      json: true,
    });
    expect(ctx.focus).toContain("FOCUS BODY");
    expect(ctx.expectedBehaviors).toBeUndefined();
  });

  test("missing file → throws with the flag name in the message", async () => {
    const target = makeTarget();
    let err: Error | null = null;
    try {
      await resolveAuditContext({
        targetDir: target,
        opts: { target, focusFile: join(target, "does-not-exist.md") },
        json: true,
      });
    } catch (e) {
      err = e as Error;
    }
    expect(err).not.toBeNull();
    expect(err!.message).toContain("--focus-file");
    expect(err!.message).toContain("does-not-exist.md");
  });

  test("oversize file → throws (no silent truncation)", async () => {
    const target = makeTarget();
    const big = join(target, "big.md");
    // 33 KB > 32 KB cap.
    writeFileSync(big, "x".repeat(33 * 1024));
    let err: Error | null = null;
    try {
      await resolveAuditContext({
        targetDir: target,
        opts: { target, expectedBehaviorsFile: big },
        json: true,
      });
    } catch (e) {
      err = e as Error;
    }
    expect(err).not.toBeNull();
    expect(err!.message).toContain("--expected-behaviors-file");
    expect(err!.message).toContain("exceeds");
  });

  test("inherits from latest prior audit when flags unset", async () => {
    const target = makeTarget();
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(
      join(resultsDir, "audit-state.json"),
      JSON.stringify({
        schema_version: 1,
        audits: [
          {
            audit_id: "2026-05-09T00:00:00.000Z",
            commit: null,
            branch: null,
            repository: null,
            mode: "deep",
            model: null,
            agent_sdk: "fake",
            started_at: "2026-05-09T00:00:00.000Z",
            completed_at: "2026-05-09T00:01:00.000Z",
            status: "complete",
            phases: {},
            context: {
              focus: "PRIOR FOCUS",
              expected_behaviors: "PRIOR EXPECTED",
            },
          },
        ],
      }),
    );
    const ctx = await resolveAuditContext({
      targetDir: target,
      opts: { target },
      json: true,
    });
    expect(ctx.focus).toBe("PRIOR FOCUS");
    expect(ctx.expectedBehaviors).toBe("PRIOR EXPECTED");
  });

  test("explicit flag overrides inheritance per-field", async () => {
    const target = makeTarget();
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(
      join(resultsDir, "audit-state.json"),
      JSON.stringify({
        schema_version: 1,
        audits: [
          {
            audit_id: "2026-05-09T00:00:00.000Z",
            commit: null,
            branch: null,
            repository: null,
            mode: "deep",
            model: null,
            agent_sdk: "fake",
            started_at: "2026-05-09T00:00:00.000Z",
            completed_at: "2026-05-09T00:01:00.000Z",
            status: "complete",
            phases: {},
            context: {
              focus: "PRIOR FOCUS",
              expected_behaviors: "PRIOR EXPECTED",
            },
          },
        ],
      }),
    );
    const focusPath = join(target, "new-focus.md");
    writeFileSync(focusPath, "NEW FOCUS");
    const ctx = await resolveAuditContext({
      targetDir: target,
      opts: { target, focusFile: focusPath },
      json: true,
    });
    expect(ctx.focus).toBe("NEW FOCUS");
    // Expected-behaviors still inherited (not overridden).
    expect(ctx.expectedBehaviors).toBe("PRIOR EXPECTED");
  });

  test("empty file overrides inheritance to no-context", async () => {
    const target = makeTarget();
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(
      join(resultsDir, "audit-state.json"),
      JSON.stringify({
        schema_version: 1,
        audits: [
          {
            audit_id: "2026-05-09T00:00:00.000Z",
            commit: null,
            branch: null,
            repository: null,
            mode: "deep",
            model: null,
            agent_sdk: "fake",
            started_at: "2026-05-09T00:00:00.000Z",
            completed_at: "2026-05-09T00:01:00.000Z",
            status: "complete",
            phases: {},
            context: { focus: "PRIOR FOCUS" },
          },
        ],
      }),
    );
    const empty = join(target, "empty.md");
    writeFileSync(empty, "");
    const ctx = await resolveAuditContext({
      targetDir: target,
      opts: { target, focusFile: empty },
      json: true,
    });
    // Read returns "", which is falsy — orchestrator skips the block.
    expect(ctx.focus).toBe("");
  });

  test("no prior state file → both fields undefined", async () => {
    const target = makeTarget();
    const ctx = await resolveAuditContext({
      targetDir: target,
      opts: { target },
      json: true,
    });
    expect(ctx.focus).toBeUndefined();
    expect(ctx.expectedBehaviors).toBeUndefined();
  });
});
