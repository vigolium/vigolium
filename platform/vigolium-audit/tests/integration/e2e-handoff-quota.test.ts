import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, utimesSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { ClaudeHandoff } from "../../src/engine/claude-handoff.js";
import { CodexHandoff } from "../../src/engine/codex-handoff.js";
import type { Adapter, AdapterEvent, AdapterRunInput } from "../../src/adapters/adapter.js";
import type { OrchestratorEvent } from "../../src/engine/events.js";

function writeLiteArtifacts(cwd: string | undefined): void {
  if (!cwd) return;
  const dir = join(cwd, "vigolium-results", "attack-surface");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "lite-recon.md"), "## Lite Recon\n\nHandoff fixture recon artifact.\n");
  writeFileSync(
    join(dir, "unauthenticated-surface.md"),
    "# Unauthenticated Attack Surface\n\nHandoff fixture surface.\n",
  );
  writeFileSync(join(dir, "lite-secrets-scan.md"), "## Lite Secrets Scan\n\nNo retained fixture secrets.\n");
  writeFileSync(join(dir, "lite-sast-summary.md"), "## Lite SAST Summary\n\nNo retained fixture findings.\n");
  const drafts = join(cwd, "vigolium-results", "findings-draft");
  mkdirSync(drafts, { recursive: true });
  writeFileSync(join(drafts, "consolidation-manifest.json"), '{"findings":[],"theoretical":[],"dropped":[]}\n');
}

/**
 * Scripted adapter that simulates Claude hitting its usage limit on the first
 * handoff attempt (prints the "You've hit your limit" notice then exits
 * non-zero) and succeeding on the second. Mirrors the real failure shape:
 * the quota line arrives as a text block, the run finishes non-ok.
 */
class QuotaThenOkAdapter implements Adapter {
  readonly id = "quota-fake";
  readonly platform = "claude" as const;
  readonly description = "QuotaThenOkAdapter (e2e tests)";
  runCalls = 0;
  probeCalls = 0;

  async probe(): Promise<void> {
    this.probeCalls++;
  }

  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    const attempt = this.runCalls++;
    if (attempt === 0) {
      yield { kind: "textDelta", text: "working on the audit…\n" };
      yield {
        kind: "textDelta",
        text: "● You've hit your limit · resets 1:20am (Asia/Singapore)\n",
      };
      yield {
        kind: "finish",
        ok: false,
        reason: "claude CLI exited 1",
        usd: 12.5,
        tokens: { input: 100, output: 50 },
        durationMs: 5,
      };
      return;
    }
    writeLiteArtifacts(input.cwd);
    yield { kind: "textDelta", text: "resuming the audit…\n" };
    yield {
      kind: "finish",
      ok: true,
      result: "done",
      usd: 4.25,
      tokens: { input: 80, output: 40 },
      durationMs: 5,
    };
  }
}

describe("e2e: claude handoff quota-limit retry", () => {
  test("retries after a usage-limit hit, preflights, then completes", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-quota-"));
    const adapter = new QuotaThenOkAdapter();

    const handoff = new ClaudeHandoff({
      adapter,
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/does-not-matter",
      quotaMaxRetries: 3,
      quotaBackoffMs: 1, // don't actually sleep an hour in tests
    });

    const texts: string[] = [];
    handoff.on((e: OrchestratorEvent) => {
      if (e.kind === "phaseAdapterEvent" && e.event.kind === "textDelta") {
        texts.push(e.event.text);
      }
    });

    const result = await handoff.run();

    // Recovered instead of stopping on the first quota hit.
    expect(result.status).toBe("complete");
    // Attempt 1 (quota fail) + attempt 2 (success).
    expect(adapter.runCalls).toBe(2);
    // Preflight probe ran once between the two attempts.
    expect(adapter.probeCalls).toBe(1);

    // The sleep/preflight notices were surfaced on the event bus.
    const joined = texts.join("");
    expect(joined).toContain("quota limit hit — sleeping 0m before retry 1/3");
    expect(joined).toContain("preflight ok — quota reset, resuming audit");

    // Cost/tokens accumulate across both attempts, not just the last one.
    expect(result.totalUsd).toBeGreaterThanOrEqual(16); // 12.5 + 4.25, round2
    expect(result.totalTokens.input).toBe(180);
    expect(result.totalTokens.output).toBe(90);

    const state = JSON.parse(readFileSync(join(target, "vigolium-results", "audit-state.json"), "utf8"));
    const audit = state.audits.at(-1);
    expect(audit.status).toBe("complete");
    expect(audit.history_available).toBe(false);
    expect(audit.usage).toEqual({ input_tokens: 180, output_tokens: 90, cost_usd: 16.75 });
    expect(
      Object.values(audit.phases as Record<string, { status: string }>).every(
        (phase) => phase.status === "complete",
      ),
    ).toBe(true);
    expect(readFileSync(join(target, "vigolium-results", "audit-context.md"), "utf8")).toContain(
      "## Engine-Owned Audit State",
    );
  });

  test("gives up after quotaMaxRetries when the limit never clears", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-quota-stuck-"));

    class AlwaysQuotaAdapter implements Adapter {
      readonly id = "always-quota";
      readonly platform = "claude" as const;
      readonly description = "AlwaysQuotaAdapter";
      runCalls = 0;
      probeCalls = 0;
      async probe(): Promise<void> {
        this.probeCalls++;
        throw new Error("rate-limited");
      }
      async *run(_input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        this.runCalls++;
        yield { kind: "textDelta", text: "You've hit your limit · resets 1:20am\n" };
        yield {
          kind: "finish",
          ok: false,
          reason: "claude CLI exited 1",
          usd: 1,
          tokens: { input: 1, output: 1 },
          durationMs: 1,
        };
      }
    }

    const adapter = new AlwaysQuotaAdapter();
    const handoff = new ClaudeHandoff({
      adapter,
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/does-not-matter",
      quotaMaxRetries: 2,
      quotaBackoffMs: 1,
    });

    const result = await handoff.run();

    // Initial attempt + 2 retries = 3 runs, then exits (resumable on disk).
    expect(adapter.runCalls).toBe(3);
    expect(adapter.probeCalls).toBe(2);
    expect(result.status).toBe("failed");
  });
});

describe("e2e: claude handoff retry edge cases", () => {
  test("quota notice inside a toolResult triggers quota sleep and retry", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-quota-tool-result-"));

    class ToolResultQuotaThenOkAdapter implements Adapter {
      readonly id = "tool-result-quota";
      readonly platform = "claude" as const;
      readonly description = "ToolResultQuotaThenOkAdapter";
      runCalls = 0;
      probeCalls = 0;
      async probe(): Promise<void> {
        this.probeCalls++;
      }
      async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        const attempt = this.runCalls++;
        if (attempt === 0) {
          yield {
            kind: "toolResult",
            id: "subagent",
            output: [
              { type: "text", text: "You've hit your limit · resets 10:20pm (Asia/Singapore)" },
              { type: "text", text: "agentId: a41fa5" },
            ],
            isError: false,
          };
          yield { kind: "error", cause: new Error("claude CLI exited 1") };
          return;
        }
        writeLiteArtifacts(input.cwd);
        yield { kind: "finish", ok: true, result: "done", usd: 0, tokens: { input: 0, output: 0 }, durationMs: 1 };
      }
    }

    const adapter = new ToolResultQuotaThenOkAdapter();
    const handoff = new ClaudeHandoff({
      adapter,
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/does-not-matter",
      quotaMaxRetries: 2,
      quotaBackoffMs: 1,
    });

    const texts: string[] = [];
    handoff.on((e: OrchestratorEvent) => {
      if (e.kind === "phaseAdapterEvent" && e.event.kind === "textDelta") texts.push(e.event.text);
    });

    const result = await handoff.run();

    expect(result.status).toBe("complete");
    expect(adapter.runCalls).toBe(2);
    expect(adapter.probeCalls).toBe(1);
    expect(texts.join("")).toContain("quota limit hit — sleeping 0m before retry 1/2");
  });

  test("successful handoff cannot complete when declared artifacts are absent", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-gate-"));

    class EmptySuccessAdapter implements Adapter {
      readonly id = "empty-success";
      readonly platform = "claude" as const;
      readonly description = "EmptySuccessAdapter";
      async probe(): Promise<void> {}
      async *run(_input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        yield { kind: "finish", ok: true, result: "done", usd: 0, tokens: { input: 0, output: 0 }, durationMs: 1 };
      }
    }

    const handoff = new ClaudeHandoff({
      adapter: new EmptySuccessAdapter(),
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/does-not-matter",
    });
    const result = await handoff.run();
    expect(result.status).toBe("failed");
    expect(result.failedPhases).toEqual(["L1", "L2", "L3"]);
    const state = JSON.parse(readFileSync(join(target, "vigolium-results", "audit-state.json"), "utf8"));
    expect(state.audits.at(-1).status).toBe("failed");
    expect(state.audits.at(-1).phases.L1.status).toBe("failed");
  });

  test("fresh handoff cannot complete from untouched prior-run artifacts", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-stale-"));
    writeLiteArtifacts(target);
    const old = new Date(Date.now() - 60_000);
    for (const relative of [
      "attack-surface/lite-recon.md",
      "attack-surface/unauthenticated-surface.md",
      "attack-surface/lite-secrets-scan.md",
      "attack-surface/lite-sast-summary.md",
      "findings-draft/consolidation-manifest.json",
    ]) {
      utimesSync(join(target, "vigolium-results", relative), old, old);
    }

    class StaleSuccessAdapter implements Adapter {
      readonly id = "stale-success";
      readonly platform = "claude" as const;
      readonly description = "StaleSuccessAdapter";
      async probe(): Promise<void> {}
      async *run(_input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        yield {
          kind: "finish",
          ok: true,
          result: "done",
          usd: 0,
          tokens: { input: 0, output: 0 },
          durationMs: 1,
        };
      }
    }

    const handoff = new ClaudeHandoff({
      adapter: new StaleSuccessAdapter(),
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/does-not-matter",
    });
    const result = await handoff.run();
    expect(result.status).toBe("failed");
    expect(result.failedPhases).toEqual(["L1", "L2", "L3"]);
  });

  test("fresh handoff archives prior core outputs before writing the new run", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-fresh-archive-"));
    writeLiteArtifacts(target);
    writeFileSync(
      join(target, "vigolium-results", "attack-surface", "lite-recon.md"),
      "## Lite Recon\n\nOLD prior-run recon artifact that must be archived.\n",
    );
    writeFileSync(
      join(target, "vigolium-results", "audit-state.json"),
      JSON.stringify({
        schema_version: 1,
        audits: [{
          audit_id: "2026-01-01T00:00:00.000Z",
          commit: null,
          branch: null,
          repository: null,
          mode: "lite",
          model: null,
          agent_sdk: "old",
          started_at: "2026-01-01T00:00:00.000Z",
          completed_at: "2026-01-01T00:01:00.000Z",
          status: "complete",
          phases: {
            L1: { status: "complete" },
            L2: { status: "complete" },
            L3: { status: "complete" },
          },
        }],
      }),
    );

    class FreshAdapter implements Adapter {
      readonly id = "fresh";
      readonly platform = "claude" as const;
      readonly description = "FreshAdapter";
      async probe(): Promise<void> {}
      async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        writeLiteArtifacts(input.cwd);
        yield {
          kind: "finish",
          ok: true,
          result: "done",
          usd: 0,
          tokens: { input: 0, output: 0 },
          durationMs: 1,
        };
      }
    }

    const handoff = new ClaudeHandoff({
      adapter: new FreshAdapter(),
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/does-not-matter",
    });
    const result = await handoff.run();
    expect(result.status).toBe("complete");

    const archiveRoot = join(target, "vigolium-results", ".archive", "pre-run");
    const archive = join(archiveRoot, readdirSync(archiveRoot)[0]!);
    expect(readFileSync(join(archive, "attack-surface", "lite-recon.md"), "utf8")).toContain("OLD prior-run");
    expect(readFileSync(join(target, "vigolium-results", "attack-surface", "lite-recon.md"), "utf8")).toContain("Handoff fixture");
    const state = JSON.parse(readFileSync(join(target, "vigolium-results", "audit-state.json"), "utf8"));
    expect(state.audits).toHaveLength(2);
  });

  test("successful handoff receives bounded phase-local artifact repair", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-repair-"));

    class RepairingAdapter implements Adapter {
      readonly id = "repairing";
      readonly platform = "claude" as const;
      readonly description = "RepairingAdapter";
      inputs: AdapterRunInput[] = [];
      async probe(): Promise<void> {}
      async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        this.inputs.push(input);
        const attackSurface = join(target, "vigolium-results", "attack-surface");
        if (input.userPrompt.startsWith("Artifact-only repair") && input.userPrompt.includes("L1")) {
          mkdirSync(attackSurface, { recursive: true });
          writeFileSync(
            join(attackSurface, "lite-recon.md"),
            "## Lite Recon\n\nRepaired recon output with sufficient detail.\n",
          );
          writeFileSync(
            join(attackSurface, "unauthenticated-surface.md"),
            "# Unauthenticated Attack Surface\n\nRepaired surface output.\n",
          );
        } else if (input.userPrompt.startsWith("Artifact-only repair") && input.userPrompt.includes("L2")) {
          writeFileSync(
            join(attackSurface, "lite-secrets-scan.md"),
            "## Lite Secrets Scan\n\nNo retained secrets after repair.\n",
          );
        } else if (input.userPrompt.startsWith("Artifact-only repair") && input.userPrompt.includes("L3")) {
          writeFileSync(
            join(attackSurface, "lite-sast-summary.md"),
            "## Lite SAST Summary\n\nNo retained findings after repair.\n",
          );
          const drafts = join(target, "vigolium-results", "findings-draft");
          mkdirSync(drafts, { recursive: true });
          writeFileSync(
            join(drafts, "consolidation-manifest.json"),
            '{"findings":[],"theoretical":[],"dropped":[]}\n',
          );
        }
        yield {
          kind: "finish",
          ok: true,
          result: "done",
          usd: 0.1,
          tokens: { input: 2, output: 1 },
          durationMs: 1,
        };
      }
    }

    const adapter = new RepairingAdapter();
    const handoff = new ClaudeHandoff({
      adapter,
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/repair-plugin",
    });
    const result = await handoff.run();

    expect(result.status).toBe("complete");
    expect(adapter.inputs).toHaveLength(4); // whole mode + one repair for L1/L2/L3
    for (const input of adapter.inputs.slice(1)) {
      expect(input.userPrompt).toStartWith("Artifact-only repair");
      expect(input.userPrompt).not.toContain("COMMAND-DEF BODY");
      expect(input.pluginDir).toBe("/tmp/repair-plugin");
    }
    expect(result.totalTokens).toEqual({ input: 8, output: 4 });
  });

  test("artifact sufficiency recovers a messy terminal adapter failure", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-artifact-recovery-"));

    class ArtifactsThenFailureAdapter implements Adapter {
      readonly id = "artifacts-then-failure";
      readonly platform = "claude" as const;
      readonly description = "ArtifactsThenFailureAdapter";
      async probe(): Promise<void> {}
      async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        writeLiteArtifacts(input.cwd);
        yield {
          kind: "finish",
          ok: false,
          reason: "worker stream closed after writing outputs",
          usd: 0.5,
          tokens: { input: 10, output: 5 },
          durationMs: 1,
        };
      }
    }

    const handoff = new ClaudeHandoff({
      adapter: new ArtifactsThenFailureAdapter(),
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/does-not-matter",
      transientMaxRetries: 0,
      quotaMaxRetries: 0,
    });
    const result = await handoff.run();
    expect(result.status).toBe("complete");
    expect(result.failedPhases).toEqual([]);
    const state = JSON.parse(readFileSync(join(target, "vigolium-results", "audit-state.json"), "utf8"));
    expect(state.audits.at(-1).status).toBe("complete");
  });

  test("stream idle timeout gets transient backoff retry in handoff mode", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-stream-idle-"));

    class StreamIdleThenOkAdapter implements Adapter {
      readonly id = "stream-idle";
      readonly platform = "claude" as const;
      readonly description = "StreamIdleThenOkAdapter";
      runCalls = 0;
      async probe(): Promise<void> {}
      async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        const attempt = this.runCalls++;
        if (attempt === 0) {
          yield { kind: "textDelta", text: "Ideator wrote nothing before stalling. Retrying with tighter scope." };
          yield {
            kind: "error",
            cause: new Error("claude CLI exited 1: API Error: Stream idle timeout - partial response received"),
          };
          return;
        }
        writeLiteArtifacts(input.cwd);
        yield { kind: "finish", ok: true, result: "done", usd: 0, tokens: { input: 0, output: 0 }, durationMs: 1 };
      }
    }

    const adapter = new StreamIdleThenOkAdapter();
    const handoff = new ClaudeHandoff({
      adapter,
      targetDir: target,
      mode: "lite",
      pluginDir: "/tmp/does-not-matter",
      transientMaxRetries: 2,
      transientBackoffMs: 1,
    });

    const texts: string[] = [];
    handoff.on((e: OrchestratorEvent) => {
      if (e.kind === "phaseAdapterEvent" && e.event.kind === "textDelta") texts.push(e.event.text);
    });

    const result = await handoff.run();

    expect(result.status).toBe("complete");
    expect(adapter.runCalls).toBe(2);
    expect(texts.join("")).toContain("transient adapter error — sleeping 1ms before retry 1/2");
  });
});

describe("e2e: codex handoff retry accounting", () => {
  test("accumulates cost and tokens across a failed attempt and its retry", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-codex-retry-"));

    class CodexTransientThenOkAdapter implements Adapter {
      readonly id = "codex-transient";
      readonly platform = "codex" as const;
      readonly description = "CodexTransientThenOkAdapter";
      runCalls = 0;
      async probe(): Promise<void> {}
      async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        if (this.runCalls++ === 0) {
          yield { kind: "error", cause: new Error("HTTP 429 from Codex") };
          yield {
            kind: "finish",
            ok: false,
            reason: "HTTP 429",
            usd: 1.25,
            tokens: { input: 100, output: 20 },
            durationMs: 1,
          };
          return;
        }
        writeLiteArtifacts(input.cwd);
        yield {
          kind: "finish",
          ok: true,
          result: "done",
          usd: 2.5,
          tokens: { input: 80, output: 30 },
          durationMs: 1,
        };
      }
    }

    const adapter = new CodexTransientThenOkAdapter();
    const handoff = new CodexHandoff({
      adapter,
      targetDir: target,
      mode: "lite",
      transientMaxRetries: 1,
      transientBackoffMs: 1,
    });
    const result = await handoff.run();

    expect(result.status).toBe("complete");
    expect(adapter.runCalls).toBe(2);
    expect(result.totalUsd).toBe(3.75);
    expect(result.totalTokens).toEqual({ input: 180, output: 50 });
  });
});
