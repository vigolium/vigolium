import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { ClaudeHandoff } from "../../src/engine/claude-handoff.js";
import type { Adapter, AdapterEvent, AdapterRunInput } from "../../src/adapters/adapter.js";
import type { OrchestratorEvent } from "../../src/engine/events.js";

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

  async *run(_input: AdapterRunInput): AsyncIterable<AdapterEvent> {
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
      async *run(_input: AdapterRunInput): AsyncIterable<AdapterEvent> {
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

  test("stream idle timeout gets transient backoff retry in handoff mode", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-handoff-stream-idle-"));

    class StreamIdleThenOkAdapter implements Adapter {
      readonly id = "stream-idle";
      readonly platform = "claude" as const;
      readonly description = "StreamIdleThenOkAdapter";
      runCalls = 0;
      async probe(): Promise<void> {}
      async *run(_input: AdapterRunInput): AsyncIterable<AdapterEvent> {
        const attempt = this.runCalls++;
        if (attempt === 0) {
          yield { kind: "textDelta", text: "Ideator wrote nothing before stalling. Retrying with tighter scope." };
          yield {
            kind: "error",
            cause: new Error("claude CLI exited 1: API Error: Stream idle timeout - partial response received"),
          };
          return;
        }
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
