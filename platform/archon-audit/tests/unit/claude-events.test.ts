import { describe, expect, test } from "bun:test";
import { adapterEventHasQuotaLimit, adapterEventHasRetryableError, isQuotaLimitMessage, isRetryableAdapterErrorMessage, isTransientError, normalizeClaudeMessage, quotaResetDelayMs, valueContainsQuotaLimit } from "../../src/adapters/claude-events.js";
import type { AdapterEvent } from "../../src/adapters/adapter.js";

function collect(messages: unknown[]): AdapterEvent[] {
  const out: AdapterEvent[] = [];
  const startedAt = Date.now();
  for (const m of messages) {
    for (const e of normalizeClaudeMessage(m, startedAt)) out.push(e);
  }
  return out;
}

describe("normalizeClaudeMessage (Claude SDK / CLI stream-json shape)", () => {
  test("assistant text → textDelta", () => {
    const events = collect([
      {
        type: "assistant",
        message: {
          role: "assistant",
          content: [
            { type: "text", text: "Hello" },
            { type: "text", text: " world" },
          ],
        },
      },
    ]);
    expect(events).toEqual([
      { kind: "textDelta", text: "Hello" },
      { kind: "textDelta", text: " world" },
    ]);
  });

  test("assistant tool_use → toolCall with id/tool/input", () => {
    const events = collect([
      {
        type: "assistant",
        message: {
          content: [
            { type: "tool_use", id: "tu_01", name: "Bash", input: { command: "ls -la" } },
          ],
        },
      },
    ]);
    expect(events).toEqual([
      { kind: "toolCall", id: "tu_01", tool: "Bash", input: { command: "ls -la" } },
    ]);
  });

  test("assistant thinking block → thinking event", () => {
    const events = collect([
      {
        type: "assistant",
        message: {
          content: [{ type: "thinking", thinking: "let me think..." }],
        },
      },
    ]);
    expect(events).toEqual([{ kind: "thinking", text: "let me think..." }]);
  });

  test("user tool_result → toolResult preserving is_error", () => {
    const events = collect([
      {
        type: "user",
        message: {
          content: [
            { type: "tool_result", tool_use_id: "tu_01", content: "ok", is_error: false },
            { type: "tool_result", tool_use_id: "tu_02", content: "boom", is_error: true },
          ],
        },
      },
    ]);
    expect(events).toEqual([
      { kind: "toolResult", id: "tu_01", output: "ok", isError: false },
      { kind: "toolResult", id: "tu_02", output: "boom", isError: true },
    ]);
  });

  test("result success → finish ok with usage + cost", () => {
    const events = collect([
      {
        type: "result",
        subtype: "success",
        result: "Pong",
        total_cost_usd: 0.097,
        usage: { input_tokens: 10, output_tokens: 7 },
        duration_ms: 2400,
      },
    ]);
    expect(events).toHaveLength(1);
    const f = events[0]!;
    expect(f.kind).toBe("finish");
    if (f.kind !== "finish") throw new Error("type narrowing");
    expect(f.ok).toBe(true);
    expect(f.usd).toBe(0.097);
    expect(f.tokens).toEqual({ input: 10, output: 7 });
    expect(f.durationMs).toBe(2400);
  });

  test("result success → input tokens include cache reads + cache creation", () => {
    const events = collect([
      {
        type: "result",
        subtype: "success",
        result: "ok",
        total_cost_usd: 1.23,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
          cache_read_input_tokens: 8000,
          cache_creation_input_tokens: 200,
        },
        duration_ms: 1000,
      },
    ]);
    const f = events[0]!;
    if (f.kind !== "finish") throw new Error("type narrowing");
    expect(f.tokens).toEqual({ input: 8300, output: 50 });
    expect(f.usd).toBe(1.23);
  });

  test("result error subtypes → finish ok=false with reason", () => {
    const events = collect([
      {
        type: "result",
        subtype: "error_max_turns",
        usage: { input_tokens: 100, output_tokens: 5 },
        total_cost_usd: 0.01,
        duration_ms: 500,
        errors: ["hit turn limit"],
      },
    ]);
    expect(events).toHaveLength(1);
    const f = events[0]!;
    if (f.kind !== "finish" || f.ok !== false) throw new Error("type narrowing");
    expect(f.reason).toContain("error_max_turns");
    expect(f.reason).toContain("hit turn limit");
  });

  test("system init with session_id → session event", () => {
    const events = collect([
      { type: "system", subtype: "init", session_id: "sess-abc-123", tools: [] },
    ]);
    expect(events).toEqual([{ kind: "session", sessionId: "sess-abc-123" }]);
  });

  test("system init without session_id → no event", () => {
    const events = collect([{ type: "system", subtype: "init", tools: [] }]);
    expect(events).toEqual([]);
  });

  test("non-recognized message types are dropped silently", () => {
    const events = collect([
      { type: "rate_limit_event", rate_limit_info: { status: "allowed" } },
      { type: "system", subtype: "init", tools: [] },
      null,
      "garbage",
      { type: "assistant", message: { content: [{ type: "text", text: "ok" }] } },
    ]);
    // Only the assistant text comes through.
    expect(events).toEqual([{ kind: "textDelta", text: "ok" }]);
  });

  test("realistic full session — assistant tool call + user result + final result", () => {
    const events = collect([
      { type: "system", subtype: "init", tools: [] },
      {
        type: "assistant",
        message: {
          content: [
            { type: "text", text: "Let me check that file." },
            { type: "tool_use", id: "tu_a", name: "Read", input: { path: "login.py" } },
          ],
        },
      },
      {
        type: "user",
        message: {
          content: [{ type: "tool_result", tool_use_id: "tu_a", content: "def login(u, p): ..." }],
        },
      },
      {
        type: "assistant",
        message: { content: [{ type: "text", text: "Done." }] },
      },
      {
        type: "result",
        subtype: "success",
        result: "Done.",
        total_cost_usd: 0.05,
        usage: { input_tokens: 20, output_tokens: 8 },
        duration_ms: 1200,
      },
    ]);
    const kinds = events.map((e) => e.kind);
    expect(kinds).toEqual(["textDelta", "toolCall", "toolResult", "textDelta", "finish"]);
  });
});

describe("isTransientError", () => {
  test("HTTP 429 → transient", () => {
    expect(isTransientError({ status: 429 })).toBe(true);
  });
  test("HTTP 500 → transient", () => {
    expect(isTransientError({ status: 503 })).toBe(true);
  });
  test("HTTP 400 → not transient", () => {
    expect(isTransientError({ status: 400 })).toBe(false);
  });
  test("ECONNRESET → transient", () => {
    expect(isTransientError({ code: "ECONNRESET" })).toBe(true);
  });
  test("Claude CLI stream idle timeout text → transient", () => {
    const msg = "claude CLI exited 1: API Error: Stream idle timeout - partial response received";
    expect(isRetryableAdapterErrorMessage(msg)).toBe(true);
    expect(isTransientError(new Error(msg))).toBe(true);
  });
  test("ENOTFOUND → not transient (NXDOMAIN-ish)", () => {
    expect(isTransientError({ code: "ENOTFOUND" })).toBe(false);
  });
  test("non-object → not transient", () => {
    expect(isTransientError(null)).toBe(false);
    expect(isTransientError("string")).toBe(false);
    expect(isTransientError(undefined)).toBe(false);
  });
  test("plain numeric snippets are not retryable adapter errors", () => {
    expect(isRetryableAdapterErrorMessage("return 500; // app status code fixture")).toBe(false);
  });
});

describe("isQuotaLimitMessage", () => {
  test("matches the real Claude Code message", () => {
    expect(isQuotaLimitMessage("You've hit your limit · resets 4am (Asia/Singapore)")).toBe(true);
    // Claude Code's renderer emits a Unicode right single quote in "You’ve"
    // and an unprefixed time after "resets" — both forms must match.
    expect(isQuotaLimitMessage("You’ve hit your limit · resets 6:20am (Asia/Singapore)")).toBe(true);
    expect(isQuotaLimitMessage("● You've hit your limit · resets 10:20pm (Asia/Singapore)")).toBe(true);
    expect(isQuotaLimitMessage("[handoff] You've hit your limit · resets 10:20pm (Asia/Singapore)")).toBe(true);
    expect(isQuotaLimitMessage('← [{"type":"text","text":"You\'ve hit your limit · resets 10:20pm (Asia/Singapore)"}]')).toBe(true);
  });
  test("matches variants of the limit phrasing", () => {
    expect(isQuotaLimitMessage("you have hit your usage limit")).toBe(true);
    expect(isQuotaLimitMessage("Your usage limit reached")).toBe(true);
    expect(isQuotaLimitMessage("5-hour limit reached")).toBe(true);
    expect(isQuotaLimitMessage("Weekly limit will reset Sunday")).toBe(true);
    expect(isQuotaLimitMessage("Claude usage limit will reset at 4am")).toBe(true);
    expect(isQuotaLimitMessage("limit resets at 4am")).toBe(true);
    expect(isQuotaLimitMessage("limit · resets 6:20am")).toBe(true);
    expect(isQuotaLimitMessage("limit resets 30m")).toBe(true);
  });

  test("detects quota notices nested inside toolResult content blocks", () => {
    const event: AdapterEvent = {
      kind: "toolResult",
      id: "agent",
      output: [
        { type: "text", text: "You've hit your limit · resets 10:20pm (Asia/Singapore)" },
        { type: "text", text: "agentId: a41fa5" },
      ],
      isError: false,
    };
    expect(adapterEventHasQuotaLimit(event)).toBe(true);
    expect(valueContainsQuotaLimit(event.output)).toBe(true);
  });

  test("extracts reset delays from quota messages", () => {
    const delay = quotaResetDelayMs("You've hit your limit · resets in 30m", new Date("2026-05-19T12:00:00Z"), 0);
    expect(delay).toBe(30 * 60 * 1000);
  });

  test("detects retryable adapter errors in nested toolResult output", () => {
    const event: AdapterEvent = {
      kind: "toolResult",
      id: "agent",
      output: [{ type: "text", text: "API Error: Stream idle timeout - partial response received" }],
      isError: true,
    };
    expect(adapterEventHasRetryableError(event)).toBe(true);
  });

  test("ignores unrelated text", () => {
    expect(isQuotaLimitMessage("the function checks an upper limit on inputs")).toBe(false);
    expect(isQuotaLimitMessage("set a rate limit of 100 req/s")).toBe(false);
    expect(isQuotaLimitMessage("")).toBe(false);
    expect(isQuotaLimitMessage(undefined)).toBe(false);
    expect(isQuotaLimitMessage(null)).toBe(false);
  });
});
