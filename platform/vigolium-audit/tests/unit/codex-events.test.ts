import { describe, expect, test } from "bun:test";
import { normalizeCodexEvent } from "../../src/adapters/codex-events.js";
import type { AdapterEvent } from "../../src/adapters/adapter.js";
import type { ThreadEvent } from "@openai/codex-sdk";

function collect(events: ThreadEvent[]): AdapterEvent[] {
  const out: AdapterEvent[] = [];
  const startedAt = Date.now();
  for (const e of events) {
    for (const a of normalizeCodexEvent(e, startedAt)) out.push(a);
  }
  return out;
}

describe("normalizeCodexEvent (Codex SDK / CLI ThreadEvent shape)", () => {
  test("agent_message item.completed → textDelta", () => {
    const events = collect([
      { type: "thread.started", thread_id: "t-1" },
      { type: "turn.started" },
      {
        type: "item.completed",
        item: { id: "i-1", type: "agent_message", text: "Pong" },
      },
      {
        type: "turn.completed",
        usage: {
          input_tokens: 5,
          cached_input_tokens: 0,
          output_tokens: 1,
          reasoning_output_tokens: 0,
        },
      },
    ]);
    expect(events.length).toBe(3);
    expect(events[0]).toEqual({ kind: "session", sessionId: "t-1" });
    expect(events[1]).toEqual({ kind: "textDelta", text: "Pong" });
    expect(events[2]?.kind).toBe("finish");
    if (events[2]?.kind !== "finish" || !events[2].ok) throw new Error("type narrowing");
    expect(events[2].tokens).toEqual({ input: 5, output: 1 });
  });

  test("command_execution start → toolCall, complete → toolResult with exit_code", () => {
    const events = collect([
      {
        type: "item.started",
        item: {
          id: "cmd-1",
          type: "command_execution",
          command: "ls -la",
          aggregated_output: "",
          status: "in_progress",
        },
      },
      {
        type: "item.updated",
        item: {
          id: "cmd-1",
          type: "command_execution",
          command: "ls -la",
          aggregated_output: "partial...",
          status: "in_progress",
        },
      },
      {
        type: "item.completed",
        item: {
          id: "cmd-1",
          type: "command_execution",
          command: "ls -la",
          aggregated_output: "file1\nfile2\n",
          exit_code: 0,
          status: "completed",
        },
      },
    ]);
    // item.updated is intentionally dropped to avoid noise.
    expect(events.length).toBe(2);
    expect(events[0]).toEqual({ kind: "toolCall", id: "cmd-1", tool: "Bash", input: { command: "ls -la" } });
    expect(events[1]).toEqual({
      kind: "toolResult",
      id: "cmd-1",
      output: "file1\nfile2\n",
      isError: false,
    });
  });

  test("command_execution non-zero exit_code → toolResult isError=true", () => {
    const events = collect([
      {
        type: "item.completed",
        item: {
          id: "cmd-2",
          type: "command_execution",
          command: "false",
          aggregated_output: "",
          exit_code: 1,
          status: "completed",
        },
      },
    ]);
    expect(events).toHaveLength(1);
    if (events[0]?.kind !== "toolResult") throw new Error("type narrowing");
    expect(events[0].isError).toBe(true);
  });

  test("file_change → Edit toolCall + toolResult with status mapping", () => {
    const events = collect([
      {
        type: "item.started",
        item: {
          id: "fc-1",
          type: "file_change",
          changes: [
            { path: "src/foo.py", kind: "update" },
            { path: "src/bar.py", kind: "add" },
          ],
          status: "completed",
        },
      },
      {
        type: "item.completed",
        item: {
          id: "fc-1",
          type: "file_change",
          changes: [
            { path: "src/foo.py", kind: "update" },
            { path: "src/bar.py", kind: "add" },
          ],
          status: "failed",
        },
      },
    ]);
    expect(events.length).toBe(2);
    expect(events[0]?.kind).toBe("toolCall");
    if (events[0]?.kind !== "toolCall") throw new Error("type narrowing");
    expect(events[0].tool).toBe("Edit");
    if (events[1]?.kind !== "toolResult") throw new Error("type narrowing");
    expect(events[1].isError).toBe(true);
  });

  test("turn.failed → finish ok=false with error message", () => {
    const events = collect([
      {
        type: "turn.failed",
        error: { message: "rate limited" },
      },
    ]);
    expect(events).toHaveLength(1);
    if (events[0]?.kind !== "finish" || events[0].ok !== false) throw new Error("type narrowing");
    expect(events[0].reason).toBe("rate limited");
  });

  test("error event → AdapterEvent error", () => {
    const events = collect([{ type: "error", message: "fatal" }]);
    expect(events).toHaveLength(1);
    if (events[0]?.kind !== "error") throw new Error("type narrowing");
    expect(events[0].cause.message).toBe("fatal");
  });

  test("reasoning item → thinking", () => {
    const events = collect([
      {
        type: "item.completed",
        item: { id: "r-1", type: "reasoning", text: "considering options" },
      },
    ]);
    expect(events).toEqual([{ kind: "thinking", text: "considering options" }]);
  });

  test("web_search → WebSearch toolCall + toolResult", () => {
    const events = collect([
      {
        type: "item.started",
        item: { id: "ws-1", type: "web_search", query: "CVE-2024-12345" },
      },
      {
        type: "item.completed",
        item: { id: "ws-1", type: "web_search", query: "CVE-2024-12345" },
      },
    ]);
    expect(events).toHaveLength(2);
    if (events[0]?.kind !== "toolCall") throw new Error("type narrowing");
    expect(events[0].tool).toBe("WebSearch");
    if (events[1]?.kind !== "toolResult") throw new Error("type narrowing");
    expect(events[1].isError).toBe(false);
  });

  test("todo_list → thinking with [x]/[ ] formatting", () => {
    const events = collect([
      {
        type: "item.completed",
        item: {
          id: "td-1",
          type: "todo_list",
          items: [
            { text: "Read login.py", completed: true },
            { text: "Find auth bypass", completed: false },
          ],
        },
      },
    ]);
    expect(events).toHaveLength(1);
    if (events[0]?.kind !== "thinking") throw new Error("type narrowing");
    expect(events[0].text).toContain("[x] Read login.py");
    expect(events[0].text).toContain("[ ] Find auth bypass");
  });

  test("USD cost is reported as 0 — Codex doesn't expose dollar cost", () => {
    const events = collect([
      {
        type: "turn.completed",
        usage: {
          input_tokens: 1000,
          cached_input_tokens: 0,
          output_tokens: 500,
          reasoning_output_tokens: 0,
        },
      },
    ]);
    if (events[0]?.kind !== "finish") throw new Error("type narrowing");
    expect(events[0].usd).toBe(0);
  });
});
