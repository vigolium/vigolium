import type { ThreadEvent, ThreadItem } from "@openai/codex-sdk";
import type { AdapterEvent } from "./adapter.js";

/**
 * Normalize a Codex SDK / CLI ThreadEvent into AdapterEvents. Shared by the
 * Codex SDK adapter (`Thread.runStreamed()`) and the Codex CLI adapter
 * (`codex exec --json` JSONL output) since both emit the same wire shape.
 *
 * Codex doesn't expose USD cost; only token counts. `usd` is reported as 0.
 */
export function* normalizeCodexEvent(event: ThreadEvent, startedAt: number): Iterable<AdapterEvent> {
  switch (event.type) {
    case "thread.started":
      if (event.thread_id && event.thread_id.length > 0) {
        yield { kind: "session", sessionId: event.thread_id };
      }
      return;
    case "turn.started":
      return;
    case "item.started":
      yield* normalizeStartedItem(event.item);
      return;
    case "item.updated":
      // Updates fire frequently for command_execution stdout streaming.
      // We only surface the completed events; updates would create noise.
      return;
    case "item.completed":
      yield* normalizeCompletedItem(event.item);
      return;
    case "turn.completed":
      yield {
        kind: "finish",
        ok: true,
        result: "",
        usd: 0,
        tokens: {
          input: event.usage?.input_tokens ?? 0,
          output: event.usage?.output_tokens ?? 0,
        },
        durationMs: Date.now() - startedAt,
      };
      return;
    case "turn.failed":
      yield {
        kind: "finish",
        ok: false,
        reason: event.error?.message ?? "turn failed",
        usd: 0,
        tokens: { input: 0, output: 0 },
        durationMs: Date.now() - startedAt,
      };
      return;
    case "error":
      yield { kind: "error", cause: new Error(event.message) };
      return;
  }
}

function* normalizeStartedItem(item: ThreadItem): Iterable<AdapterEvent> {
  switch (item.type) {
    case "command_execution":
      yield { kind: "toolCall", id: item.id, tool: "Bash", input: { command: item.command } };
      return;
    case "file_change":
      yield {
        kind: "toolCall",
        id: item.id,
        tool: "Edit",
        input: { changes: item.changes.map((c) => ({ path: c.path, kind: c.kind })) },
      };
      return;
    case "mcp_tool_call":
      yield {
        kind: "toolCall",
        id: item.id,
        tool: `mcp:${item.server}:${item.tool}`,
        input: item.arguments,
      };
      return;
    case "web_search":
      yield { kind: "toolCall", id: item.id, tool: "WebSearch", input: { query: item.query } };
      return;
    default:
      return;
  }
}

function* normalizeCompletedItem(item: ThreadItem): Iterable<AdapterEvent> {
  switch (item.type) {
    case "agent_message":
      if (item.text.length > 0) yield { kind: "textDelta", text: item.text };
      return;
    case "reasoning":
      if (item.text.trim().length > 0) yield { kind: "thinking", text: item.text };
      return;
    case "command_execution":
      yield {
        kind: "toolResult",
        id: item.id,
        output: item.aggregated_output,
        isError: item.exit_code !== undefined && item.exit_code !== 0,
      };
      return;
    case "file_change":
      yield { kind: "toolResult", id: item.id, output: item.changes, isError: item.status === "failed" };
      return;
    case "mcp_tool_call":
      yield {
        kind: "toolResult",
        id: item.id,
        output: item.result?.content ?? item.error?.message ?? "",
        isError: item.status === "failed",
      };
      return;
    case "web_search":
      yield { kind: "toolResult", id: item.id, output: item.query, isError: false };
      return;
    case "error":
      yield { kind: "error", cause: new Error(item.message) };
      return;
    case "todo_list":
      yield {
        kind: "thinking",
        text: item.items.map((t) => `${t.completed ? "[x]" : "[ ]"} ${t.text}`).join("\n"),
      };
      return;
    default:
      return;
  }
}
