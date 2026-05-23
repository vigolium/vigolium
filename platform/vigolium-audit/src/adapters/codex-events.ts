import type { ThreadEvent, ThreadItem } from "@openai/codex-sdk";
import type { AdapterEvent } from "./adapter.js";

/**
 * Mutable per-run state for Codex event normalization.
 *
 * Codex emits command output as a growing `aggregated_output` string on
 * item.updated/item.completed. Keeping offsets lets us surface only the new
 * suffix, so long-running Bash commands stream instead of appearing as one
 * huge blob at completion.
 */
export interface CodexNormalizeState {
  commandOutputOffsets: Map<string, number>;
  extraToolCallIds: Set<string>;
  extraToolOutputIds: Set<string>;
  seenSubagentNotifications: Set<string>;
}

export function createCodexNormalizeState(): CodexNormalizeState {
  return {
    commandOutputOffsets: new Map(),
    extraToolCallIds: new Set(),
    extraToolOutputIds: new Set(),
    seenSubagentNotifications: new Set(),
  };
}

/**
 * Normalize a Codex SDK / CLI ThreadEvent into AdapterEvents. Shared by the
 * Codex SDK adapter (`Thread.runStreamed()`) and the Codex CLI adapter
 * (`codex exec --json` JSONL output) since both emit the same wire shape.
 *
 * Codex doesn't expose USD cost; only token counts. `usd` is reported as 0.
 */
export function* normalizeCodexEvent(
  event: ThreadEvent,
  startedAt: number,
  state: CodexNormalizeState = createCodexNormalizeState(),
): Iterable<AdapterEvent> {
  switch (event.type) {
    case "thread.started":
      if (event.thread_id && event.thread_id.length > 0) {
        yield { kind: "session", sessionId: event.thread_id };
      }
      return;
    case "turn.started":
      return;
    case "item.started":
      yield* normalizeStartedItem(event.item, state);
      return;
    case "item.updated":
      yield* normalizeUpdatedItem(event.item, state);
      return;
    case "item.completed":
      yield* normalizeCompletedItem(event.item, state);
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

const EXTRA_CODEX_TOOL_NAMES = new Map<string, string>([
  ["spawn_agent", "SpawnAgent"],
  ["wait_agent", "WaitAgent"],
  ["close_agent", "CloseAgent"],
]);

/**
 * Normalize records from Codex's persisted session JSONL. The public
 * `codex exec --json` stream currently omits multi-agent lifecycle events;
 * the session log preserves them as response_item/function_call records and
 * subagent_notification messages. The CLI adapter tails that file and feeds
 * each record here.
 */
export function* normalizeCodexSessionRecord(
  record: unknown,
  state: CodexNormalizeState,
): Iterable<AdapterEvent> {
  if (!record || typeof record !== "object") return;
  const outer = record as Record<string, unknown>;
  const payload = outer.payload && typeof outer.payload === "object"
    ? outer.payload as Record<string, unknown>
    : outer;

  if (payload.type === "function_call") {
    const name = typeof payload.name === "string" ? payload.name : "";
    const display = EXTRA_CODEX_TOOL_NAMES.get(name);
    if (!display) return;
    const callId = typeof payload.call_id === "string" ? payload.call_id : `${name}:${state.extraToolCallIds.size}`;
    if (state.extraToolCallIds.has(callId)) return;
    state.extraToolCallIds.add(callId);
    yield {
      kind: "toolCall",
      id: callId,
      tool: display,
      input: parseMaybeJson(payload.arguments),
    };
    return;
  }

  if (payload.type === "function_call_output") {
    const callId = typeof payload.call_id === "string" ? payload.call_id : "";
    if (!state.extraToolCallIds.has(callId)) return;
    if (state.extraToolOutputIds.has(callId)) return;
    state.extraToolOutputIds.add(callId);
    yield {
      kind: "toolResult",
      id: callId,
      output: parseMaybeJson(payload.output),
      isError: false,
    };
    return;
  }

  if (payload.type === "message" && payload.role === "user") {
    const text = extractMessageText(payload.content);
    if (!text.includes("<subagent_notification>")) return;
    const parsed = parseSubagentNotification(text);
    if (!parsed) return;
    const key = `${parsed.agentPath}:${parsed.statusText}`;
    if (state.seenSubagentNotifications.has(key)) return;
    state.seenSubagentNotifications.add(key);
    yield {
      kind: "toolResult",
      id: `subagent:${parsed.agentPath}`,
      output: `Subagent ${parsed.agentPath} ${parsed.statusKind}: ${parsed.statusText}`,
      isError: parsed.statusKind !== "completed",
    };
  }
}

function* normalizeStartedItem(item: ThreadItem, state: CodexNormalizeState): Iterable<AdapterEvent> {
  switch (item.type) {
    case "command_execution":
      state.commandOutputOffsets.set(item.id, 0);
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

function* normalizeUpdatedItem(item: ThreadItem, state: CodexNormalizeState): Iterable<AdapterEvent> {
  switch (item.type) {
    case "command_execution": {
      const output = item.aggregated_output ?? "";
      const prev = state.commandOutputOffsets.get(item.id) ?? 0;
      if (output.length > prev) {
        state.commandOutputOffsets.set(item.id, output.length);
        yield {
          kind: "toolResult",
          id: item.id,
          output: output.slice(prev),
          isError: false,
          partial: true,
        };
      }
      return;
    }
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

function* normalizeCompletedItem(item: ThreadItem, state: CodexNormalizeState): Iterable<AdapterEvent> {
  switch (item.type) {
    case "agent_message":
      if (item.text.length > 0) yield { kind: "textDelta", text: item.text };
      return;
    case "reasoning":
      if (item.text.trim().length > 0) yield { kind: "thinking", text: item.text };
      return;
    case "command_execution": {
      const output = item.aggregated_output ?? "";
      const prev = state.commandOutputOffsets.get(item.id) ?? 0;
      const suffix = output.length > prev ? output.slice(prev) : "";
      state.commandOutputOffsets.set(item.id, output.length);
      const isError = item.exit_code !== undefined && item.exit_code !== 0;
      yield {
        kind: "toolResult",
        id: item.id,
        output: suffix || (isError ? `exit code ${item.exit_code}` : ""),
        isError,
      };
      return;
    }
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

function parseMaybeJson(value: unknown): unknown {
  if (typeof value !== "string") return value ?? "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (trimmed[0] !== "{" && trimmed[0] !== "[") return value;
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return value;
  }
}

function extractMessageText(content: unknown): string {
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const block of content) {
    if (block && typeof block === "object") {
      const b = block as Record<string, unknown>;
      if (typeof b.text === "string") parts.push(b.text);
      else if (typeof b.input_text === "string") parts.push(b.input_text);
    }
  }
  return parts.join("\n");
}

function parseSubagentNotification(text: string): { agentPath: string; statusKind: string; statusText: string } | null {
  const match = /<subagent_notification>\s*([\s\S]*?)\s*<\/subagent_notification>/.exec(text);
  if (!match) return null;
  const parsed = parseMaybeJson(match[1]);
  if (!parsed || typeof parsed !== "object") return null;
  const rec = parsed as Record<string, unknown>;
  const agentPath = typeof rec.agent_path === "string" ? rec.agent_path : "unknown";
  const status = rec.status && typeof rec.status === "object" ? rec.status as Record<string, unknown> : {};
  for (const key of ["completed", "failed", "blocked", "cancelled"]) {
    const v = status[key];
    if (typeof v === "string") return { agentPath, statusKind: key, statusText: v };
  }
  return { agentPath, statusKind: "updated", statusText: JSON.stringify(status) };
}
