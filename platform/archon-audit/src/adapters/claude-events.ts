import type { AdapterEvent, RateLimitsSnapshot, RateLimitsWindow } from "./adapter.js";

/**
 * Normalize a Claude Agent SDK message (SDKMessage shape) into AdapterEvents.
 * Shared by both claude-sdk and claude-cli adapters since the SDK and the
 * `claude --print --output-format stream-json` mode emit the same JSON shape.
 */
export function* normalizeClaudeMessage(message: unknown, startedAt: number): Iterable<AdapterEvent> {
  if (!message || typeof message !== "object") return;
  const m = message as Record<string, unknown>;

  // Claude Code surfaces subscriber rate-limit state via two shapes:
  //   1. `type: "rate_limit_event"` with `rate_limit_info: { rateLimitType,
  //      utilization, resetsAt }` — emitted inline during a stream when a
  //      window state changes (allowed → allowed_warning → blocked).
  //   2. Legacy nested `rate_limits` block (older Claude Code releases /
  //      direct Anthropic API responses).
  // Each event typically reports ONE window; the consumer should merge
  // partial snapshots into the cache.
  if (m.type === "rate_limit_event") {
    const partial = parseRateLimitEvent(m);
    if (partial !== null) yield { kind: "rateLimits", data: partial };
    return;
  }
  const rl = findRateLimits(m);
  if (rl !== null) {
    yield { kind: "rateLimits", data: rl };
  }

  if (m.type === "system" && m.subtype === "init") {
    if (typeof m.session_id === "string" && m.session_id.length > 0) {
      yield {
        kind: "session",
        sessionId: m.session_id,
        ...(Array.isArray(m.agents) ? { agents: m.agents.filter((x): x is string => typeof x === "string") } : {}),
        ...(Array.isArray(m.slash_commands)
          ? { commands: m.slash_commands.filter((x): x is string => typeof x === "string") }
          : {}),
        ...(Array.isArray(m.skills) ? { skills: m.skills.filter((x): x is string => typeof x === "string") } : {}),
        ...(Array.isArray(m.plugins) ? { plugins: extractPlugins(m.plugins) } : {}),
        ...(typeof m.model === "string" ? { model: m.model } : {}),
        ...(typeof m.permissionMode === "string" ? { permissionMode: m.permissionMode } : {}),
      };
    }
    return;
  }

  if (m.type === "assistant") {
    const inner = (m.message ?? {}) as Record<string, unknown>;
    const content = (inner.content ?? []) as Array<Record<string, unknown>>;
    if (!Array.isArray(content)) return;
    for (const block of content) {
      switch (block.type) {
        case "text":
          if (typeof block.text === "string" && block.text.length > 0) {
            yield { kind: "textDelta", text: block.text };
          }
          break;
        case "thinking":
          if (typeof block.thinking === "string" && block.thinking.trim().length > 0) {
            yield { kind: "thinking", text: block.thinking };
          }
          break;
        case "tool_use":
        case "server_tool_use":
        case "mcp_tool_use":
          yield {
            kind: "toolCall",
            id: String(block.id ?? ""),
            tool: String(block.name ?? "<unknown>"),
            input: block.input ?? {},
          };
          break;
        default:
          break;
      }
    }
    return;
  }

  if (m.type === "user") {
    const inner = (m.message ?? {}) as Record<string, unknown>;
    const content = (inner.content ?? []) as Array<Record<string, unknown>>;
    if (!Array.isArray(content)) return;
    for (const block of content) {
      if (block.type === "tool_result") {
        yield {
          kind: "toolResult",
          id: String(block.tool_use_id ?? ""),
          output: block.content ?? "",
          isError: Boolean(block.is_error),
        };
      }
    }
    return;
  }

  if (m.type === "result") {
    const usage = (m.usage ?? {}) as Record<string, unknown>;
    // Claude reports cache reads/writes as separate fields; rolling them into
    // input keeps long-running audits (where most input is cached context)
    // from looking like they barely used the model.
    const tokens = {
      input:
        numberOf(usage.input_tokens) +
        numberOf(usage.cache_read_input_tokens) +
        numberOf(usage.cache_creation_input_tokens),
      output: numberOf(usage.output_tokens),
    };
    const usd = numberOf(m.total_cost_usd);
    const durationMs = numberOf(m.duration_ms) || Date.now() - startedAt;
    if (m.subtype === "success") {
      yield {
        kind: "finish",
        ok: true,
        result: typeof m.result === "string" ? m.result : "",
        usd,
        tokens,
        durationMs,
      };
    } else {
      yield {
        kind: "finish",
        ok: false,
        reason: `${m.subtype ?? "unknown"}${Array.isArray(m.errors) && m.errors.length ? `: ${m.errors.join("; ")}` : ""}`,
        usd,
        tokens,
        durationMs,
      };
    }
  }
}

function numberOf(x: unknown): number {
  return typeof x === "number" && Number.isFinite(x) ? x : 0;
}

/**
 * Parse a `type: "rate_limit_event"` Claude Code stream-json message into
 * a partial RateLimitsSnapshot (covering one window). Returns null when the
 * shape doesn't match. The wire format uses camelCase keys (`resetsAt`,
 * `rateLimitType`) and `utilization` as a 0-1 decimal, which we convert to
 * the snapshot's `resets_at` + `used_percentage` (0-100) conventions.
 */
export function parseRateLimitEvent(m: Record<string, unknown>): RateLimitsSnapshot | null {
  const info = m.rate_limit_info as Record<string, unknown> | undefined;
  if (info === undefined || info === null || typeof info !== "object") return null;
  const kind = typeof info.rateLimitType === "string" ? info.rateLimitType : null;
  const util = typeof info.utilization === "number" ? info.utilization : null;
  const resetsAt = typeof info.resetsAt === "number" ? info.resetsAt : null;
  if (kind === null || util === null || resetsAt === null) return null;
  const win: RateLimitsWindow = { used_percentage: util * 100, resets_at: resetsAt };
  switch (kind) {
    case "five_hour":
      return { five_hour: win };
    case "seven_day":
      return { seven_day: win };
    case "seven_day_opus":
      return { seven_day_opus: win };
    case "seven_day_sonnet":
      return { seven_day_sonnet: win };
    default:
      return null;
  }
}

/**
 * Recursively scan an object for a `rate_limits` key whose value parses as
 * a RateLimitsSnapshot (at least one of the expected windows present).
 * Returns null when no such block is found.
 */
export function findRateLimits(obj: unknown): RateLimitsSnapshot | null {
  if (obj === null || typeof obj !== "object") return null;
  const stack: unknown[] = [obj];
  while (stack.length > 0) {
    const cur = stack.pop();
    if (cur === null || typeof cur !== "object") continue;
    if (Array.isArray(cur)) {
      for (const item of cur) stack.push(item);
      continue;
    }
    const rec = cur as Record<string, unknown>;
    if ("rate_limits" in rec) {
      const parsed = parseRateLimits(rec.rate_limits);
      if (parsed !== null) return parsed;
    }
    for (const v of Object.values(rec)) {
      if (v !== null && typeof v === "object") stack.push(v);
    }
  }
  return null;
}

function parseRateLimits(raw: unknown): RateLimitsSnapshot | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const snap: RateLimitsSnapshot = {};
  const fiveHour = parseWindow(r.five_hour);
  const sevenDay = parseWindow(r.seven_day);
  const opus = parseWindow(r.seven_day_opus);
  const sonnet = parseWindow(r.seven_day_sonnet);
  if (fiveHour !== null) snap.five_hour = fiveHour;
  if (sevenDay !== null) snap.seven_day = sevenDay;
  if (opus !== null) snap.seven_day_opus = opus;
  if (sonnet !== null) snap.seven_day_sonnet = sonnet;
  return Object.keys(snap).length === 0 ? null : snap;
}

function parseWindow(raw: unknown): RateLimitsWindow | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const used = typeof r.used_percentage === "number" ? r.used_percentage : null;
  const resets = typeof r.resets_at === "number" ? r.resets_at : null;
  if (used === null || resets === null) return null;
  return { used_percentage: used, resets_at: resets };
}

function extractPlugins(raw: unknown): { name: string; path: string }[] {
  if (!Array.isArray(raw)) return [];
  const out: { name: string; path: string }[] = [];
  for (const entry of raw) {
    if (entry && typeof entry === "object") {
      const e = entry as Record<string, unknown>;
      if (typeof e.name === "string" && typeof e.path === "string") {
        out.push({ name: e.name, path: e.path });
      }
    }
  }
  return out;
}

export function isTransientError(err: unknown): boolean {
  if (!err) return false;
  if (typeof err === "string") return isRetryableAdapterErrorMessage(err);
  if (typeof err !== "object") return false;
  const status = (err as Record<string, unknown>).status;
  if (typeof status === "number" && (status === 429 || status >= 500)) return true;
  const code = (err as Record<string, unknown>).code;
  if (typeof code === "string" && /ECONN|ETIMEDOUT|ENETUNREACH|EAI_AGAIN/.test(code)) return true;
  return valueContainsRetryableAdapterError(err);
}

/**
 * Retryable Claude/transport failures that often arrive only as plain text in
 * `claude` CLI stderr (wrapped as `claude CLI exited 1: ...`) rather than as a
 * structured status/code. These are distinct from subscription quota notices:
 * callers should prefer the quota path when both are present.
 */
export function isRetryableAdapterErrorMessage(text: unknown): boolean {
  if (typeof text !== "string" || text.length === 0) return false;
  return (
    /\bAPI\s+Error:\s*Stream\s+idle\s+timeout\b/i.test(text) ||
    /\bStream\s+idle\s+timeout\b/i.test(text) ||
    /\bpartial\s+response\s+received\b/i.test(text) ||
    /\bstream(?:ing)?\b.{0,80}\b(?:timed?\s*out|timeout)\b/i.test(text) ||
    /\brequest\b.{0,40}\b(?:timed?\s*out|timeout)\b/i.test(text) ||
    /\bsocket\s+hang\s+up\b/i.test(text) ||
    /\b(?:ECONNRESET|ETIMEDOUT|EAI_AGAIN|ENETUNREACH)\b/i.test(text) ||
    /\b(?:temporarily\s+unavailable|overloaded|bad\s+gateway|service\s+unavailable|gateway\s+timeout)\b/i.test(text) ||
    /\b(?:HTTP|status(?:\s+code)?|response(?:\s+status)?|API\s+Error:)\s*(?:429|500|502|503|504|529)\b/i.test(text) ||
    /\b(?:429\s+Too\s+Many\s+Requests|5\d\d\s+(?:Bad\s+Gateway|Service\s+Unavailable|Gateway\s+Timeout))\b/i.test(text)
  );
}

/**
 * Detects Claude Code's usage-limit / quota-reached notice. Claude prints the
 * message as an assistant text block (e.g. "You've hit your limit · resets 4am
 * (Asia/Singapore)") then the CLI exits non-zero — so the orchestrator has to
 * scan the streamed text, not just stderr or the error object, to catch it.
 *
 * Patterns intentionally loose: the exact wording has drifted between Claude
 * Code releases ("hit your limit", "usage limit reached", "5-hour limit", "your
 * Claude usage limit will reset at …"). False positives are cheap (we sleep
 * and retry); false negatives are expensive (we burn the short exponential
 * backoff and give up).
 *
 * Apostrophe matches both ASCII `'` and Unicode `‘`/`’` — Claude
 * Code's renderer emits the curly quote variant, which the old ASCII-only
 * pattern silently missed.
 */
export function isQuotaLimitMessage(text: unknown): boolean {
  if (typeof text !== "string" || text.length === 0) return false;
  return (
    /you[‘’']?ve\s+hit\s+your\s+(usage\s+)?limit/i.test(text) ||
    /you\s+have\s+hit\s+your\s+(usage\s+)?limit/i.test(text) ||
    /usage\s+limit\s+(reached|exceeded)/i.test(text) ||
    /\b\d+\s*-?\s*hour\s+limit\b/i.test(text) ||
    /\b(weekly|daily)\s+limit\b/i.test(text) ||
    /(claude\s+)?(usage\s+)?limit\s+will\s+reset/i.test(text) ||
    // "limit · resets 6:20am" / "limit resets at 4am" / "limit resets in 30m"
    // — allow any non-letter run between "limit" and "resets" so middle-dots,
    // hyphens, JSON punctuation, or extra spaces don't break the match.
    /\blimit\b[^a-z\n]{0,16}resets?\b/i.test(text)
  );
}

export function adapterEventHasQuotaLimit(event: AdapterEvent): boolean {
  switch (event.kind) {
    case "textDelta":
    case "thinking":
      return valueContainsQuotaLimit(event.text);
    case "toolResult":
      return valueContainsQuotaLimit(event.output);
    case "finish":
      return event.ok ? valueContainsQuotaLimit(event.result) : valueContainsQuotaLimit(event.reason);
    case "error":
      return valueContainsQuotaLimit(event.cause);
    default:
      return false;
  }
}

export function adapterEventHasRetryableError(event: AdapterEvent): boolean {
  switch (event.kind) {
    case "textDelta":
    case "thinking":
      return valueContainsRetryableAdapterError(event.text);
    case "toolResult":
      return valueContainsRetryableAdapterError(event.output);
    case "finish":
      return event.ok ? false : valueContainsRetryableAdapterError(event.reason);
    case "error":
      return isTransientError(event.cause) || valueContainsRetryableAdapterError(event.cause);
    default:
      return false;
  }
}

export function valueContainsQuotaLimit(value: unknown): boolean {
  return valueContainsMatchingText(value, isQuotaLimitMessage);
}

export function valueContainsRetryableAdapterError(value: unknown): boolean {
  return valueContainsMatchingText(value, isRetryableAdapterErrorMessage);
}

export function quotaResetDelayMs(value: unknown, now: Date = new Date(), bufferMs = 60_000): number | null {
  let best: number | null = null;
  visitText(value, (text) => {
    if (!isQuotaLimitMessage(text)) return false;
    const parsed = parseQuotaResetDelayMs(text, now, bufferMs);
    if (parsed === null) return false;
    if (best === null || parsed < best) best = parsed;
    return false;
  });
  return best;
}

function valueContainsMatchingText(value: unknown, matcher: (text: string) => boolean): boolean {
  let found = false;
  visitText(value, (text) => {
    if (matcher(text)) {
      found = true;
      return true;
    }
    return false;
  });
  return found;
}

function visitText(value: unknown, visitor: (text: string) => boolean): boolean {
  const seen = new WeakSet<object>();
  let stringsSeen = 0;
  const maxStrings = 512;
  const maxDepth = 8;

  const visit = (v: unknown, depth: number): boolean => {
    if (stringsSeen >= maxStrings || depth > maxDepth) return false;
    if (typeof v === "string") {
      stringsSeen++;
      if (visitor(v)) return true;
      const trimmed = v.trim();
      if (trimmed.length >= 2 && trimmed.length <= 250_000 && (trimmed[0] === "{" || trimmed[0] === "[")) {
        try {
          if (visit(JSON.parse(trimmed), depth + 1)) return true;
        } catch {
          /* not JSON; raw string was already scanned */
        }
      }
      return false;
    }
    if (v === null || v === undefined || typeof v !== "object") return false;
    if (seen.has(v)) return false;
    seen.add(v);

    if (v instanceof Error) {
      if (visit(v.message, depth + 1)) return true;
      if (visit(v.stack, depth + 1)) return true;
      const maybeCause = (v as Error & { cause?: unknown }).cause;
      if (visit(maybeCause, depth + 1)) return true;
    }

    if (Array.isArray(v)) {
      for (const item of v) {
        if (visit(item, depth + 1)) return true;
      }
      return false;
    }

    for (const val of Object.values(v as Record<string, unknown>)) {
      if (visit(val, depth + 1)) return true;
    }
    return false;
  };

  return visit(value, 0);
}

function parseQuotaResetDelayMs(text: string, now: Date, bufferMs: number): number | null {
  const relative = /resets?\s+in\s+(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours)\b/i.exec(text);
  if (relative) {
    const amount = Number(relative[1]);
    const unit = relative[2]!.toLowerCase();
    if (Number.isFinite(amount) && amount >= 0) {
      const unitMs = unit.startsWith("h") ? 60 * 60 * 1000 : 60 * 1000;
      return amount * unitMs + bufferMs;
    }
  }

  const absolute = /resets?(?:\s+at)?\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b(?:\s*\(([^)]+)\))?/i.exec(text);
  if (!absolute) return null;
  let hour = Number(absolute[1]);
  const minute = absolute[2] !== undefined ? Number(absolute[2]) : 0;
  const meridiem = absolute[3]?.toLowerCase();
  const timeZone = absolute[4];
  if (!Number.isFinite(hour) || !Number.isFinite(minute) || minute < 0 || minute > 59) return null;
  if (meridiem) {
    if (hour < 1 || hour > 12) return null;
    if (meridiem === "am") hour = hour === 12 ? 0 : hour;
    else hour = hour === 12 ? 12 : hour + 12;
  } else if (hour > 23) {
    return null;
  }

  const targetMs = timeZone && isLikelyIanaTimeZone(timeZone)
    ? nextZonedWallClockMs(now, timeZone, hour, minute)
    : nextLocalWallClockMs(now, hour, minute);
  if (targetMs === null) return null;
  return Math.max(0, targetMs - now.getTime() + bufferMs);
}

function nextLocalWallClockMs(now: Date, hour: number, minute: number): number {
  const target = new Date(now);
  target.setHours(hour, minute, 0, 0);
  if (target.getTime() <= now.getTime()) target.setDate(target.getDate() + 1);
  return target.getTime();
}

function isLikelyIanaTimeZone(tz: string): boolean {
  return /^[A-Za-z_]+\/[A-Za-z0-9_+\-/]+$/.test(tz);
}

function nextZonedWallClockMs(now: Date, timeZone: string, hour: number, minute: number): number | null {
  try {
    const parts = zonedParts(now.getTime(), timeZone);
    let target = zonedWallClockToEpochMs(timeZone, parts.year, parts.month, parts.day, hour, minute);
    if (target <= now.getTime()) {
      const tomorrowUtc = Date.UTC(parts.year, parts.month - 1, parts.day + 1, 12, 0, 0);
      const tomorrow = zonedParts(tomorrowUtc, timeZone);
      target = zonedWallClockToEpochMs(timeZone, tomorrow.year, tomorrow.month, tomorrow.day, hour, minute);
    }
    return target;
  } catch {
    return null;
  }
}

function zonedWallClockToEpochMs(timeZone: string, year: number, month: number, day: number, hour: number, minute: number): number {
  const utcGuess = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  const atGuess = zonedParts(utcGuess, timeZone);
  const asIfUtc = Date.UTC(atGuess.year, atGuess.month - 1, atGuess.day, atGuess.hour, atGuess.minute, atGuess.second, 0);
  const offsetMs = asIfUtc - utcGuess;
  return Date.UTC(year, month - 1, day, hour, minute, 0, 0) - offsetMs;
}

function zonedParts(epochMs: number, timeZone: string): { year: number; month: number; day: number; hour: number; minute: number; second: number } {
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour12: false,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const out: Record<string, number> = {};
  for (const part of fmt.formatToParts(new Date(epochMs))) {
    if (part.type !== "literal") out[part.type] = Number(part.value);
  }
  return {
    year: out.year ?? 1970,
    month: out.month ?? 1,
    day: out.day ?? 1,
    hour: out.hour ?? 0,
    minute: out.minute ?? 0,
    second: out.second ?? 0,
  };
}
