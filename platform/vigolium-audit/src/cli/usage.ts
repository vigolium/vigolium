import { readdir, readFile, stat } from "fs/promises";
import { existsSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { round2 } from "../engine/util.js";
import {
  readCache as readRateLimitsCache,
  writeCache as writeRateLimitsCache,
  ageMs,
  formatResetsIn,
} from "../engine/rate-limits-cache.js";
import type { RateLimitsSnapshot } from "../adapters/adapter.js";

/**
 * Per-model pricing in USD per *million* tokens. Source: Anthropic public
 * pricing as of 2026-01. These will drift; treat the resulting USD numbers
 * as estimates, not invoices. Subscription users (Pro / Max / Team) don't
 * actually pay these rates — the dollar figure here is what equivalent API
 * usage would cost, useful for comparing run-to-run intensity.
 */
export interface ModelPricing {
  inputPerMTok: number;
  outputPerMTok: number;
  cacheReadPerMTok: number;
  cacheWrite5mPerMTok: number;
  cacheWrite1hPerMTok: number;
}

const OPUS: ModelPricing = {
  inputPerMTok: 15,
  outputPerMTok: 75,
  cacheReadPerMTok: 1.5,
  cacheWrite5mPerMTok: 18.75,
  cacheWrite1hPerMTok: 30,
};

const SONNET: ModelPricing = {
  inputPerMTok: 3,
  outputPerMTok: 15,
  cacheReadPerMTok: 0.3,
  cacheWrite5mPerMTok: 3.75,
  cacheWrite1hPerMTok: 6,
};

const HAIKU: ModelPricing = {
  inputPerMTok: 1,
  outputPerMTok: 5,
  cacheReadPerMTok: 0.1,
  cacheWrite5mPerMTok: 1.25,
  cacheWrite1hPerMTok: 2,
};

export function pricingFor(model: string): ModelPricing | null {
  const m = model.toLowerCase();
  if (m.includes("opus")) return OPUS;
  if (m.includes("sonnet")) return SONNET;
  if (m.includes("haiku")) return HAIKU;
  return null;
}

export interface TokenBreakdown {
  input: number;
  output: number;
  cacheRead: number;
  cacheCreate5m: number;
  cacheCreate1h: number;
}

export function emptyTokens(): TokenBreakdown {
  return { input: 0, output: 0, cacheRead: 0, cacheCreate5m: 0, cacheCreate1h: 0 };
}

export function addTokens(a: TokenBreakdown, b: TokenBreakdown): TokenBreakdown {
  return {
    input: a.input + b.input,
    output: a.output + b.output,
    cacheRead: a.cacheRead + b.cacheRead,
    cacheCreate5m: a.cacheCreate5m + b.cacheCreate5m,
    cacheCreate1h: a.cacheCreate1h + b.cacheCreate1h,
  };
}

export function costFor(tokens: TokenBreakdown, pricing: ModelPricing): number {
  const M = 1_000_000;
  return (
    (tokens.input / M) * pricing.inputPerMTok +
    (tokens.output / M) * pricing.outputPerMTok +
    (tokens.cacheRead / M) * pricing.cacheReadPerMTok +
    (tokens.cacheCreate5m / M) * pricing.cacheWrite5mPerMTok +
    (tokens.cacheCreate1h / M) * pricing.cacheWrite1hPerMTok
  );
}

export interface UsageEntry {
  timestamp: Date;
  model: string;
  tokens: TokenBreakdown;
  sessionId: string | undefined;
  /** message.id from the Claude API response — used for dedup across replayed jsonl lines. */
  messageId: string | undefined;
}

/**
 * Default Claude Code project log dir. Override with CLAUDE_PROJECTS_DIR
 * (mainly for tests).
 */
export function claudeProjectsDir(): string {
  return process.env.CLAUDE_PROJECTS_DIR ?? join(homedir(), ".claude", "projects");
}

/**
 * Walk ~/.claude/projects/**\/*.jsonl, parse each line, return assistant
 * messages with token usage. Deduped by message.id so a session that was
 * resumed (and rewrote earlier turns into a new jsonl) doesn't double-count.
 */
export async function loadUsageEntries(opts: { since?: Date; projectsDir?: string } = {}): Promise<UsageEntry[]> {
  const root = opts.projectsDir ?? claudeProjectsDir();
  if (!existsSync(root)) return [];

  const files: string[] = [];
  await collectJsonl(root, files);
  const seen = new Set<string>();
  const out: UsageEntry[] = [];

  for (const f of files) {
    let raw: string;
    try {
      raw = await readFile(f, "utf8");
    } catch {
      continue;
    }
    for (const line of raw.split("\n")) {
      if (line.length === 0) continue;
      const entry = parseEntry(line);
      if (entry === null) continue;
      if (opts.since !== undefined && entry.timestamp < opts.since) continue;
      if (entry.messageId !== undefined) {
        if (seen.has(entry.messageId)) continue;
        seen.add(entry.messageId);
      }
      out.push(entry);
    }
  }
  out.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  return out;
}

async function collectJsonl(dir: string, out: string[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      await collectJsonl(full, out);
    } else if (e.isFile() && e.name.endsWith(".jsonl")) {
      out.push(full);
    }
  }
}

function parseEntry(line: string): UsageEntry | null {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(line);
  } catch {
    return null;
  }
  if (obj.type !== "assistant") return null;
  const message = obj.message as Record<string, unknown> | undefined;
  if (!message || typeof message !== "object") return null;
  const usage = message.usage as Record<string, unknown> | undefined;
  if (!usage || typeof usage !== "object") return null;

  const ts = typeof obj.timestamp === "string" ? new Date(obj.timestamp) : null;
  if (ts === null || Number.isNaN(ts.getTime())) return null;
  const model = typeof message.model === "string" ? message.model : "unknown";

  const cacheCreation = usage.cache_creation as Record<string, unknown> | undefined;
  const tokens: TokenBreakdown = {
    input: num(usage.input_tokens),
    output: num(usage.output_tokens),
    cacheRead: num(usage.cache_read_input_tokens),
    cacheCreate5m: num(cacheCreation?.ephemeral_5m_input_tokens),
    cacheCreate1h: num(cacheCreation?.ephemeral_1h_input_tokens),
  };
  // If cache_creation breakdown is missing but cache_creation_input_tokens is
  // present, fall back to lumping it all under the 5m tier (the default TTL).
  if (
    tokens.cacheCreate5m === 0 &&
    tokens.cacheCreate1h === 0 &&
    typeof usage.cache_creation_input_tokens === "number"
  ) {
    tokens.cacheCreate5m = usage.cache_creation_input_tokens;
  }

  return {
    timestamp: ts,
    model,
    tokens,
    sessionId: typeof obj.sessionId === "string" ? obj.sessionId : undefined,
    messageId: typeof message.id === "string" ? message.id : undefined,
  };
}

function num(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

export interface WindowAggregate {
  tokens: TokenBreakdown;
  usd: number;
  /** Per-model breakdown (sorted desc by usd). */
  byModel: Array<{ model: string; tokens: TokenBreakdown; usd: number; pricingKnown: boolean }>;
  /** Number of distinct message.id values aggregated. */
  count: number;
}

export function aggregate(entries: UsageEntry[]): WindowAggregate {
  let usd = 0;
  let totalTokens = emptyTokens();
  const perModel = new Map<string, { tokens: TokenBreakdown; usd: number; pricingKnown: boolean }>();
  for (const e of entries) {
    const pricing = pricingFor(e.model);
    const c = pricing !== null ? costFor(e.tokens, pricing) : 0;
    usd += c;
    totalTokens = addTokens(totalTokens, e.tokens);
    const existing = perModel.get(e.model) ?? { tokens: emptyTokens(), usd: 0, pricingKnown: pricing !== null };
    existing.tokens = addTokens(existing.tokens, e.tokens);
    existing.usd += c;
    existing.pricingKnown = existing.pricingKnown && pricing !== null;
    perModel.set(e.model, existing);
  }
  const byModel = [...perModel.entries()]
    .map(([model, v]) => ({ model, ...v, usd: round2(v.usd) }))
    .sort((a, b) => b.usd - a.usd);
  return {
    tokens: totalTokens,
    usd: round2(usd),
    byModel,
    count: entries.length,
  };
}

export interface UsageSummary {
  total: WindowAggregate;
  windows: Record<string, WindowAggregate>;
  /** Most-recent timestamp in the dataset (or null when empty). */
  newestTimestamp: Date | null;
}

/**
 * Aggregate entries into pre-named time windows: last 24h, last 7 days,
 * last 30 days, and all-time total. Pass `now` for deterministic tests.
 */
export function summarize(entries: UsageEntry[], now: Date = new Date()): UsageSummary {
  const dayMs = 24 * 60 * 60 * 1000;
  const cutoffs: Record<string, Date> = {
    "24h": new Date(now.getTime() - dayMs),
    "7d": new Date(now.getTime() - 7 * dayMs),
    "30d": new Date(now.getTime() - 30 * dayMs),
  };
  const windows: Record<string, WindowAggregate> = {};
  for (const [name, cutoff] of Object.entries(cutoffs)) {
    windows[name] = aggregate(entries.filter((e) => e.timestamp >= cutoff));
  }
  const total = aggregate(entries);
  const newestTimestamp = entries.length > 0 ? (entries[entries.length - 1]?.timestamp ?? null) : null;
  return { total, windows, newestTimestamp };
}

/**
 * Parse a since-spec like "24h", "7d", "30d", "all" into a Date cutoff (or
 * undefined for "all"). Throws on garbage input.
 */
export function parseSince(spec: string, now: Date = new Date()): Date | undefined {
  if (spec === "all") return undefined;
  const m = /^(\d+)([hdwm])$/.exec(spec);
  if (m === null) {
    throw new Error(`--since must be like "24h", "7d", "4w", "3m", or "all" (got "${spec}")`);
  }
  const n = parseInt(m[1]!, 10);
  const unit = m[2]!;
  const hourMs = 60 * 60 * 1000;
  const multipliers: Record<string, number> = {
    h: hourMs,
    d: 24 * hourMs,
    w: 7 * 24 * hourMs,
    m: 30 * 24 * hourMs,
  };
  return new Date(now.getTime() - n * multipliers[unit]!);
}

/**
 * Send a minimal "ping" prompt to Claude and harvest the `rate_limits` block
 * from the response. Cost is a handful of tokens against claude-haiku.
 * Returns null when:
 *  - no `claude` binary is installed
 *  - the user is on API-key auth (Anthropic doesn't include `rate_limits` for
 *    non-subscribers)
 *  - the probe finishes but no rateLimits event arrives
 */
export async function probeQuota(opts: { debug?: boolean } = {}): Promise<RateLimitsSnapshot | null> {
  const { chooseAdapter } = await import("../adapters/detect.js");
  const { ClaudeCliAdapter } = await import("../adapters/claude-cli.js");
  const { ClaudeSdkAdapter } = await import("../adapters/claude-sdk.js");
  const choice = chooseAdapter("claude");
  if (choice.binaryPath === null) {
    throw new Error(
      "no `claude` binary found. Install via `npm i -g @anthropic-ai/claude-code` or set VIGOLIUM_AUDIT_CLAUDE_PATH.",
    );
  }
  const adapter =
    choice.flavor === "cli"
      ? new ClaudeCliAdapter({ pathToClaudeCodeExecutable: choice.binaryPath, defaultModel: "haiku" })
      : new ClaudeSdkAdapter({ pathToClaudeCodeExecutable: choice.binaryPath, defaultModel: "haiku" });

  let snapshot: RateLimitsSnapshot | null = null;
  let lastError: Error | null = null;
  for await (const ev of adapter.run({
    systemPrompt: "Reply with exactly: pong",
    userPrompt: "ping",
    maxTurns: 1,
    tools: [],
    model: "haiku",
  })) {
    if (ev.kind === "rateLimits") {
      snapshot = ev.data;
    }
    if (ev.kind === "error") {
      lastError = ev.cause;
      break;
    }
    if (ev.kind === "finish") {
      if (!ev.ok) lastError = new Error(`probe finished non-ok: ${ev.reason}`);
      break;
    }
  }
  if (snapshot !== null) return snapshot;
  if (lastError !== null) throw lastError;
  void opts;
  return null;
}

export async function usageCommand(opts: { since?: string; json?: boolean; refresh?: boolean } = {}): Promise<void> {
  const json = !!opts.json;
  const sinceSpec = opts.since ?? "all";
  let cutoff: Date | undefined;
  try {
    cutoff = parseSince(sinceSpec);
  } catch (err) {
    const msg = (err as Error).message;
    if (json) process.stdout.write(JSON.stringify({ kind: "fatal", error: msg }) + "\n");
    else process.stderr.write(`error: ${msg}\n`);
    process.exit(2);
  }
  // Always load everything when `--since=all`; only narrow at load time when
  // the user picks a specific window (avoids the bug where canned windows
  // become meaningless because their data was filtered out at load time).
  const entries = await loadUsageEntries(
    cutoff !== undefined ? { since: cutoff } : {},
  );
  const summary = summarize(entries);
  const projectsDir = claudeProjectsDir();

  // Optional active probe: send a tiny "ping" to Claude and harvest the
  // `rate_limits` block from the response. Burns a handful of haiku tokens
  // (~$0.0001) but gives a real-time snapshot. Updates the on-disk cache.
  if (opts.refresh === true) {
    const chalk = (await import("chalk")).default;
    if (!json) process.stdout.write(chalk.dim("  probing claude for live quota… "));
    try {
      const snap = await probeQuota();
      if (snap !== null) {
        await writeRateLimitsCache(snap);
        if (!json) process.stdout.write(chalk.green("ok\n"));
      } else {
        if (!json) process.stdout.write(chalk.yellow("no rate_limits in response (API-key user?)\n"));
      }
    } catch (err) {
      const msg = (err as Error).message;
      if (json) process.stdout.write(JSON.stringify({ kind: "probeError", error: msg }) + "\n");
      else process.stdout.write(chalk.red(`failed: ${msg}\n`));
    }
  }

  const quota = await readRateLimitsCache();
  if (json) {
    process.stdout.write(
      JSON.stringify({
        kind: "usage",
        projectsDir,
        since: sinceSpec,
        newestTimestamp: summary.newestTimestamp?.toISOString() ?? null,
        total: summary.total,
        ...(cutoff === undefined ? { windows: summary.windows } : {}),
        ...(quota !== null ? { quota } : {}),
      }) + "\n",
    );
    return;
  }
  await printHuman(summary, projectsDir, sinceSpec, cutoff !== undefined, quota);
}

async function printHuman(
  summary: UsageSummary,
  projectsDir: string,
  sinceSpec: string,
  filtered: boolean,
  quota: Awaited<ReturnType<typeof readRateLimitsCache>>,
): Promise<void> {
  const chalk = (await import("chalk")).default;
  const dim = chalk.dim;
  const cyan = chalk.cyan;
  const magenta = chalk.magenta;
  const yellow = chalk.yellow;

  console.log(chalk.bold("vigolium-audit usage") + dim(`   (source: ${projectsDir})`));

  // Subscription quota (from rate_limit_event messages harvested in prior
  // runs or via --refresh). Each window is reported independently by Claude
  // when its state changes — windows we haven't observed yet show "—".
  const ageMin = quota !== null ? Math.round(ageMs(quota) / 60_000) : null;
  const staleNote =
    ageMin === null
      ? ""
      : ageMin > 60
        ? yellow(` stale ${ageMin}m`)
        : dim(` ${ageMin}m ago`);
  console.log("");
  console.log(chalk.bold("  Subscription quota") + dim(":") + staleNote);
  const rows: Array<{ label: string; win?: { used_percentage: number; resets_at: number } | undefined }> = [
    { label: "5-hour ", win: quota?.data.five_hour },
    { label: "7-day  ", win: quota?.data.seven_day },
    { label: "7d opus", win: quota?.data.seven_day_opus },
    { label: "7d sonn", win: quota?.data.seven_day_sonnet },
  ];
  for (const r of rows) {
    if (r.win === undefined) {
      console.log(`    ${cyan(r.label)}  ${dim("—  no recent data")}`);
    } else {
      console.log(
        `    ${cyan(r.label)}  ${magenta(`${r.win.used_percentage.toFixed(1)}%`)} ${dim(`used · resets ${formatResetsIn(r.win.resets_at)}`)}`,
      );
    }
  }
  if (quota === null) {
    console.log(dim("    (run `vigolium-audit usage --refresh` to populate, or wait for `vigolium-audit run` to harvest passively)"));
  }
  console.log("");

  if (summary.total.count === 0) {
    const hint = filtered
      ? `no Claude Code activity in the last ${sinceSpec}.`
      : "no Claude Code session logs found — run claude at least once first.";
    console.log(dim(`  ${hint}`));
    return;
  }
  console.log(dim(`  newest entry: ${summary.newestTimestamp?.toISOString() ?? "?"}`));
  console.log("");
  // When --since=all, show the canned 24h / 7d / 30d / all-time windows.
  // When --since=<spec>, just show one row scoped to that window.
  const usageRows: Array<{ label: string; agg: WindowAggregate }> = filtered
    ? [{ label: `Since ${sinceSpec.padEnd(4)}`, agg: summary.total }]
    : [
        { label: "Last 24h ", agg: summary.windows["24h"]! },
        { label: "Last 7d  ", agg: summary.windows["7d"]! },
        { label: "Last 30d ", agg: summary.windows["30d"]! },
        { label: "All time ", agg: summary.total },
      ];
  for (const row of usageRows) {
    console.log(
      `  ${cyan(row.label)}  ` +
        `${dim("in")} ${fmtTok(row.agg.tokens.input)}  ` +
        `${dim("out")} ${fmtTok(row.agg.tokens.output)}  ` +
        `${dim("cache_r")} ${fmtTok(row.agg.tokens.cacheRead)}  ` +
        `${dim("→")} ${magenta(`~$${row.agg.usd.toFixed(2)}`)}  ` +
        dim(`(${row.agg.count} msg)`),
    );
  }
  console.log("");
  console.log(
    dim(
      "  $ figures are estimates from Anthropic public pricing. Subscription users (Pro/Max/Team) " +
        "don't pay these rates — treat as 'what API-equivalent usage would cost'.",
    ),
  );
}

function fmtTok(n: number): string {
  if (n < 1_000) return String(n);
  if (n < 1_000_000) return `${(n / 1_000).toFixed(0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
