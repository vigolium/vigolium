import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  aggregate,
  costFor,
  emptyTokens,
  loadUsageEntries,
  parseSince,
  pricingFor,
  summarize,
  type UsageEntry,
} from "../../src/cli/usage.js";

function mkEntry(opts: { ts: string; model: string; input?: number; output?: number; cacheRead?: number; cacheCreate5m?: number; cacheCreate1h?: number; messageId?: string }): UsageEntry {
  return {
    timestamp: new Date(opts.ts),
    model: opts.model,
    tokens: {
      input: opts.input ?? 0,
      output: opts.output ?? 0,
      cacheRead: opts.cacheRead ?? 0,
      cacheCreate5m: opts.cacheCreate5m ?? 0,
      cacheCreate1h: opts.cacheCreate1h ?? 0,
    },
    sessionId: "s1",
    messageId: opts.messageId,
  };
}

describe("pricingFor", () => {
  test("matches opus / sonnet / haiku by substring", () => {
    expect(pricingFor("claude-opus-4-7")!.inputPerMTok).toBe(15);
    expect(pricingFor("claude-sonnet-4-6")!.inputPerMTok).toBe(3);
    expect(pricingFor("claude-haiku-4-5-20251001")!.inputPerMTok).toBe(1);
  });

  test("returns null for unknown model", () => {
    expect(pricingFor("gpt-4o")).toBeNull();
    expect(pricingFor("unknown")).toBeNull();
  });
});

describe("costFor", () => {
  test("computes from breakdown using per-MTok rates", () => {
    const tokens = { input: 1_000_000, output: 0, cacheRead: 0, cacheCreate5m: 0, cacheCreate1h: 0 };
    expect(costFor(tokens, pricingFor("opus")!)).toBeCloseTo(15, 5);
    const opusBlend = {
      input: 100_000,
      output: 50_000,
      cacheRead: 200_000,
      cacheCreate5m: 30_000,
      cacheCreate1h: 0,
    };
    // 0.1*15 + 0.05*75 + 0.2*1.5 + 0.03*18.75 = 1.5 + 3.75 + 0.3 + 0.5625 = 6.1125
    expect(costFor(opusBlend, pricingFor("opus")!)).toBeCloseTo(6.1125, 4);
  });
});

describe("aggregate", () => {
  test("sums tokens, groups by model, sorts byModel desc by usd", () => {
    const entries: UsageEntry[] = [
      mkEntry({ ts: "2026-01-01T00:00:00Z", model: "claude-sonnet-4-6", input: 1_000_000, output: 100_000 }),
      mkEntry({ ts: "2026-01-02T00:00:00Z", model: "claude-opus-4-7", input: 500_000, output: 100_000 }),
      mkEntry({ ts: "2026-01-03T00:00:00Z", model: "claude-opus-4-7", input: 500_000, output: 200_000 }),
    ];
    const agg = aggregate(entries);
    expect(agg.count).toBe(3);
    expect(agg.tokens.input).toBe(2_000_000);
    expect(agg.tokens.output).toBe(400_000);
    expect(agg.byModel.length).toBe(2);
    // opus = 1M in*$15 + 300k out*$75 = 15 + 22.5 = $37.50
    // sonnet = 1M in*$3 + 100k out*$15 = 3 + 1.5 = $4.50
    expect(agg.byModel[0]!.model).toBe("claude-opus-4-7");
    expect(agg.byModel[0]!.usd).toBeCloseTo(37.5, 2);
    expect(agg.byModel[1]!.usd).toBeCloseTo(4.5, 2);
    expect(agg.usd).toBeCloseTo(42, 1);
  });

  test("handles unknown model: zero $ cost, pricingKnown=false", () => {
    const entries = [mkEntry({ ts: "2026-01-01T00:00:00Z", model: "gpt-unknown", input: 1_000_000 })];
    const agg = aggregate(entries);
    expect(agg.usd).toBe(0);
    expect(agg.byModel[0]!.pricingKnown).toBe(false);
  });
});

describe("summarize windows", () => {
  test("buckets by 24h / 7d / 30d cutoffs", () => {
    const now = new Date("2026-02-01T12:00:00Z");
    const entries: UsageEntry[] = [
      mkEntry({ ts: "2026-01-01T00:00:00Z", model: "claude-opus-4-7", input: 1_000_000 }), // 31 days ago — outside all windows
      mkEntry({ ts: "2026-01-20T00:00:00Z", model: "claude-opus-4-7", input: 1_000_000 }), // 12 days ago — only 30d
      mkEntry({ ts: "2026-01-29T00:00:00Z", model: "claude-opus-4-7", input: 1_000_000 }), // 3 days ago — 30d + 7d
      mkEntry({ ts: "2026-02-01T06:00:00Z", model: "claude-opus-4-7", input: 1_000_000 }), // 6h ago — all
    ];
    const s = summarize(entries, now);
    expect(s.total.count).toBe(4);
    expect(s.windows["24h"]!.count).toBe(1);
    expect(s.windows["7d"]!.count).toBe(2);
    expect(s.windows["30d"]!.count).toBe(3);
  });
});

describe("parseSince", () => {
  test("parses units h/d/w/m", () => {
    const now = new Date("2026-02-01T00:00:00Z");
    expect(parseSince("24h", now)!.toISOString()).toBe("2026-01-31T00:00:00.000Z");
    expect(parseSince("7d", now)!.toISOString()).toBe("2026-01-25T00:00:00.000Z");
    expect(parseSince("2w", now)!.toISOString()).toBe("2026-01-18T00:00:00.000Z");
    expect(parseSince("1m", now)!.toISOString()).toBe("2026-01-02T00:00:00.000Z");
  });

  test("returns undefined for 'all'", () => {
    expect(parseSince("all")).toBeUndefined();
  });

  test("throws on garbage", () => {
    expect(() => parseSince("forever")).toThrow();
    expect(() => parseSince("7")).toThrow();
    expect(() => parseSince("7x")).toThrow();
  });
});

describe("loadUsageEntries", () => {
  test("parses jsonl, dedupes by message.id, sorts by timestamp", async () => {
    const root = mkdtempSync(join(tmpdir(), "archon-usage-"));
    const proj = join(root, "-Users-x-repo");
    mkdirSync(proj, { recursive: true });
    const lines = [
      JSON.stringify({
        type: "assistant",
        timestamp: "2026-02-01T10:00:00Z",
        sessionId: "s1",
        message: { id: "msg_1", model: "claude-opus-4-7", usage: { input_tokens: 100, output_tokens: 50 } },
      }),
      JSON.stringify({
        type: "assistant",
        timestamp: "2026-02-01T09:00:00Z",
        sessionId: "s1",
        message: { id: "msg_2", model: "claude-sonnet-4-6", usage: { input_tokens: 200, output_tokens: 30 } },
      }),
      // Duplicate of msg_1 (resumed session) — must be skipped.
      JSON.stringify({
        type: "assistant",
        timestamp: "2026-02-01T11:00:00Z",
        sessionId: "s2",
        message: { id: "msg_1", model: "claude-opus-4-7", usage: { input_tokens: 100, output_tokens: 50 } },
      }),
      // Non-assistant — must be ignored.
      JSON.stringify({ type: "permission-mode", permissionMode: "default", sessionId: "s1" }),
      // Garbage line — must be ignored, not crash.
      "{not json",
    ];
    writeFileSync(join(proj, "session.jsonl"), lines.join("\n") + "\n");

    const entries = await loadUsageEntries({ projectsDir: root });
    expect(entries.length).toBe(2);
    expect(entries[0]!.timestamp.toISOString()).toBe("2026-02-01T09:00:00.000Z");
    expect(entries[1]!.timestamp.toISOString()).toBe("2026-02-01T10:00:00.000Z");
    expect(entries[1]!.tokens.input).toBe(100);
  });

  test("returns empty array when projects dir missing", async () => {
    const entries = await loadUsageEntries({ projectsDir: "/nonexistent-path-archon-test" });
    expect(entries).toEqual([]);
  });

  test("applies since filter", async () => {
    const root = mkdtempSync(join(tmpdir(), "archon-usage-"));
    const proj = join(root, "proj");
    mkdirSync(proj, { recursive: true });
    writeFileSync(
      join(proj, "a.jsonl"),
      [
        JSON.stringify({
          type: "assistant",
          timestamp: "2026-01-01T00:00:00Z",
          message: { id: "old", model: "claude-opus-4-7", usage: { input_tokens: 100 } },
        }),
        JSON.stringify({
          type: "assistant",
          timestamp: "2026-02-01T00:00:00Z",
          message: { id: "new", model: "claude-opus-4-7", usage: { input_tokens: 200 } },
        }),
      ].join("\n"),
    );
    const entries = await loadUsageEntries({ projectsDir: root, since: new Date("2026-01-15T00:00:00Z") });
    expect(entries.length).toBe(1);
    expect(entries[0]!.tokens.input).toBe(200);
  });

  test("falls back to cache_creation_input_tokens when ephemeral breakdown missing", async () => {
    const root = mkdtempSync(join(tmpdir(), "archon-usage-"));
    const proj = join(root, "proj");
    mkdirSync(proj, { recursive: true });
    writeFileSync(
      join(proj, "a.jsonl"),
      JSON.stringify({
        type: "assistant",
        timestamp: "2026-02-01T00:00:00Z",
        message: {
          id: "m1",
          model: "claude-opus-4-7",
          usage: { input_tokens: 0, output_tokens: 0, cache_creation_input_tokens: 50_000 },
        },
      }),
    );
    const entries = await loadUsageEntries({ projectsDir: root });
    expect(entries[0]!.tokens.cacheCreate5m).toBe(50_000);
    expect(entries[0]!.tokens.cacheCreate1h).toBe(0);
  });
});

describe("emptyTokens", () => {
  test("returns zeroed breakdown", () => {
    expect(emptyTokens()).toEqual({ input: 0, output: 0, cacheRead: 0, cacheCreate5m: 0, cacheCreate1h: 0 });
  });
});
