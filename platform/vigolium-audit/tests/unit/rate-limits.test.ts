import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { findRateLimits, normalizeClaudeMessage } from "../../src/adapters/claude-events.js";
import {
  ageMs,
  formatResetsIn,
  readCache,
  writeCache,
} from "../../src/engine/rate-limits-cache.js";

describe("findRateLimits", () => {
  test("returns null when no rate_limits present", () => {
    expect(findRateLimits({})).toBeNull();
    expect(findRateLimits({ type: "result", usage: { input_tokens: 5 } })).toBeNull();
  });

  test("parses a flat top-level rate_limits block", () => {
    const obj = {
      rate_limits: {
        five_hour: { used_percentage: 42.3, resets_at: 1_800_000_000 },
        seven_day: { used_percentage: 18.7, resets_at: 1_800_500_000 },
      },
    };
    const parsed = findRateLimits(obj);
    expect(parsed).not.toBeNull();
    expect(parsed!.five_hour!.used_percentage).toBeCloseTo(42.3, 1);
    expect(parsed!.seven_day!.resets_at).toBe(1_800_500_000);
  });

  test("finds rate_limits nested deep inside the message", () => {
    const obj = {
      type: "result",
      message: {
        id: "msg_1",
        usage: {
          input_tokens: 1,
          rate_limits: {
            five_hour: { used_percentage: 12, resets_at: 1_800_000_000 },
          },
        },
      },
    };
    const parsed = findRateLimits(obj);
    expect(parsed).not.toBeNull();
    expect(parsed!.five_hour!.used_percentage).toBe(12);
  });

  test("includes seven_day_opus + seven_day_sonnet when present", () => {
    const obj = {
      rate_limits: {
        seven_day_opus: { used_percentage: 24.1, resets_at: 1_800_000_000 },
        seven_day_sonnet: { used_percentage: 12.5, resets_at: 1_800_000_000 },
      },
    };
    const parsed = findRateLimits(obj);
    expect(parsed!.seven_day_opus!.used_percentage).toBeCloseTo(24.1);
    expect(parsed!.seven_day_sonnet!.used_percentage).toBeCloseTo(12.5);
  });

  test("ignores rate_limits with no recognized windows", () => {
    expect(findRateLimits({ rate_limits: { something_else: 1 } })).toBeNull();
  });

  test("ignores rate_limits whose window is missing required fields", () => {
    expect(findRateLimits({ rate_limits: { five_hour: { used_percentage: 10 } } })).toBeNull();
    expect(findRateLimits({ rate_limits: { five_hour: { resets_at: 100 } } })).toBeNull();
  });

  test("survives arrays in the path", () => {
    const obj = {
      messages: [
        { type: "user", content: "hi" },
        {
          type: "assistant",
          metadata: {
            rate_limits: {
              five_hour: { used_percentage: 50, resets_at: 1_800_000_000 },
            },
          },
        },
      ],
    };
    const parsed = findRateLimits(obj);
    expect(parsed!.five_hour!.used_percentage).toBe(50);
  });
});

describe("normalizeClaudeMessage yields rateLimits", () => {
  test("emits a rateLimits event when present in the message", () => {
    const msg = {
      type: "result",
      subtype: "success",
      total_cost_usd: 0.01,
      usage: { input_tokens: 5, output_tokens: 10 },
      rate_limits: {
        five_hour: { used_percentage: 55.0, resets_at: 1_800_000_000 },
      },
    };
    const events = [...normalizeClaudeMessage(msg, Date.now())];
    const rl = events.find((e) => e.kind === "rateLimits");
    expect(rl).toBeDefined();
    if (rl && rl.kind === "rateLimits") {
      expect(rl.data.five_hour!.used_percentage).toBeCloseTo(55, 2);
    }
  });

  test("does not emit rateLimits when absent", () => {
    const msg = {
      type: "result",
      subtype: "success",
      total_cost_usd: 0.01,
      usage: { input_tokens: 5, output_tokens: 10 },
    };
    const events = [...normalizeClaudeMessage(msg, Date.now())];
    expect(events.some((e) => e.kind === "rateLimits")).toBe(false);
  });

  test("parses Claude Code's rate_limit_event shape (utilization → used_percentage)", () => {
    const msg = {
      type: "rate_limit_event",
      rate_limit_info: {
        status: "allowed_warning",
        rateLimitType: "seven_day",
        utilization: 0.55,
        resetsAt: 1_800_000_000,
        isUsingOverage: false,
      },
    };
    const events = [...normalizeClaudeMessage(msg, Date.now())];
    expect(events.length).toBe(1);
    if (events[0]!.kind === "rateLimits") {
      expect(events[0]!.data.seven_day!.used_percentage).toBeCloseTo(55, 5);
      expect(events[0]!.data.seven_day!.resets_at).toBe(1_800_000_000);
      expect(events[0]!.data.five_hour).toBeUndefined();
    }
  });

  test("rate_limit_event with unknown rateLimitType yields no event", () => {
    const msg = {
      type: "rate_limit_event",
      rate_limit_info: { rateLimitType: "future_window", utilization: 0.1, resetsAt: 1 },
    };
    const events = [...normalizeClaudeMessage(msg, Date.now())];
    expect(events.length).toBe(0);
  });

  test("rate_limit_event missing required fields yields no event", () => {
    expect(
      [...normalizeClaudeMessage({ type: "rate_limit_event", rate_limit_info: {} }, Date.now())].length,
    ).toBe(0);
  });
});

describe("rate-limits cache", () => {
  function withTempCache(): string {
    const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-rl-cache-"));
    const path = join(dir, "rate-limits-cache.json");
    process.env.VIGOLIUM_AUDIT_RATE_LIMITS_CACHE = path;
    return path;
  }

  test("round-trips a snapshot", async () => {
    withTempCache();
    const at = new Date("2026-02-01T10:00:00Z");
    await writeCache(
      {
        five_hour: { used_percentage: 42, resets_at: 1_800_000_000 },
        seven_day: { used_percentage: 18, resets_at: 1_800_500_000 },
      },
      at,
    );
    const entry = await readCache();
    expect(entry).not.toBeNull();
    expect(entry!.fetched_at).toBe("2026-02-01T10:00:00.000Z");
    expect(entry!.data.five_hour!.used_percentage).toBe(42);
  });

  test("returns null when cache missing", async () => {
    process.env.VIGOLIUM_AUDIT_RATE_LIMITS_CACHE = "/nonexistent-path-vigolium-audit-rl-test";
    expect(await readCache()).toBeNull();
  });

  test("merges incoming partial snapshots into the cache", async () => {
    withTempCache();
    await writeCache(
      { five_hour: { used_percentage: 30, resets_at: 1_800_000_000 } },
      new Date("2026-02-01T10:00:00Z"),
    );
    // Second write covers only seven_day — five_hour should survive.
    await writeCache(
      { seven_day: { used_percentage: 55, resets_at: 1_800_500_000 } },
      new Date("2026-02-01T10:05:00Z"),
    );
    const entry = await readCache();
    expect(entry!.data.five_hour!.used_percentage).toBe(30);
    expect(entry!.data.seven_day!.used_percentage).toBe(55);
    expect(entry!.fetched_at).toBe("2026-02-01T10:05:00.000Z");
  });

  test("overwrites a window when a fresher snapshot for the same window arrives", async () => {
    withTempCache();
    await writeCache(
      { seven_day: { used_percentage: 20, resets_at: 1_800_000_000 } },
      new Date("2026-02-01T10:00:00Z"),
    );
    await writeCache(
      { seven_day: { used_percentage: 55, resets_at: 1_800_500_000 } },
      new Date("2026-02-01T10:05:00Z"),
    );
    const entry = await readCache();
    expect(entry!.data.seven_day!.used_percentage).toBe(55);
    expect(entry!.data.seven_day!.resets_at).toBe(1_800_500_000);
  });

  test("ageMs reflects elapsed time", async () => {
    withTempCache();
    const at = new Date("2026-02-01T10:00:00Z");
    await writeCache({ five_hour: { used_percentage: 1, resets_at: 1 } }, at);
    const entry = await readCache();
    const now = new Date("2026-02-01T10:30:00Z");
    expect(ageMs(entry!, now)).toBe(30 * 60 * 1000);
  });
});

describe("formatResetsIn", () => {
  const now = new Date("2026-02-01T12:00:00Z");
  const at = (offsetMs: number): number => Math.floor((now.getTime() + offsetMs) / 1000);

  test("formats sub-minute as <1m", () => {
    expect(formatResetsIn(at(30_000), now)).toBe("<1m");
  });

  test("formats minutes", () => {
    expect(formatResetsIn(at(23 * 60_000), now)).toBe("23m");
  });

  test("formats hours + minutes", () => {
    expect(formatResetsIn(at(2 * 60 * 60_000 + 14 * 60_000), now)).toBe("2h 14m");
  });

  test("formats days + hours when >= 24h", () => {
    expect(formatResetsIn(at(2 * 24 * 60 * 60_000 + 5 * 60 * 60_000), now)).toBe("2d 5h");
  });

  test("returns 'now' when already past", () => {
    expect(formatResetsIn(at(-1000), now)).toBe("now");
  });
});
