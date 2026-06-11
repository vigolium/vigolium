import { describe, expect, test } from "bun:test";
import { decideRetry, resolveRetryConfig, runWithRetry, type RetryConfig } from "../../src/engine/retry.js";

const BASE: RetryConfig = {
  quotaMaxRetries: 3,
  quotaOverrideDelayMs: undefined,
  quotaFallbackDelayMs: 60 * 60 * 1000,
  transientMaxRetries: 3,
  transientBaseDelayMs: 1000,
  skipTransientAfterProgress: true,
};

const outcome = (over: Partial<Parameters<typeof decideRetry>[2]> = {}) => ({
  ok: false,
  quotaLimit: false,
  transient: false,
  sawProgress: false,
  ...over,
});

describe("decideRetry", () => {
  test("stops immediately on success", () => {
    expect(decideRetry(BASE, 0, outcome({ ok: true })).action).toBe("stop");
  });

  test("retries on quota with the fallback delay when nothing else is known", () => {
    const step = decideRetry(BASE, 0, outcome({ quotaLimit: true }));
    expect(step).toMatchObject({ action: "retry", kind: "quota", delayMs: 60 * 60 * 1000 });
  });

  test("prefers the parsed reset delay over the fallback", () => {
    const step = decideRetry(BASE, 0, outcome({ quotaLimit: true, parsedQuotaDelayMs: 5000 }));
    expect(step).toMatchObject({ kind: "quota", delayMs: 5000 });
  });

  test("an explicit override beats the parsed reset delay", () => {
    const cfg = { ...BASE, quotaOverrideDelayMs: 1 };
    const step = decideRetry(cfg, 0, outcome({ quotaLimit: true, parsedQuotaDelayMs: 5000 }));
    expect(step).toMatchObject({ kind: "quota", delayMs: 1 });
  });

  test("stops quota retries once the cap is reached", () => {
    expect(decideRetry(BASE, 3, outcome({ quotaLimit: true })).action).toBe("stop");
  });

  test("retries transient with exponential backoff", () => {
    expect(decideRetry(BASE, 0, outcome({ transient: true }))).toMatchObject({ kind: "transient", delayMs: 1000 });
    expect(decideRetry(BASE, 2, outcome({ transient: true }))).toMatchObject({ kind: "transient", delayMs: 4000 });
  });

  test("skips transient retry after progress when configured", () => {
    expect(decideRetry(BASE, 0, outcome({ transient: true, sawProgress: true })).action).toBe("stop");
  });

  test("retries transient after progress when not configured to skip", () => {
    const cfg = { ...BASE, skipTransientAfterProgress: false };
    expect(decideRetry(cfg, 0, outcome({ transient: true, sawProgress: true })).action).toBe("retry");
  });

  test("quota takes precedence over transient when both are set", () => {
    const step = decideRetry(BASE, 0, outcome({ quotaLimit: true, transient: true }));
    expect(step).toMatchObject({ kind: "quota" });
  });
});

describe("resolveRetryConfig", () => {
  const defaults = { quotaMaxRetries: 5, transientMaxRetries: 3, transientBaseDelayMs: 1000 };

  test("uses defaults when nothing is provided", () => {
    const cfg = resolveRetryConfig({ skipTransientAfterProgress: true, defaults, env: {} });
    expect(cfg.quotaMaxRetries).toBe(5);
    expect(cfg.transientMaxRetries).toBe(3);
    expect(cfg.quotaOverrideDelayMs).toBeUndefined();
  });

  test("opts beat env beat defaults", () => {
    const cfg = resolveRetryConfig({
      quotaMaxRetries: 9,
      skipTransientAfterProgress: true,
      defaults,
      env: { VIGOLIUM_AUDIT_QUOTA_MAX_RETRIES: "7", VIGOLIUM_AUDIT_TRANSIENT_MAX_RETRIES: "2" },
    });
    expect(cfg.quotaMaxRetries).toBe(9); // opt wins
    expect(cfg.transientMaxRetries).toBe(2); // env wins over default
  });

  test("leaves quota override undefined unless opts/env set it (so parsed delay wins)", () => {
    const withEnv = resolveRetryConfig({
      skipTransientAfterProgress: true,
      defaults,
      env: { VIGOLIUM_AUDIT_QUOTA_BACKOFF_MS: "1234" },
    });
    expect(withEnv.quotaOverrideDelayMs).toBe(1234);
  });
});

describe("runWithRetry", () => {
  test("retries until success and reports attempt count", async () => {
    let calls = 0;
    const notes: string[] = [];
    const ac = new AbortController();
    await runWithRetry({ ...BASE, transientBaseDelayMs: 0 }, {
      abortSignal: ac.signal,
      note: (t) => void notes.push(t),
      attempt: async () => {
        calls++;
        return outcome({ ok: calls >= 3, transient: calls < 3 });
      },
    });
    expect(calls).toBe(3); // two transient retries, then success
    expect(notes.length).toBe(2); // two retry notices before the success
  });

  test("runs the preflight probe after a quota sleep", async () => {
    let probes = 0;
    let calls = 0;
    const ac = new AbortController();
    await runWithRetry({ ...BASE, quotaOverrideDelayMs: 0 }, {
      abortSignal: ac.signal,
      note: () => {},
      probe: async () => {
        probes++;
      },
      attempt: async () => {
        calls++;
        return outcome({ ok: calls >= 2, quotaLimit: calls < 2 });
      },
    });
    expect(calls).toBe(2);
    expect(probes).toBe(1);
  });

  test("stops when the abort signal fires", async () => {
    const ac = new AbortController();
    let calls = 0;
    await runWithRetry({ ...BASE, transientBaseDelayMs: 0 }, {
      abortSignal: ac.signal,
      note: () => {},
      attempt: async () => {
        calls++;
        ac.abort();
        return outcome({ transient: true });
      },
    });
    expect(calls).toBe(1);
  });
});
