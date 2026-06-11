import { parseIntEnv, sleepInterruptible } from "./util.js";

/**
 * Shared retry policy for adapter-driven work — used by both the per-phase
 * Orchestrator and the whole-mode handoffs. Before this module each had its own
 * copy with subtly different behavior (the orchestrator never parsed the reset
 * timestamp and never preflighted after a quota sleep). Centralizing the
 * algorithm means a fix lands everywhere; the only per-caller knobs are the
 * resolved config (defaults differ) and whether progress already streamed.
 *
 * Two retry classes:
 *   - quota   — Claude usage-limit hit. Long sleep (prefer the event's parsed
 *               "resets at" delay, else the override/env, else 1h), then an
 *               optional preflight probe to report whether the quota cleared.
 *   - transient — retryable transport failure (429/5xx, stream idle timeout).
 *               Short exponential backoff. Skipped mid-stream when the caller
 *               opts into `skipTransientAfterProgress` (a replay would dupe).
 */
export interface RetryConfig {
  quotaMaxRetries: number;
  /**
   * Explicit quota delay (from opts or env). When defined it is used verbatim,
   * overriding any reset delay parsed from the event. Tests set this tiny so
   * the loop doesn't actually sleep an hour.
   */
  quotaOverrideDelayMs: number | undefined;
  /** Quota delay when there is no override and no parsed reset timestamp. */
  quotaFallbackDelayMs: number;
  transientMaxRetries: number;
  transientBaseDelayMs: number;
  /**
   * Skip a transient retry once the attempt has already streamed progress
   * (orchestrator: a mid-stream retry would replay events to the bus). Quota
   * retries are never skipped — the user explicitly wants to wait out the reset.
   */
  skipTransientAfterProgress: boolean;
}

export interface RetryAttemptOutcome {
  ok: boolean;
  quotaLimit: boolean;
  transient: boolean;
  sawProgress: boolean;
  /** "resets at" delay parsed from the streamed quota notice, if any. */
  parsedQuotaDelayMs?: number | null | undefined;
  /** Human-readable error surfaced in the retry notice. */
  error?: string | undefined;
}

export type RetryStep =
  | { action: "stop" }
  | { action: "retry"; kind: "quota" | "transient"; delayMs: number; note: string };

/**
 * Pure decision — no I/O. Given the config, the just-finished attempt index,
 * and the attempt's classification, decide whether to retry and how long to
 * wait. Callers own the sleep, the bus notice, and any preflight probe.
 */
export function decideRetry(cfg: RetryConfig, attempt: number, o: RetryAttemptOutcome): RetryStep {
  if (o.ok) return { action: "stop" };

  if (o.quotaLimit) {
    if (attempt >= cfg.quotaMaxRetries) return { action: "stop" };
    const delayMs = cfg.quotaOverrideDelayMs ?? o.parsedQuotaDelayMs ?? cfg.quotaFallbackDelayMs;
    const minutes = Math.max(0, Math.round(delayMs / 60000));
    return {
      action: "retry",
      kind: "quota",
      delayMs,
      note: `[quota limit hit — sleeping ${minutes}m before retry ${attempt + 1}/${cfg.quotaMaxRetries} — ${o.error ?? "usage limit reached"}]\n`,
    };
  }

  if (o.transient && !(cfg.skipTransientAfterProgress && o.sawProgress)) {
    if (attempt >= cfg.transientMaxRetries) return { action: "stop" };
    const delayMs = cfg.transientBaseDelayMs * Math.pow(2, attempt);
    return {
      action: "retry",
      kind: "transient",
      delayMs,
      note: `[transient adapter error — sleeping ${delayMs}ms before retry ${attempt + 1}/${cfg.transientMaxRetries} — ${o.error ?? "retryable adapter error"}]\n`,
    };
  }

  return { action: "stop" };
}

export interface RunWithRetryHooks {
  /** Run one attempt and classify its outcome. */
  attempt(): Promise<RetryAttemptOutcome>;
  /** Surface a human-readable note (callers forward it to the event bus). */
  note(text: string): Promise<void> | void;
  /**
   * Optional preflight after a quota sleep — a trivial round-trip that reports
   * whether the quota actually reset. Purely informational: a still-limited
   * probe just means the next attempt fails fast and sleeps again, keeping the
   * total bounded by `quotaMaxRetries`.
   */
  probe?: () => Promise<void>;
  abortSignal: AbortSignal;
}

/**
 * Drive attempts under a config, sleeping (and optionally probing) between
 * retries. The caller captures per-attempt results (cost, tokens, ok/error)
 * via the `attempt` closure.
 */
export async function runWithRetry(cfg: RetryConfig, hooks: RunWithRetryHooks): Promise<void> {
  const maxAttempts = Math.max(cfg.quotaMaxRetries, cfg.transientMaxRetries);
  for (let attempt = 0; attempt <= maxAttempts; attempt++) {
    const outcome = await hooks.attempt();
    if (outcome.ok || hooks.abortSignal.aborted) return;

    const step = decideRetry(cfg, attempt, outcome);
    if (step.action === "stop") return;

    await hooks.note(step.note);
    await sleepInterruptible(step.delayMs, hooks.abortSignal);
    if (hooks.abortSignal.aborted) return;

    if (step.kind === "quota" && hooks.probe) {
      try {
        await hooks.probe();
        await hooks.note(`[preflight ok — quota reset, resuming audit]\n`);
      } catch (probeErr) {
        await hooks.note(
          `[preflight: still rate-limited (${(probeErr as Error).message.slice(0, 120)}) — retrying anyway]\n`,
        );
      }
    }
  }
}

export interface ResolveRetryConfigInput {
  quotaMaxRetries?: number | undefined;
  quotaBackoffMs?: number | undefined;
  transientMaxRetries?: number | undefined;
  transientBackoffMs?: number | undefined;
  skipTransientAfterProgress: boolean;
  /** Per-caller defaults applied when neither opts nor env provide a value. */
  defaults: { quotaMaxRetries: number; transientMaxRetries: number; transientBaseDelayMs: number };
  env?: NodeJS.ProcessEnv;
}

/**
 * Resolve a {@link RetryConfig} from explicit opts + env vars with a single,
 * shared precedence so both callers read the same knobs the same way:
 *   opts → VIGOLIUM_AUDIT_*_{MAX_RETRIES,BACKOFF_MS} env → per-caller default.
 * When neither opts.quotaBackoffMs nor the quota-backoff env is set, the quota
 * delay is left undefined so the event-parsed reset timestamp wins (falling
 * back to 1h only when the event carries no timestamp).
 */
export function resolveRetryConfig(input: ResolveRetryConfigInput): RetryConfig {
  const env = input.env ?? process.env;
  const quotaMaxRetries =
    input.quotaMaxRetries ?? parseIntEnv(env.VIGOLIUM_AUDIT_QUOTA_MAX_RETRIES, input.defaults.quotaMaxRetries);
  const envQuotaDelay =
    env.VIGOLIUM_AUDIT_QUOTA_BACKOFF_MS !== undefined
      ? parseIntEnv(env.VIGOLIUM_AUDIT_QUOTA_BACKOFF_MS, 60 * 60 * 1000)
      : undefined;
  const quotaOverrideDelayMs = input.quotaBackoffMs ?? envQuotaDelay;
  const transientMaxRetries =
    input.transientMaxRetries ??
    parseIntEnv(env.VIGOLIUM_AUDIT_TRANSIENT_MAX_RETRIES, input.defaults.transientMaxRetries);
  const transientBaseDelayMs =
    input.transientBackoffMs ??
    parseIntEnv(env.VIGOLIUM_AUDIT_TRANSIENT_BACKOFF_MS, input.defaults.transientBaseDelayMs);
  return {
    quotaMaxRetries,
    quotaOverrideDelayMs,
    quotaFallbackDelayMs: 60 * 60 * 1000,
    transientMaxRetries,
    transientBaseDelayMs,
    skipTransientAfterProgress: input.skipTransientAfterProgress,
  };
}
