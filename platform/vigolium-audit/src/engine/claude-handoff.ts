import { adapterEventHasQuotaLimit, adapterEventHasRetryableError, quotaResetDelayMs } from "../adapters/claude-events.js";
import { BaseHandoff, type BaseHandoffOptions, type HandoffDriveResult, type HandoffRunContext } from "./base-handoff.js";
import { resolveRetryConfig, runWithRetry } from "./retry.js";

/**
 * Headless audit driver for the claude platform. Hands the entire mode off to
 * the user's `claude` runtime via the `/vigolium-audit:vigolium-audit:<mode>` slash
 * command, with the vigolium-audit plugin loaded for skills/agents/commands.
 *
 * The common skeleton (context file, state snapshot, findings watcher, progress
 * poller, finalize) lives in {@link BaseHandoff}. This subclass contributes the
 * slash-command trigger and the quota/transient retry policy.
 *
 * User-supplied focus / expected-behaviors / orchestrator directives flow
 * through `vigolium-results/audit-context.md`, which each command-def inlines via a
 * `!cat` Context substitution.
 */
export interface ClaudeHandoffOptions extends BaseHandoffOptions {
  /** Path to the installed vigolium-audit plugin. Forwarded to the adapter. */
  pluginDir: string;
  /**
   * Max retries when the run fails because Claude's usage limit was hit
   * (detected from the streamed "You've hit your limit · resets …" message).
   * Default: 5, overridable via `VIGOLIUM_AUDIT_QUOTA_MAX_RETRIES`. With the default
   * 1h backoff this caps the wait at ~5h before the run gives up and exits with
   * resumable state on disk.
   */
  quotaMaxRetries?: number;
  /**
   * Delay between quota-limit retry attempts in milliseconds. When omitted, the
   * handoff first honors `VIGOLIUM_AUDIT_QUOTA_BACKOFF_MS`, then tries to sleep until
   * the streamed `resets ...` timestamp, and finally falls back to 1h. Tests set
   * this tiny so the retry loop doesn't actually sleep an hour.
   */
  quotaBackoffMs?: number;
  /** Max retries for retryable non-quota transport failures. Default: 3. */
  transientMaxRetries?: number;
  /** Base delay for retryable non-quota transport failures. Default: 30s. */
  transientBackoffMs?: number;
}

export class ClaudeHandoff extends BaseHandoff<ClaudeHandoffOptions> {
  protected override phaseTitleSuffix(): string {
    return "slash command";
  }

  protected override async driveAdapter(ctx: HandoffRunContext): Promise<HandoffDriveResult> {
    const { provisionalAuditId, phase } = ctx;

    const slashArgs = this.opts.liveTarget !== undefined ? ` ${this.opts.liveTarget}` : "";
    const slash = `/vigolium-audit:vigolium-audit:${this.opts.mode}${slashArgs}`;

    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let ok = false;
    let errorMsg: string | undefined;

    // Retry policy for the headless handoff. Quota-limit failures get long
    // sleeps (prefer the streamed reset timestamp when available); retryable
    // transport failures such as Claude CLI stream-idle timeouts get
    // exponential backoff. The algorithm is shared with the orchestrator via
    // `runWithRetry`; only the defaults differ (30s transient base here).
    const retryConfig = resolveRetryConfig({
      ...(this.opts.quotaMaxRetries !== undefined ? { quotaMaxRetries: this.opts.quotaMaxRetries } : {}),
      ...(this.opts.quotaBackoffMs !== undefined ? { quotaBackoffMs: this.opts.quotaBackoffMs } : {}),
      ...(this.opts.transientMaxRetries !== undefined ? { transientMaxRetries: this.opts.transientMaxRetries } : {}),
      ...(this.opts.transientBackoffMs !== undefined ? { transientBackoffMs: this.opts.transientBackoffMs } : {}),
      // The handoff is one whole-mode call writing findings to disk; a transient
      // retry after progress is acceptable (and desirable) here.
      skipTransientAfterProgress: false,
      defaults: { quotaMaxRetries: 5, transientMaxRetries: 3, transientBaseDelayMs: 30 * 1000 },
    });
    const abortSignal = this.opts.abortSignal ?? new AbortController().signal;

    await runWithRetry(retryConfig, {
      abortSignal,
      probe: () => this.opts.adapter.probe(),
      note: async (text) => {
        await this.bus.emit({ kind: "phaseAdapterEvent", auditId: provisionalAuditId, phase, event: { kind: "textDelta", text } });
      },
      attempt: async () => {
        let quotaLimit = false;
        let retryableFailure = false;
        let attemptOk = false;
        let sawProgress = false;
        let attemptErr: string | undefined;
        let parsedQuotaDelayMs: number | null = null;

        for await (const event of this.opts.adapter.run({
          userPrompt: slash,
          cwd: this.opts.targetDir,
          pluginDir: this.opts.pluginDir,
          bypassPermissions: true,
          // AskUserQuestion would block forever in a non-interactive run.
          disallowedTools: ["AskUserQuestion"],
          ...(this.opts.abortSignal && { abortSignal: this.opts.abortSignal }),
          ...(this.opts.debug ? { debug: true } : {}),
          label: `${this.opts.mode}:handoff`,
        })) {
          await this.bus.emit({ kind: "phaseAdapterEvent", auditId: provisionalAuditId, phase, event });
          if (event.kind === "rateLimits") {
            await this.bus.emit({ kind: "rateLimits", auditId: provisionalAuditId, data: event.data });
          }
          if (event.kind === "textDelta" || event.kind === "toolCall") sawProgress = true;

          // Quota notices can arrive as assistant text, failed finish reasons,
          // error messages, or as Task/subagent toolResult payloads (rendered in
          // the CLI with a `←` prefix). Scan the whole normalized event.
          if (adapterEventHasQuotaLimit(event)) {
            quotaLimit = true;
            const delay = quotaResetDelayMs(event);
            if (delay !== null && (parsedQuotaDelayMs === null || delay < parsedQuotaDelayMs)) {
              parsedQuotaDelayMs = delay;
            }
          }
          if (adapterEventHasRetryableError(event)) retryableFailure = true;

          if (event.kind === "error") attemptErr = event.cause.message;
          if (event.kind === "finish") {
            usd += event.usd;
            tokens = { input: tokens.input + event.tokens.input, output: tokens.output + event.tokens.output };
            attemptOk = event.ok;
            if (!event.ok) attemptErr = event.reason;
          }
        }

        ok = attemptOk;
        errorMsg = attemptErr;
        return {
          ok: attemptOk,
          quotaLimit,
          transient: retryableFailure,
          sawProgress,
          parsedQuotaDelayMs,
          error: attemptErr,
        };
      },
    });

    return { usd, tokens, ok, errorMsg };
  }
}
