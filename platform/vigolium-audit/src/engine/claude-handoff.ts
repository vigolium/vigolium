import { adapterEventHasQuotaLimit, adapterEventHasRetryableError, quotaResetDelayMs } from "../adapters/claude-events.js";
import { BaseHandoff, type BaseHandoffOptions, type HandoffDriveResult, type HandoffRunContext } from "./base-handoff.js";
import { parseIntEnv, sleepInterruptible } from "./util.js";

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
    // exponential backoff.
    const quotaMaxRetries =
      this.opts.quotaMaxRetries ?? parseIntEnv(process.env.VIGOLIUM_AUDIT_QUOTA_MAX_RETRIES, 5);
    const envQuotaDelayMs = process.env.VIGOLIUM_AUDIT_QUOTA_BACKOFF_MS !== undefined
      ? parseIntEnv(process.env.VIGOLIUM_AUDIT_QUOTA_BACKOFF_MS, 60 * 60 * 1000)
      : undefined;
    const quotaOverrideDelayMs = this.opts.quotaBackoffMs ?? envQuotaDelayMs;
    const quotaFallbackDelayMs = 60 * 60 * 1000;
    const transientMaxRetries =
      this.opts.transientMaxRetries ?? parseIntEnv(process.env.VIGOLIUM_AUDIT_TRANSIENT_MAX_RETRIES, 3);
    const transientBaseDelayMs =
      this.opts.transientBackoffMs ?? parseIntEnv(process.env.VIGOLIUM_AUDIT_TRANSIENT_BACKOFF_MS, 30 * 1000);
    const maxAttempts = Math.max(quotaMaxRetries, transientMaxRetries);
    const abortSignal = this.opts.abortSignal ?? new AbortController().signal;

    for (let attempt = 0; attempt <= maxAttempts; attempt++) {
      let quotaLimit = false;
      let retryableFailure = false;
      let attemptOk = false;
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
        await this.bus.emit({
          kind: "phaseAdapterEvent",
          auditId: provisionalAuditId,
          phase,
          event,
        });
        if (event.kind === "rateLimits") {
          await this.bus.emit({ kind: "rateLimits", auditId: provisionalAuditId, data: event.data });
        }

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
        if (adapterEventHasRetryableError(event)) {
          retryableFailure = true;
        }

        if (event.kind === "error") {
          attemptErr = event.cause.message;
        }
        if (event.kind === "finish") {
          usd += event.usd;
          tokens = {
            input: tokens.input + event.tokens.input,
            output: tokens.output + event.tokens.output,
          };
          attemptOk = event.ok;
          if (!event.ok) attemptErr = event.reason;
        }
      }

      ok = attemptOk;
      errorMsg = attemptErr;

      if (ok) break;
      if (abortSignal.aborted) break;

      if (quotaLimit) {
        if (attempt >= quotaMaxRetries) break;
        const delayMs = quotaOverrideDelayMs ?? parsedQuotaDelayMs ?? quotaFallbackDelayMs;
        const minutes = Math.max(0, Math.round(delayMs / 60000));
        await this.bus.emit({
          kind: "phaseAdapterEvent",
          auditId: provisionalAuditId,
          phase,
          event: {
            kind: "textDelta",
            text: `[quota limit hit — sleeping ${minutes}m before retry ${attempt + 1}/${quotaMaxRetries} — ${errorMsg ?? "usage limit reached"}]\n`,
          },
        });
        await sleepInterruptible(delayMs, abortSignal);
        if (abortSignal.aborted) break;

        // Preflight: round-trip a trivial prompt (same probe `vigolium-audit
        // verify` uses) to report whether the quota actually reset before we
        // spend another full slash-command attempt. Purely informational — a
        // still-limited probe just means the next attempt will fail fast and
        // sleep again, keeping the total bounded by quotaMaxRetries.
        try {
          await this.opts.adapter.probe();
          await this.bus.emit({
            kind: "phaseAdapterEvent",
            auditId: provisionalAuditId,
            phase,
            event: { kind: "textDelta", text: `[preflight ok — quota reset, resuming audit]\n` },
          });
        } catch (probeErr) {
          await this.bus.emit({
            kind: "phaseAdapterEvent",
            auditId: provisionalAuditId,
            phase,
            event: {
              kind: "textDelta",
              text: `[preflight: still rate-limited (${(probeErr as Error).message.slice(0, 120)}) — retrying anyway]\n`,
            },
          });
        }
        continue;
      }

      if (retryableFailure) {
        if (attempt >= transientMaxRetries) break;
        const delayMs = transientBaseDelayMs * Math.pow(2, attempt);
        await this.bus.emit({
          kind: "phaseAdapterEvent",
          auditId: provisionalAuditId,
          phase,
          event: {
            kind: "textDelta",
            text: `[transient adapter error — sleeping ${delayMs}ms before retry ${attempt + 1}/${transientMaxRetries} — ${errorMsg ?? "retryable adapter error"}]\n`,
          },
        });
        await sleepInterruptible(delayMs, abortSignal);
        if (abortSignal.aborted) break;
        continue;
      }

      // Non-retryable failure → give up; the finalize path records the
      // (resumable) state and exits.
      break;
    }

    return { usd, tokens, ok, errorMsg };
  }
}
