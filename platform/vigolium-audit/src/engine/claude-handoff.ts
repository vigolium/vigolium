import { mkdir } from "fs/promises";
import { join } from "path";
import type { Adapter } from "../adapters/adapter.js";
import { adapterEventHasQuotaLimit, adapterEventHasRetryableError, quotaResetDelayMs } from "../adapters/claude-events.js";
import { writeAuditContext } from "./audit-context.js";
import { OrchestratorBus, type OrchestratorEvent } from "./events.js";
import {
  startFindingsWatcher,
  summarizeFindings,
  type OrchestratorResult,
} from "./orchestrator.js";
import { StateStore } from "./state.js";
import { deriveHandoffStatus, startHandoffPoller } from "./handoff-poll.js";
import { parseIntEnv, round2, sleepInterruptible } from "./util.js";
import type { AuditMode, AuditRecord, PhaseDef } from "./types.js";

/**
 * Headless audit driver for the claude platform. Hands the entire mode off
 * to the user's `claude` runtime via the `/vigolium-audit:vigolium-audit:<mode>` slash
 * command, with the vigolium-audit plugin loaded for skills/agents/commands. The
 * agents themselves manage `vigolium-results/audit-state.json` (create / resume), spawn
 * sub-agents, and write findings — this driver only kicks off the run, streams
 * events out for the renderer, and reads state back when it finishes.
 *
 * Differences from the per-phase Orchestrator:
 *   - One adapter call instead of one per phase.
 *   - No phase-graph topo-sort, no per-phase retries, no quarantine of partial
 *     output (claude handles its own resume on the next run).
 *   - `--max-cost` is observed only at the finish event (no mid-stream abort
 *     for cost). Abort signal still works.
 *   - User-supplied focus / expected-behaviors / orchestrator directives flow
 *     through `vigolium-results/audit-context.md`, which each command-def inlines via
 *     a `!cat` Context substitution.
 */
export interface ClaudeHandoffOptions {
  adapter: Adapter;
  targetDir: string;
  mode: AuditMode;
  /** Path to the installed vigolium-audit plugin. Forwarded to the adapter. */
  pluginDir: string;
  abortSignal?: AbortSignal;
  debug?: boolean;
  focus?: string;
  expectedBehaviors?: string;
  liveTarget?: string;
  /**
   * Phase IDs the orchestrator wants the agents to skip (refresh-fallback
   * policy). Surfaced in `audit-context.md`; the agents are expected to
   * honor it and record skips in `audit-state.json`.
   */
  excludePhases?: string[];
  /** Persisted via `audit-context.md`; agents stamp `triggered_via` on the audit record. */
  triggeredVia?: string;
  /**
   * Max retries when the run fails because Claude's usage limit was hit
   * (detected from the streamed "You've hit your limit · resets …" message).
   * Default: 5, overridable via `VIGOLIUM_AUDIT_QUOTA_MAX_RETRIES`. With the default
   * 1h backoff this caps the wait at ~5h before the run gives up and exits
   * with resumable state on disk.
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

export class ClaudeHandoff {
  readonly bus = new OrchestratorBus();

  constructor(private readonly opts: ClaudeHandoffOptions) {}

  on(listener: (e: OrchestratorEvent) => void | Promise<void>): () => void {
    return this.bus.on(listener);
  }

  async run(): Promise<OrchestratorResult> {
    const resultsDir = join(this.opts.targetDir, "vigolium-results");
    await mkdir(resultsDir, { recursive: true });

    await writeAuditContext(resultsDir, {
      ...(this.opts.triggeredVia !== undefined ? { triggeredVia: this.opts.triggeredVia } : {}),
      ...(this.opts.excludePhases !== undefined ? { excludePhases: this.opts.excludePhases } : {}),
      ...(this.opts.focus !== undefined ? { focus: this.opts.focus } : {}),
      ...(this.opts.expectedBehaviors !== undefined ? { expectedBehaviors: this.opts.expectedBehaviors } : {}),
    });

    // Snapshot existing audit IDs so we can identify whichever record the
    // agents create (or pick up) during this run.
    const stateStore = new StateStore(resultsDir);
    const before = await stateStore.load().catch(() => ({ schema_version: 1 as const, audits: [] as AuditRecord[] }));
    const knownIds = new Set(before.audits.map((a) => a.audit_id));

    const slashArgs = this.opts.liveTarget !== undefined ? ` ${this.opts.liveTarget}` : "";
    const slash = `/vigolium-audit:vigolium-audit:${this.opts.mode}${slashArgs}`;

    // Synthetic event metadata so the existing line/JSON loggers can render
    // the handoff stream. The real audit_id is read back from audit-state.json
    // after the run; until then, events use a provisional id.
    const provisionalAuditId = `handoff-${Date.now().toString(36)}`;
    const phase: PhaseDef = {
      id: "handoff",
      title: `${this.opts.mode} (slash command)`,
      agent: null,
      requires_git: false,
      depends_on: [],
      parallel_with: [],
    };

    await this.bus.emit({
      kind: "auditStart",
      auditId: provisionalAuditId,
      mode: this.opts.mode,
      totalPhases: 1,
      runnablePhases: 1,
    });
    await this.bus.emit({
      kind: "phaseStart",
      auditId: provisionalAuditId,
      phase,
      index: 1,
      total: 1,
    });

    const stopWatch = startFindingsWatcher({
      resultsDir,
      auditId: provisionalAuditId,
      targetDir: this.opts.targetDir,
      bus: this.bus,
    });
    // Poll audit-state.json so per-phase progress shows up on the event bus
    // even though the adapter only emits one event stream for the whole audit.
    const stopPoll = startHandoffPoller({
      resultsDir,
      bus: this.bus,
      knownAuditIds: knownIds,
      provisionalAuditId,
    });

    const startedAt = Date.now();
    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let ok = false;
    let errorMsg: string | undefined;

    // Retry policy for headless handoff. Quota-limit failures get long sleeps
    // (prefer the streamed reset timestamp when available); retryable transport
    // failures such as Claude CLI stream-idle timeouts get exponential backoff.
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

    try {
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

        // Non-retryable failure → give up; the existing finalize path records
        // the (resumable) state and exits.
        break;
      }
    } finally {
      stopWatch();
      stopPoll();
    }

    const durationMs = Date.now() - startedAt;

    const after = await stateStore.load().catch(() => ({ schema_version: 1 as const, audits: [] as AuditRecord[] }));
    const newAudit = [...after.audits].reverse().find((a) => !knownIds.has(a.audit_id));
    const finalAuditId = newAudit?.audit_id ?? provisionalAuditId;
    // The agents may leave the audit `in_progress` if the slash command
    // returned without writing a terminal status (truncation, partial run).
    // audit-state.json preserves the in_progress record so a future run can resume.
    const status = deriveHandoffStatus({
      recordedStatus: newAudit?.status,
      aborted: this.opts.abortSignal?.aborted === true,
      ok,
    });

    const findings = await summarizeFindings(resultsDir);

    await this.bus.emit({
      kind: "phaseEnd",
      auditId: finalAuditId,
      phase,
      ok,
      usd,
      tokens,
      durationMs,
      ...(errorMsg !== undefined ? { error: errorMsg } : {}),
    });
    await this.bus.emit({
      kind: "auditEnd",
      auditId: finalAuditId,
      status,
      usd: round2(usd),
      tokens,
      findings,
    });

    return {
      auditId: finalAuditId,
      status,
      totalUsd: round2(usd),
      totalTokens: tokens,
      findings,
      failedPhases: [],
      skippedPhases: [],
    };
  }

}

