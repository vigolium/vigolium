import { adapterEventHasQuotaLimit, adapterEventHasRetryableError, quotaResetDelayMs } from "../adapters/claude-events.js";
import { BaseHandoff, type BaseHandoffOptions, type HandoffDriveResult, type HandoffRunContext } from "./base-handoff.js";
import { resolveRetryConfig, runWithRetry } from "./retry.js";
import type { AuditMode } from "./types.js";

/**
 * Headless audit driver for the codex platform — analogue of `ClaudeHandoff`.
 *
 * Codex has no slash commands, so the trigger isn't `/vigolium-audit:vigolium-audit:<mode>`;
 * it's a short user prompt that names the mode and points at the dispatch
 * fragment installed in `~/.codex/AGENTS.md` (codex auto-loads AGENTS.md on
 * every `codex exec`, which makes "register a known dispatch the agent will
 * follow when prompted" work the same way slash commands do for claude).
 *
 * The common skeleton (context file, state snapshot, findings watcher, progress
 * poller, finalize) lives in {@link BaseHandoff}. This subclass contributes the
 * dispatch trigger prompt; the quota/transient retry algorithm is shared with
 * the claude handoff and the orchestrator via `runWithRetry`. (Codex rarely
 * surfaces a quota notice, but retryable transport errors — now flagged by the
 * codex CLI adapter — do get the same exponential backoff.)
 *
 * Required pre-condition: `installCodexHarness` (or the ephemeral harness handle
 * held by the caller) must have already written:
 *   - `~/.codex/agents/vigolium-audit-*.toml` (subagent registry)
 *   - `~/.codex/skills/vigolium-audit-<skill>/` (skills the subagents reference)
 *   - the BEGIN/END vigolium-audit block in `~/.codex/AGENTS.md` (dispatch)
 *
 * Modes covered by the dispatch fragment: lite, balanced, deep, revisit,
 * confirm. `isCodexHandoffMode()` is the canonical predicate — keep in sync if
 * `agents-dispatch.md` is extended.
 */

const MODE_TRIGGER_PHRASE: Partial<Record<AuditMode, string>> = {
  lite: "Lite mode: L1-L3",
  balanced: "Balanced mode: B1-B9",
  deep: "Full deep mode",
  revisit: "Revisit mode",
  confirm: "Confirm mode",
};

export interface CodexTriggerPromptOptions {
  mode: AuditMode;
  targetDir: string;
  liveTarget?: string;
}

/**
 * Build the canonical Codex dispatch prompt used by both headless SDK/CLI
 * handoff and native interactive mode. Keeping one prompt prevents `-i` from
 * drifting into a manual, Claude-style subagent invocation flow.
 */
export function buildCodexTriggerPrompt(options: CodexTriggerPromptOptions): string {
  const trigger = MODE_TRIGGER_PHRASE[options.mode];
  if (trigger === undefined) {
    throw new Error(
      `Codex AGENTS.md dispatch does not support mode "${options.mode}"; run it through the phase orchestrator instead`,
    );
  }
  const lines = [
    `${trigger}.`,
    ``,
    `Dispatch authority: \`~/.codex/AGENTS.md\` between \`# BEGIN vigolium-audit\` and \`# END vigolium-audit\`. Follow that contract exactly — do not import orchestration from any other prompt.`,
    `Audit context: read \`vigolium-results/audit-context.md\` first if it exists; it carries focus, expected behaviors, and orchestrator directives.`,
    `Target directory: ${options.targetDir}`,
    `Mode: ${options.mode}`,
  ];
  if (options.liveTarget !== undefined) {
    lines.push(`Live target: ${options.liveTarget}`);
  }
  return lines.join("\n");
}

export function isCodexHandoffMode(mode: AuditMode): boolean {
  return mode in MODE_TRIGGER_PHRASE;
}

export interface CodexHandoffOptions extends BaseHandoffOptions {
  quotaMaxRetries?: number;
  quotaBackoffMs?: number;
  transientMaxRetries?: number;
  transientBackoffMs?: number;
}

export class CodexHandoff extends BaseHandoff<CodexHandoffOptions> {
  protected override phaseTitleSuffix(): string {
    return "codex dispatch";
  }

  protected override async driveAdapter(ctx: HandoffRunContext): Promise<HandoffDriveResult> {
    const { provisionalAuditId, phase } = ctx;
    const userPrompt = buildCodexTriggerPrompt({
      mode: this.opts.mode,
      targetDir: this.opts.targetDir,
      ...(this.opts.liveTarget !== undefined ? { liveTarget: this.opts.liveTarget } : {}),
    });

    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let ok = false;
    let errorMsg: string | undefined;

    const retryConfig = resolveRetryConfig({
      ...(this.opts.quotaMaxRetries !== undefined ? { quotaMaxRetries: this.opts.quotaMaxRetries } : {}),
      ...(this.opts.quotaBackoffMs !== undefined ? { quotaBackoffMs: this.opts.quotaBackoffMs } : {}),
      ...(this.opts.transientMaxRetries !== undefined ? { transientMaxRetries: this.opts.transientMaxRetries } : {}),
      ...(this.opts.transientBackoffMs !== undefined ? { transientBackoffMs: this.opts.transientBackoffMs } : {}),
      // Whole-mode call writing findings to disk; a transient retry after
      // progress is acceptable here, same as the claude handoff.
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
          userPrompt,
          cwd: this.opts.targetDir,
          bypassPermissions: true,
          ...(this.opts.abortSignal && { abortSignal: this.opts.abortSignal }),
          ...(this.opts.debug ? { debug: true } : {}),
          label: `${this.opts.mode}:codex-handoff`,
        })) {
          await this.bus.emit({ kind: "phaseAdapterEvent", auditId: provisionalAuditId, phase, event });
          if (event.kind === "textDelta" || event.kind === "toolCall") sawProgress = true;
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
