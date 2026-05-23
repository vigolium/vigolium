import { BaseHandoff, type BaseHandoffOptions, type HandoffDriveResult, type HandoffRunContext } from "./base-handoff.js";
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
 * dispatch trigger prompt and a single-pass adapter drive (codex has no
 * quota/transient retry policy).
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

export function isCodexHandoffMode(mode: AuditMode): boolean {
  return mode in MODE_TRIGGER_PHRASE;
}

export type CodexHandoffOptions = BaseHandoffOptions;

export class CodexHandoff extends BaseHandoff<CodexHandoffOptions> {
  protected override phaseTitleSuffix(): string {
    return "codex dispatch";
  }

  protected override async driveAdapter(ctx: HandoffRunContext): Promise<HandoffDriveResult> {
    const { provisionalAuditId, phase } = ctx;
    const userPrompt = this.buildTriggerPrompt();

    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let ok = false;
    let errorMsg: string | undefined;

    for await (const event of this.opts.adapter.run({
      userPrompt,
      cwd: this.opts.targetDir,
      bypassPermissions: true,
      ...(this.opts.abortSignal && { abortSignal: this.opts.abortSignal }),
      ...(this.opts.debug ? { debug: true } : {}),
      label: `${this.opts.mode}:codex-handoff`,
    })) {
      await this.bus.emit({
        kind: "phaseAdapterEvent",
        auditId: provisionalAuditId,
        phase,
        event,
      });
      if (event.kind === "finish") {
        usd = event.usd;
        tokens = event.tokens;
        ok = event.ok;
        if (!event.ok) errorMsg = event.reason;
      }
    }

    return { usd, tokens, ok, errorMsg };
  }

  /**
   * Build the user prompt that tells codex to follow the AGENTS.md dispatch.
   * Includes the mode-specific trigger phrase verbatim from the dispatch doc so
   * codex's mode-selection rule resolves to the right pipeline rather than
   * falling back to balanced.
   */
  private buildTriggerPrompt(): string {
    const trigger = MODE_TRIGGER_PHRASE[this.opts.mode] ?? this.opts.mode;
    const lines = [
      `${trigger}.`,
      ``,
      `Dispatch authority: \`~/.codex/AGENTS.md\` between \`# BEGIN vigolium-audit\` and \`# END vigolium-audit\`. Follow that contract exactly — do not import orchestration from any other prompt.`,
      `Audit context: read \`vigolium-results/audit-context.md\` first if it exists; it carries focus, expected behaviors, and orchestrator directives.`,
      `Target directory: ${this.opts.targetDir}`,
      `Mode: ${this.opts.mode}`,
    ];
    if (this.opts.liveTarget !== undefined) {
      lines.push(`Live target: ${this.opts.liveTarget}`);
    }
    return lines.join("\n");
  }
}
