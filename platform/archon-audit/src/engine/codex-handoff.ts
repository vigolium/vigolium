import { mkdir } from "fs/promises";
import { join } from "path";
import type { Adapter } from "../adapters/adapter.js";
import { writeAuditContext } from "./audit-context.js";
import { OrchestratorBus, type OrchestratorEvent } from "./events.js";
import {
  startFindingsWatcher,
  summarizeFindings,
  type OrchestratorResult,
} from "./orchestrator.js";
import { StateStore } from "./state.js";
import { deriveHandoffStatus, startHandoffPoller } from "./handoff-poll.js";
import { round2 } from "./util.js";
import type { AuditMode, AuditRecord, PhaseDef } from "./types.js";

/**
 * Headless audit driver for the codex platform — analogue of `ClaudeHandoff`.
 *
 * Codex has no slash commands, so the trigger isn't `/archon-audit:archon:<mode>`;
 * it's a short user prompt that names the mode and points at the dispatch
 * fragment installed in `~/.codex/AGENTS.md` (codex auto-loads AGENTS.md on
 * every `codex exec`, which makes "register a known dispatch the agent will
 * follow when prompted" work the same way slash commands do for claude).
 *
 * Required pre-condition: `installCodexHarness` (or the ephemeral harness
 * handle held by the caller) must have already written:
 *   - `~/.codex/agents/archon-*.toml` (subagent registry)
 *   - `~/.codex/skills/archon-<skill>/` (skills the subagents reference)
 *   - the BEGIN/END archon-audit block in `~/.codex/AGENTS.md` (dispatch)
 *
 * Modes covered by the dispatch fragment: lite, balanced, deep, revisit,
 * confirm. `isCodexHandoffMode()` is the canonical predicate — keep in sync
 * if `agents-dispatch.md` is extended.
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

export interface CodexHandoffOptions {
  adapter: Adapter;
  targetDir: string;
  mode: AuditMode;
  abortSignal?: AbortSignal;
  debug?: boolean;
  focus?: string;
  expectedBehaviors?: string;
  liveTarget?: string;
  excludePhases?: string[];
  triggeredVia?: string;
}

export class CodexHandoff {
  readonly bus = new OrchestratorBus();

  constructor(private readonly opts: CodexHandoffOptions) {}

  on(listener: (e: OrchestratorEvent) => void | Promise<void>): () => void {
    return this.bus.on(listener);
  }

  async run(): Promise<OrchestratorResult> {
    const archonDir = join(this.opts.targetDir, "archon");
    await mkdir(archonDir, { recursive: true });

    await writeAuditContext(archonDir, {
      ...(this.opts.triggeredVia !== undefined ? { triggeredVia: this.opts.triggeredVia } : {}),
      ...(this.opts.excludePhases !== undefined ? { excludePhases: this.opts.excludePhases } : {}),
      ...(this.opts.focus !== undefined ? { focus: this.opts.focus } : {}),
      ...(this.opts.expectedBehaviors !== undefined ? { expectedBehaviors: this.opts.expectedBehaviors } : {}),
    });

    const stateStore = new StateStore(archonDir);
    const before = await stateStore.load().catch(() => ({
      schema_version: 1 as const,
      audits: [] as AuditRecord[],
    }));
    const knownIds = new Set(before.audits.map((a) => a.audit_id));

    const provisionalAuditId = `handoff-${Date.now().toString(36)}`;
    const phase: PhaseDef = {
      id: "handoff",
      title: `${this.opts.mode} (codex dispatch)`,
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
      archonDir,
      auditId: provisionalAuditId,
      targetDir: this.opts.targetDir,
      bus: this.bus,
    });
    const stopPoll = startHandoffPoller({
      archonDir,
      bus: this.bus,
      knownAuditIds: knownIds,
      provisionalAuditId,
    });

    const userPrompt = this.buildTriggerPrompt();

    const startedAt = Date.now();
    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let ok = false;
    let errorMsg: string | undefined;

    try {
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
    } finally {
      stopWatch();
      stopPoll();
    }

    const durationMs = Date.now() - startedAt;

    const after = await stateStore.load().catch(() => ({
      schema_version: 1 as const,
      audits: [] as AuditRecord[],
    }));
    const newAudit = [...after.audits].reverse().find((a) => !knownIds.has(a.audit_id));
    const finalAuditId = newAudit?.audit_id ?? provisionalAuditId;
    const status = deriveHandoffStatus({
      recordedStatus: newAudit?.status,
      aborted: this.opts.abortSignal?.aborted === true,
      ok,
    });

    const findings = await summarizeFindings(archonDir);

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

  /**
   * Build the user prompt that tells codex to follow the AGENTS.md dispatch.
   * Includes the mode-specific trigger phrase verbatim from the dispatch doc
   * so codex's mode-selection rule resolves to the right pipeline rather than
   * falling back to balanced.
   */
  private buildTriggerPrompt(): string {
    const trigger = MODE_TRIGGER_PHRASE[this.opts.mode] ?? this.opts.mode;
    const lines = [
      `${trigger}.`,
      ``,
      `Dispatch authority: \`~/.codex/AGENTS.md\` between \`# BEGIN archon-audit\` and \`# END archon-audit\`. Follow that contract exactly — do not import orchestration from any other prompt.`,
      `Audit context: read \`archon/audit-context.md\` first if it exists; it carries focus, expected behaviors, and orchestrator directives.`,
      `Target directory: ${this.opts.targetDir}`,
      `Mode: ${this.opts.mode}`,
    ];
    if (this.opts.liveTarget !== undefined) {
      lines.push(`Live target: ${this.opts.liveTarget}`);
    }
    return lines.join("\n");
  }

}

