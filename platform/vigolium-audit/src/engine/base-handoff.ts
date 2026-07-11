import { mkdir } from "fs/promises";
import { join } from "path";
import type { Adapter } from "../adapters/adapter.js";
import { getContentLoader } from "../content-loader.js";
import { writeAuditContext } from "./audit-context.js";
import { evaluatePhaseArtifacts, formatArtifactFailures } from "./artifact-gates.js";
import { archivePriorCoreArtifacts } from "./artifact-lifecycle.js";
import { OrchestratorBus, type OrchestratorEvent } from "./events.js";
import { startFindingsWatcher, summarizeFindings } from "./findings.js";
import { probeGit } from "./git.js";
import { type OrchestratorResult } from "./orchestrator.js";
import { StateStore, buildAuditId, findResumableAudit, newAuditRecord } from "./state.js";
import { deriveHandoffStatus, startHandoffPoller } from "./handoff-poll.js";
import { round2 } from "./util.js";
import type { AuditMode, AuditRecord, CommandDef, PhaseDef } from "./types.js";

const ENGINE_STATE_MODES = new Set<AuditMode>(["lite", "balanced", "deep"]);

/**
 * Options common to every headless handoff driver. Platform-specific drivers
 * (claude slash command, codex AGENTS.md dispatch) extend this.
 */
export interface BaseHandoffOptions {
  adapter: Adapter;
  targetDir: string;
  mode: AuditMode;
  abortSignal?: AbortSignal;
  debug?: boolean;
  focus?: string;
  expectedBehaviors?: string;
  liveTarget?: string;
  /** Continue latest non-complete audit for this mode instead of starting fresh. */
  resume?: boolean;
  /**
   * Phase IDs the orchestrator wants the agents to skip (refresh-fallback
   * policy). Surfaced in `audit-context.md`; the agents are expected to honor
   * it and record skips in `audit-state.json`.
   */
  excludePhases?: string[];
  /** Persisted via `audit-context.md`; agents stamp `triggered_via` on the audit record. */
  triggeredVia?: string;
  /** Model recorded on engine-owned audit entries. */
  model?: string;
  /** Force Git-unavailable behavior even when the target has a .git directory. */
  noGit?: boolean;
  /** Optional Claude plugin path reused by direct artifact-repair turns. */
  pluginDir?: string;
}

/** Per-run state shared between the common skeleton and the platform-specific drive. */
export interface HandoffRunContext {
  resultsDir: string;
  stateStore: StateStore;
  /** Audit IDs that existed before this run, so we can identify the new/resumed record. */
  knownIds: Set<string>;
  resumeAudit: AuditRecord | null;
  activeAudit: AuditRecord | null;
  command: CommandDef;
  engineOwnsState: boolean;
  /** Synthetic id used for events until the real audit_id is read back from state. */
  provisionalAuditId: string;
  phase: PhaseDef;
  startedAt: number;
  stopWatch: () => void;
  stopPoll: () => void;
}

/** Aggregate outcome a platform's adapter drive reports back to the skeleton. */
export interface HandoffDriveResult {
  usd: number;
  tokens: { input: number; output: number };
  ok: boolean;
  errorMsg: string | undefined;
}

/**
 * Shared skeleton for the headless handoff drivers. Both platforms hand the
 * whole audit off to the native runtime in one adapter session. For the core
 * lite/balanced/deep modes the driver owns audit-state creation, resume
 * recovery, artifact-derived phase transitions, and final status; agents own
 * analysis and artifacts. Specialized modes retain their dedicated state
 * contracts. The driver also streams events and watches findings.
 *
 * The only real per-platform differences are the trigger and the retry policy
 * around the adapter call; those live in `phaseTitleSuffix()` and
 * `driveAdapter()`. Everything else — the context file, the state snapshot, the
 * findings watcher, the progress poller, and the finalize/emit dance — is
 * identical and lives here.
 *
 * Differences from the per-phase `Orchestrator`:
 *   - One adapter call instead of one per phase.
 *   - No phase-graph topo-sort, no per-phase quarantine of partial output (the
 *     native runtime handles its own resume on the next run).
 *   - `--max-cost` is observed only at the finish event (no mid-stream abort for
 *     cost). The abort signal still works.
 */
export abstract class BaseHandoff<O extends BaseHandoffOptions = BaseHandoffOptions> {
  readonly bus = new OrchestratorBus();

  constructor(protected readonly opts: O) {}

  on(listener: (e: OrchestratorEvent) => void | Promise<void>): () => void {
    return this.bus.on(listener);
  }

  /** Suffix for the synthetic phase title, e.g. "slash command" / "codex dispatch". */
  protected abstract phaseTitleSuffix(): string;

  /**
   * Drive the underlying adapter to completion, applying any platform-specific
   * retry policy, and report the aggregate cost / outcome. Implementations emit
   * `phaseAdapterEvent` (and any `rateLimits`) on `this.bus` as they stream.
   */
  protected abstract driveAdapter(ctx: HandoffRunContext): Promise<HandoffDriveResult>;

  async run(): Promise<OrchestratorResult> {
    const ctx = await this.setup();
    let result: HandoffDriveResult;
    try {
      result = await this.driveAdapter(ctx);
      if (result.ok && ctx.engineOwnsState && this.opts.abortSignal?.aborted !== true) {
        try {
          result = await this.repairMissingArtifacts(ctx, result);
        } catch (err) {
          await this.bus.emit({
            kind: "phaseAdapterEvent",
            auditId: ctx.provisionalAuditId,
            phase: ctx.phase,
            event: {
              kind: "textDelta",
              text: `[artifact-gate] repair orchestration failed; continuing to deterministic final validation: ${(err as Error).message}\n`,
            },
          }).catch(() => {});
        }
      }
    } finally {
      ctx.stopWatch();
      ctx.stopPoll();
    }
    return this.finalize(ctx, result);
  }

  /**
   * Whole-mode handoffs normally let the native runtime run the complete
   * pipeline in one turn. If that turn reports success but required artifacts
   * are still missing, issue only the bounded, phase-local repair turns
   * declared by the canonical command contract. Finalize revalidates all
   * contracts independently, so a repair agent cannot self-certify success.
   */
  private async repairMissingArtifacts(
    ctx: HandoffRunContext,
    initial: HandoffDriveResult,
  ): Promise<HandoffDriveResult> {
    let aggregate = initial;
    const gateOptions = this.artifactGateOptions(ctx);
    const state = await ctx.stateStore.load().catch(() => null);
    const audit = ctx.activeAudit
      ? state?.audits.find((entry) => entry.audit_id === ctx.activeAudit!.audit_id)
      : null;

    for (const phaseDef of ctx.command.phases) {
      if (this.opts.abortSignal?.aborted === true) break;
      if (audit?.phases[phaseDef.id]?.status === "skipped") continue;
      const contract = phaseDef.completion;
      if (!contract || contract.enforcement === "advisory" || contract.repair_attempts === 0) continue;

      let gate = await evaluatePhaseArtifacts(phaseDef, ctx.resultsDir, gateOptions);
      for (let attempt = 1; !gate.ok && attempt <= contract.repair_attempts; attempt++) {
        const failures = formatArtifactFailures(gate);
        const prompt = this.buildArtifactRepairPrompt(phaseDef, failures, attempt, contract.repair_attempts);
        await this.bus.emit({
          kind: "phaseAdapterEvent",
          auditId: ctx.provisionalAuditId,
          phase: ctx.phase,
          event: {
            kind: "textDelta",
            text: `[artifact-gate] repairing ${phaseDef.id} (${attempt}/${contract.repair_attempts}): ${failures.join("; ")}\n`,
          },
        });
        const repair = await this.driveArtifactRepair(ctx, phaseDef, prompt, attempt);
        aggregate = mergeDriveResults(aggregate, repair);
        gate = await evaluatePhaseArtifacts(phaseDef, ctx.resultsDir, gateOptions);
      }
    }
    return aggregate;
  }

  private artifactGateOptions(ctx: HandoffRunContext): { notBeforeMs?: number } {
    if (!ctx.engineOwnsState || !ctx.activeAudit) return {};
    const notBeforeMs = Date.parse(ctx.activeAudit.started_at);
    return Number.isFinite(notBeforeMs) ? { notBeforeMs } : {};
  }

  private buildArtifactRepairPrompt(
    phase: PhaseDef,
    failures: string[],
    attempt: number,
    maxAttempts: number,
  ): string {
    return [
      `Artifact-only repair ${attempt}/${maxAttempts} for ${phase.id} — ${phase.title}.`,
      `Target directory: ${this.opts.targetDir}`,
      `The audit already ran. Inspect existing outputs and write only the missing or invalid phase-owned artifacts below.`,
      `Do not rerun completed phases, modify unrelated evidence, ask questions, or edit vigolium-results/audit-state.json.`,
      ...failures.map((failure) => `- ${failure}`),
      `Finish immediately after writing the repaired artifacts; the trusted engine validates them independently.`,
    ].join("\n");
  }

  private async driveArtifactRepair(
    ctx: HandoffRunContext,
    phaseDef: PhaseDef,
    userPrompt: string,
    attempt: number,
  ): Promise<HandoffDriveResult> {
    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let ok = false;
    let errorMsg: string | undefined;

    try {
      for await (const event of this.opts.adapter.run({
        userPrompt,
        cwd: this.opts.targetDir,
        bypassPermissions: true,
        disallowedTools: ["AskUserQuestion"],
        ...(this.opts.pluginDir !== undefined ? { pluginDir: this.opts.pluginDir } : {}),
        ...(this.opts.model !== undefined ? { model: this.opts.model } : {}),
        ...(this.opts.abortSignal !== undefined ? { abortSignal: this.opts.abortSignal } : {}),
        ...(this.opts.debug ? { debug: true } : {}),
        label: `${this.opts.mode}:${phaseDef.id}:artifact-repair-${attempt}`,
      })) {
        await this.bus.emit({
          kind: "phaseAdapterEvent",
          auditId: ctx.provisionalAuditId,
          phase: ctx.phase,
          event,
        });
        if (event.kind === "rateLimits") {
          await this.bus.emit({ kind: "rateLimits", auditId: ctx.provisionalAuditId, data: event.data });
        } else if (event.kind === "error") {
          errorMsg = event.cause.message;
        } else if (event.kind === "finish") {
          usd += event.usd;
          tokens = {
            input: tokens.input + event.tokens.input,
            output: tokens.output + event.tokens.output,
          };
          ok = event.ok;
          if (!event.ok) errorMsg = event.reason;
        }
      }
    } catch (err) {
      errorMsg = (err as Error).message;
    }

    return { usd, tokens, ok, errorMsg };
  }

  private async setup(): Promise<HandoffRunContext> {
    const resultsDir = join(this.opts.targetDir, "vigolium-results");
    await mkdir(resultsDir, { recursive: true });
    const variant = this.opts.adapter.platform === "codex" ? "sdk" : "default";
    const command = await getContentLoader().loadCommand(this.opts.mode, { variant });
    const engineOwnsState = ENGINE_STATE_MODES.has(this.opts.mode);

    // Snapshot existing audit IDs before an engine-owned record is appended so
    // the poller still recognizes the new record as belonging to this run.
    const stateStore = new StateStore(resultsDir);
    const before = await stateStore.load().catch(() => ({ schema_version: 1 as const, audits: [] as AuditRecord[] }));
    const knownIds = new Set(before.audits.map((a) => a.audit_id));
    const resumeAudit = this.opts.resume ? findResumableAudit(before.audits, this.opts.mode) : null;

    let activeAudit: AuditRecord | null = null;
    if (engineOwnsState) {
      if (resumeAudit) {
        activeAudit = resumeAudit;
        await stateStore.updateAudit(activeAudit.audit_id, { status: "in_progress", completed_at: null });
      } else {
        const git = this.opts.noGit
          ? { available: false, branch: null, commit: null, repository: null }
          : probeGit(this.opts.targetDir);
        const auditId = buildAuditId();
        if (before.audits.length > 0) {
          await archivePriorCoreArtifacts(resultsDir, auditId);
        }
        activeAudit = newAuditRecord({
          audit_id: auditId,
          mode: this.opts.mode,
          agent_sdk: this.opts.adapter.id,
          model: this.opts.model ?? null,
          commit: git.commit,
          branch: git.branch,
          repository: git.repository,
          historyAvailable: git.available,
          phaseIds: command.phases.map((phase) => phase.id),
          ...(this.opts.focus || this.opts.expectedBehaviors
            ? {
                context: {
                  ...(this.opts.focus ? { focus: this.opts.focus } : {}),
                  ...(this.opts.expectedBehaviors
                    ? { expected_behaviors: this.opts.expectedBehaviors }
                    : {}),
                },
              }
            : {}),
          ...(this.opts.triggeredVia ? { triggeredVia: this.opts.triggeredVia } : {}),
        });
        await stateStore.appendAudit(activeAudit);
      }

      const gitAvailable = this.opts.noGit ? false : probeGit(this.opts.targetDir).available;
      const exclusions = new Set(this.opts.excludePhases ?? []);
      for (const phaseDef of command.phases) {
        const skipReason = phaseDef.requires_git && !gitAvailable
          ? "requires_git but target has no local history"
          : exclusions.has(phaseDef.id)
            ? "excluded by orchestrator directive"
            : null;
        if (skipReason) {
          await stateStore.updatePhase(activeAudit.audit_id, phaseDef.id, {
            status: "skipped",
            error: skipReason,
          });
          continue;
        }

        // Artifact sufficiency recovers completed work even when a previous
        // handoff died before it could persist a phase transition.
        if (resumeAudit && phaseDef.completion) {
          const gate = await evaluatePhaseArtifacts(phaseDef, resultsDir);
          if (gate.ok) {
            await stateStore.updatePhase(activeAudit.audit_id, phaseDef.id, {
              status: "complete",
              completed_at: new Date().toISOString(),
            });
          } else if (
            activeAudit.phases[phaseDef.id]?.status === "complete" &&
            phaseDef.completion.enforcement === "required"
          ) {
            await stateStore.updatePhase(activeAudit.audit_id, phaseDef.id, {
              status: "pending",
              error: `artifact contract failed during resume: ${formatArtifactFailures(gate).join("; ")}`,
            });
          }
        }
      }
    }

    await writeAuditContext(resultsDir, {
      ...(this.opts.resume ? { resume: true } : {}),
      ...(this.opts.triggeredVia !== undefined ? { triggeredVia: this.opts.triggeredVia } : {}),
      ...(this.opts.excludePhases !== undefined ? { excludePhases: this.opts.excludePhases } : {}),
      ...(this.opts.focus !== undefined ? { focus: this.opts.focus } : {}),
      ...(this.opts.expectedBehaviors !== undefined ? { expectedBehaviors: this.opts.expectedBehaviors } : {}),
      ...(engineOwnsState ? { engineOwnsState: true } : {}),
    });

    // Specialized handoffs may still create their own state record. Core audit
    // modes use the engine-created ID immediately.
    const provisionalAuditId = activeAudit?.audit_id ?? `handoff-${Date.now().toString(36)}`;
    const phase: PhaseDef = {
      id: "handoff",
      title: `${this.opts.mode} (${this.phaseTitleSuffix()})`,
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
    // Poll audit-state.json so per-phase progress shows up on the event bus even
    // though the adapter only emits one event stream for the whole audit.
    const stopPoll = startHandoffPoller({
      resultsDir,
      bus: this.bus,
      knownAuditIds: knownIds,
      ...(activeAudit || resumeAudit
        ? { trackedAuditIds: new Set([activeAudit?.audit_id ?? resumeAudit!.audit_id]) }
        : {}),
      provisionalAuditId,
    });

    return {
      resultsDir,
      stateStore,
      knownIds,
      resumeAudit,
      activeAudit,
      command,
      engineOwnsState,
      provisionalAuditId,
      phase,
      startedAt: Date.now(),
      stopWatch,
      stopPoll,
    };
  }

  private async finalize(ctx: HandoffRunContext, result: HandoffDriveResult): Promise<OrchestratorResult> {
    const { usd, tokens, ok } = result;
    let errorMsg = result.errorMsg;
    const durationMs = Date.now() - ctx.startedAt;

    const after = await ctx.stateStore.load().catch(() => ({ schema_version: 1 as const, audits: [] as AuditRecord[] }));
    const resumeAudit = ctx.resumeAudit;
    const newAudit = [...after.audits].reverse().find((a) => !ctx.knownIds.has(a.audit_id));
    const resumedAudit = resumeAudit ? after.audits.find((a) => a.audit_id === resumeAudit.audit_id) : undefined;
    const engineAudit = ctx.activeAudit
      ? after.audits.find((audit) => audit.audit_id === ctx.activeAudit!.audit_id) ?? ctx.activeAudit
      : undefined;
    const observedAudit = engineAudit ?? newAudit ?? resumedAudit;
    const finalAuditId = observedAudit?.audit_id ?? ctx.provisionalAuditId;

    // Whole-mode handoffs still let the native runtime coordinate subagents,
    // but the engine has the final word on completion. Evaluate every declared
    // artifact contract before trusting the handoff's terminal status.
    const failedGatePhases: string[] = [];
    let artifactSufficient = true;
    try {
      for (const phaseDef of ctx.command.phases) {
        if (observedAudit?.phases[phaseDef.id]?.status === "skipped") continue;
        if (!phaseDef.completion) {
          artifactSufficient = false;
          continue;
        }
        const gate = await evaluatePhaseArtifacts(
          phaseDef,
          ctx.resultsDir,
          this.artifactGateOptions(ctx),
        );
        if (gate.ok) {
          if (ctx.engineOwnsState && observedAudit?.phases[phaseDef.id] !== undefined) {
            await ctx.stateStore.updatePhase(observedAudit.audit_id, phaseDef.id, {
              status: "complete",
              completed_at: new Date().toISOString(),
            });
          }
          continue;
        }

        const detail = formatArtifactFailures(gate).join("; ");
        const advisory = phaseDef.completion.enforcement === "advisory";
        if (!advisory) {
          failedGatePhases.push(phaseDef.id);
          artifactSufficient = false;
        }
        await this.bus.emit({
          kind: "phaseAdapterEvent",
          auditId: finalAuditId,
          phase: ctx.phase,
          event: {
            kind: "textDelta",
            text: `[artifact-gate] ${phaseDef.id} ${advisory ? "advisory incomplete" : "incomplete"}: ${detail}\n`,
          },
        });
        if (ctx.engineOwnsState && observedAudit?.phases[phaseDef.id] !== undefined) {
          await ctx.stateStore.updatePhase(
            observedAudit.audit_id,
            phaseDef.id,
            advisory
              ? { status: "complete", completed_at: new Date().toISOString() }
              : {
                  status: "failed",
                  failed_at: new Date().toISOString(),
                  error: `artifact contract failed: ${detail}`,
                },
          );
        }
      }
    } catch (err) {
      failedGatePhases.push("contract-load");
      errorMsg = `artifact contract evaluation failed: ${(err as Error).message}`;
    }

    const recoveredByArtifacts = ctx.engineOwnsState && artifactSufficient;
    const handoffOk = ok || recoveredByArtifacts;
    const status = failedGatePhases.length > 0
      ? "failed"
      : ctx.engineOwnsState
        ? handoffOk
          ? "complete"
          : this.opts.abortSignal?.aborted === true
            ? "aborted"
            : "failed"
        : deriveHandoffStatus({
            recordedStatus: observedAudit?.status,
            aborted: this.opts.abortSignal?.aborted === true,
            ok,
          });
    const effectiveOk = handoffOk && failedGatePhases.length === 0;
    if (ctx.engineOwnsState && observedAudit) {
      await ctx.stateStore.updateAudit(observedAudit.audit_id, {
        status,
        completed_at: new Date().toISOString(),
        usage: {
          input_tokens: tokens.input,
          output_tokens: tokens.output,
          cost_usd: round2(usd),
        },
      });
    } else if (failedGatePhases.length > 0 && observedAudit) {
      await ctx.stateStore.updateAudit(observedAudit.audit_id, {
        status: "failed",
        completed_at: new Date().toISOString(),
      });
    }
    if (effectiveOk && !ok && recoveredByArtifacts) errorMsg = undefined;
    if (!effectiveOk && errorMsg === undefined && failedGatePhases.length > 0) {
      errorMsg = `artifact contracts failed for phases: ${failedGatePhases.join(", ")}`;
    }

    const findings = await summarizeFindings(ctx.resultsDir);

    await this.bus.emit({
      kind: "phaseEnd",
      auditId: finalAuditId,
      phase: ctx.phase,
      ok: effectiveOk,
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
      failedPhases: failedGatePhases,
      skippedPhases: [],
    };
  }
}

function mergeDriveResults(
  current: HandoffDriveResult,
  next: HandoffDriveResult,
): HandoffDriveResult {
  return {
    usd: current.usd + next.usd,
    tokens: {
      input: current.tokens.input + next.tokens.input,
      output: current.tokens.output + next.tokens.output,
    },
    // The original whole-mode handoff succeeded. A repair turn's terminal
    // status is not authoritative; deterministic gates decide final success.
    ok: current.ok,
    errorMsg: current.errorMsg,
  };
}
