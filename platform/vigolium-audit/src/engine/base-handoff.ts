import { mkdir } from "fs/promises";
import { join } from "path";
import type { Adapter } from "../adapters/adapter.js";
import { writeAuditContext } from "./audit-context.js";
import { OrchestratorBus, type OrchestratorEvent } from "./events.js";
import { startFindingsWatcher, summarizeFindings } from "./findings.js";
import { type OrchestratorResult } from "./orchestrator.js";
import { StateStore, findResumableAudit } from "./state.js";
import { deriveHandoffStatus, startHandoffPoller } from "./handoff-poll.js";
import { round2 } from "./util.js";
import type { AuditMode, AuditRecord, PhaseDef } from "./types.js";

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
}

/** Per-run state shared between the common skeleton and the platform-specific drive. */
export interface HandoffRunContext {
  resultsDir: string;
  stateStore: StateStore;
  /** Audit IDs that existed before this run, so we can identify the new/resumed record. */
  knownIds: Set<string>;
  resumeAudit: AuditRecord | null;
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
 * whole audit off to the native runtime in one adapter session — the agents
 * themselves manage `vigolium-results/audit-state.json` (create / resume), spawn
 * sub-agents, and write findings. This driver only kicks off the run, streams
 * events out for the renderer, and reads state back when it finishes.
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
    } finally {
      ctx.stopWatch();
      ctx.stopPoll();
    }
    return this.finalize(ctx, result);
  }

  private async setup(): Promise<HandoffRunContext> {
    const resultsDir = join(this.opts.targetDir, "vigolium-results");
    await mkdir(resultsDir, { recursive: true });

    await writeAuditContext(resultsDir, {
      ...(this.opts.resume ? { resume: true } : {}),
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
    const resumeAudit = this.opts.resume ? findResumableAudit(before.audits, this.opts.mode) : null;

    // Synthetic event metadata so the existing line/JSON loggers can render the
    // handoff stream. The real audit_id is read back from audit-state.json after
    // the run; until then, events use a provisional id.
    const provisionalAuditId = `handoff-${Date.now().toString(36)}`;
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
      ...(resumeAudit ? { trackedAuditIds: new Set([resumeAudit.audit_id]) } : {}),
      provisionalAuditId,
    });

    return {
      resultsDir,
      stateStore,
      knownIds,
      resumeAudit,
      provisionalAuditId,
      phase,
      startedAt: Date.now(),
      stopWatch,
      stopPoll,
    };
  }

  private async finalize(ctx: HandoffRunContext, result: HandoffDriveResult): Promise<OrchestratorResult> {
    const { usd, tokens, ok, errorMsg } = result;
    const durationMs = Date.now() - ctx.startedAt;

    const after = await ctx.stateStore.load().catch(() => ({ schema_version: 1 as const, audits: [] as AuditRecord[] }));
    const resumeAudit = ctx.resumeAudit;
    const newAudit = [...after.audits].reverse().find((a) => !ctx.knownIds.has(a.audit_id));
    const resumedAudit = resumeAudit ? after.audits.find((a) => a.audit_id === resumeAudit.audit_id) : undefined;
    const observedAudit = newAudit ?? resumedAudit;
    const finalAuditId = observedAudit?.audit_id ?? ctx.provisionalAuditId;
    // The agents may leave the audit `in_progress` if the trigger returned
    // without writing a terminal status (truncation, partial run).
    // audit-state.json preserves the in_progress record so a future run can resume.
    const status = deriveHandoffStatus({
      recordedStatus: observedAudit?.status,
      aborted: this.opts.abortSignal?.aborted === true,
      ok,
    });

    const findings = await summarizeFindings(ctx.resultsDir);

    await this.bus.emit({
      kind: "phaseEnd",
      auditId: finalAuditId,
      phase: ctx.phase,
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

