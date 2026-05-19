import { mkdir, readdir, readFile, rename, rm, stat, unlink } from "fs/promises";
import { join, relative } from "path";
import { existsSync, readdirSync, statSync, watch as fsWatch } from "fs";
import type { Adapter } from "../adapters/adapter.js";
import type { ContentLoader, ContentVariant } from "../content-loader.js";
import { OrchestratorBus, type OrchestratorEvent } from "./events.js";
import { scheduleBatches, topologicalOrder } from "./phase.js";
import { StateStore, buildAuditId, newAuditRecord } from "./state.js";
import type { AuditContext, AuditMode, AuditRecord, CommandDef, PhaseDef } from "./types.js";
import { listTrackedFiles, probeGit } from "./git.js";
import { atomicWrite, compact, parseIntEnv, round2, sleepInterruptible } from "./util.js";
import { adapterEventHasQuotaLimit, adapterEventHasRetryableError, isTransientError, valueContainsQuotaLimit } from "../adapters/claude-events.js";

export interface OrchestratorOptions {
  adapter: Adapter;
  loader: ContentLoader;
  targetDir: string;
  mode: AuditMode;
  archonDir?: string;
  /** When set, hard-abort the audit if total cost exceeds this many USD. */
  maxCost?: number;
  /** Default model. Per-agent frontmatter still wins. */
  defaultModel?: string;
  /** v1: only "skip-and-continue" or "strict" (abort on first phase failure). */
  failurePolicy?: "skip-and-continue" | "strict";
  /** Resume the latest in-progress audit for this mode if one exists. */
  resume?: boolean;
  /** External signal to abort the audit cleanly. */
  abortSignal?: AbortSignal;
  /**
   * When false (default), filter out tools that block in non-interactive
   * runtime — currently `AskUserQuestion`. Set true when running with the
   * Ink TUI which can satisfy interactive prompts.
   */
  interactive?: boolean;
  /**
   * Max retries when a phase fails with `transient: true` *before any
   * progress events* were emitted. Default: 3 (with 1s/2s/4s backoff).
   * Mid-stream errors are not retried to avoid duplicate event delivery.
   */
  transientRetries?: number;
  /**
   * Max retries when a phase fails because Claude's usage limit was hit
   * (detected from the streamed "You've hit your limit · resets …" message).
   * Default: 5. Overridable via `ARCHON_QUOTA_MAX_RETRIES` env var.
   * Unlike ordinary transient retries, the quota path *does* retry mid-stream
   * — the alternative is throwing away the whole audit, and progress events
   * from the failed attempt are already on disk (findings-draft, state).
   */
  quotaMaxRetries?: number;
  /**
   * Delay between quota-limit retry attempts in milliseconds. Default: 3,600,000
   * (1 hour). Overridable via `ARCHON_QUOTA_BACKOFF_MS` env var. Tests set this
   * to a tiny value so the retry loop doesn't actually sleep an hour.
   */
  quotaBackoffMs?: number;
  /** Verbose adapter mode: forwarded to AdapterRunInput.debug per phase. */
  debug?: boolean;
  /**
   * When true, strip raw scanner output / draft findings / codeql/semgrep
   * workspaces from `archon/` after a `complete` run. Always kept when
   * stripping runs: durable state JSON, `findings/`, `findings-theoretical/`,
   * `attack-surface/`, `confirm-workspace/` (when relevant), and top-level
   * `*.md` reports. Stripping is skipped on `failed`/`aborted` so users can
   * resume or debug.
   */
  stripRaw?: boolean;
  /**
   * User-supplied focus prose (already loaded from --focus-file). Injected
   * as a soft hint into every phase's user prompt and persisted into the
   * audit record so chained modes can inherit it.
   */
  focus?: string;
  /**
   * User-supplied expected-behaviors prose (already loaded from
   * --expected-behaviors-file). Injected as a hard exclusion into every
   * phase's user prompt and persisted into the audit record.
   */
  expectedBehaviors?: string;
  /**
   * Live HTTP(S) endpoint for `confirm` mode. Substituted for `$ARGUMENTS`
   * in the command body and surfaced as a `Live target:` header in every
   * phase's user prompt. CLI is responsible for validation (scheme +
   * confirm-only).
   */
  liveTarget?: string;
  /**
   * Phase IDs to skip unconditionally for this run, in addition to the
   * existing `requires_git && !git.available` skip set. Used by the
   * `refresh` router to drop phases like Advisory Hunting / Commit
   * Archaeology / Patch Bypass when falling back to a fresh deep audit.
   * Skipped phases are recorded with status `skipped` in audit-state.json.
   */
  excludePhases?: string[];
  /**
   * Suffix appended to event auditId / log tags to disambiguate when
   * multiple modes run concurrently against the same target. Optional;
   * set by the parallel-modes runner.
   */
  modeTag?: string;
  /**
   * Persisted to `triggered_via` on the AuditRecord for provenance. Set by
   * the `refresh` router so reports can attribute the run to the user's
   * actual invocation even though `mode` records the resolved underlying
   * mode (revisit / deep) the agents need to see.
   */
  triggeredVia?: string;
  /**
   * When true (default), honor `parallel_with` and run mutually-declared
   * sibling phases concurrently. Pass false to force purely sequential
   * execution — useful for debugging interleaved logs or for caps that
   * can't tolerate concurrent token spend.
   */
  parallel?: boolean;
  /**
   * When true, skip git probing entirely: `requires_git` phases are
   * dropped (as if no .git existed) and the audit record's
   * commit/branch/repository fields are left null. Plumbed from the CLI's
   * `--no-git` flag.
   */
  noGit?: boolean;
}

export interface OrchestratorResult {
  auditId: string;
  status: AuditRecord["status"];
  totalUsd: number;
  totalTokens: { input: number; output: number };
  findings: { total: number; bySeverity: Record<string, number> };
  failedPhases: string[];
  skippedPhases: string[];
}

export class Orchestrator {
  readonly bus = new OrchestratorBus();
  private readonly state: StateStore;
  private totalUsd = 0;
  private totalIn = 0;
  private totalOut = 0;
  private warnedAtUsd = 0;
  /**
   * Internal abort controller fired when the cost cap is breached. Composed
   * with `opts.abortSignal` so adapters see a single signal that fires on
   * either user-initiated SIGINT or budget exhaustion.
   */
  private readonly costAbort = new AbortController();

  constructor(private readonly opts: OrchestratorOptions) {
    this.state = new StateStore(opts.archonDir ?? join(opts.targetDir, "archon"));
  }

  /**
   * Combined abort signal: user SIGINT or cost cap. Adapter calls listen to
   * this so they terminate the moment either fires.
   */
  private combinedAbortSignal(): AbortSignal {
    const user = this.opts.abortSignal;
    if (!user) return this.costAbort.signal;
    if (user.aborted) return user;
    return AbortSignal.any([user, this.costAbort.signal]);
  }

  on(listener: (e: OrchestratorEvent) => void | Promise<void>): () => void {
    return this.bus.on(listener);
  }

  async run(): Promise<OrchestratorResult> {
    const archonDir = this.opts.archonDir ?? join(this.opts.targetDir, "archon");
    await mkdir(archonDir, { recursive: true });

    const command = await this.opts.loader.loadCommand(this.opts.mode, { variant: this.contentVariant() });
    const ordered = topologicalOrder(command.phases);
    const git = this.opts.noGit
      ? { available: false, branch: null, commit: null, repository: null }
      : probeGit(this.opts.targetDir);

    const excludeSet = new Set(this.opts.excludePhases ?? []);
    const skipReasons = new Map<string, string>();
    for (const p of ordered) {
      if (p.requires_git && !git.available) {
        skipReasons.set(
          p.id,
          this.opts.noGit
            ? "requires_git, but git checks disabled via --no-git"
            : "requires_git but target has no git history",
        );
      } else if (excludeSet.has(p.id)) {
        skipReasons.set(p.id, "excluded by --mode refresh fresh-fallback policy");
      }
    }
    const runnable = ordered.filter((p) => !skipReasons.has(p.id));
    const skipped = ordered.filter((p) => skipReasons.has(p.id));

    const auditId = await this.resolveAuditId(command, runnable);

    const stopFindingsWatch = this.startFindingsWatcher(archonDir, auditId);
    let watchStopped = false;
    const stopWatchOnce = (): void => {
      if (watchStopped) return;
      watchStopped = true;
      stopFindingsWatch();
    };

    try {
      return await this.runInner({ archonDir, auditId, command, ordered, runnable, skipped, skipReasons });
    } finally {
      stopWatchOnce();
    }
  }

  private async runInner(args: {
    archonDir: string;
    auditId: string;
    command: CommandDef;
    ordered: PhaseDef[];
    runnable: PhaseDef[];
    skipped: PhaseDef[];
    skipReasons: Map<string, string>;
  }): Promise<OrchestratorResult> {
    const { archonDir, auditId, command, ordered, runnable, skipped, skipReasons } = args;

    await this.bus.emit({
      kind: "auditStart",
      auditId,
      mode: this.opts.mode,
      totalPhases: ordered.length,
      runnablePhases: runnable.length,
    });

    for (const phase of skipped) {
      await this.state.updatePhase(auditId, phase.id, { status: "skipped" });
      await this.bus.emit({
        kind: "phaseSkip",
        auditId,
        phase,
        reason: skipReasons.get(phase.id) ?? "skipped",
      });
    }

    const failedPhases: string[] = [];
    let aborted = false;
    const runnableIds = new Set(runnable.map((p) => p.id));
    // Schedule into batches so parallel_with siblings run concurrently. When
    // parallel is disabled, fall back to a single phase per batch — same as
    // walking the topo list serially. Skipped phases (git-gated, refresh
    // fallback) are treated as already-satisfied dependencies so phases that
    // depend on them aren't stranded.
    const phasesForSchedule = runnable.map((p) => ({
      ...p,
      depends_on: p.depends_on.filter((d) => runnableIds.has(d)),
    }));
    const batches = this.opts.parallel === false
      ? phasesForSchedule.map((p) => [p])
      : scheduleBatches(phasesForSchedule);
    let i = 0;
    const total = runnable.length;
    for (const batch of batches) {
      if (this.opts.abortSignal?.aborted || this.costAbort.signal.aborted) {
        aborted = true;
        break;
      }

      // Prep each phase: skip already-complete, reset stale in_progress.
      // Load state once per batch — each phase reads its own status from the
      // same snapshot. runPhase writes through the StateStore's write-lock,
      // so this snapshot is read-only here.
      const auditBefore = (await this.state.load()).audits.find((a) => a.audit_id === auditId);
      const toRun: PhaseDef[] = [];
      for (const phase of batch) {
        const phaseStatus = auditBefore?.phases[phase.id]?.status;
        if (phaseStatus === "complete" || phaseStatus === "skipped") continue;
        if (phaseStatus === "in_progress") {
          const checkpoint = await this.loadCheckpoint(auditId, phase.id);
          if (checkpoint) {
            this.totalUsd += checkpoint.usd;
            this.totalIn += checkpoint.tokens.input;
            this.totalOut += checkpoint.tokens.output;
            await this.bus.emit({
              kind: "phaseAdapterEvent",
              auditId,
              phase,
              event: {
                kind: "textDelta",
                text:
                  `[resume] previous attempt logged $${checkpoint.usd.toFixed(2)}, ` +
                  `${checkpoint.tokens.input}/${checkpoint.tokens.output} tok, ` +
                  `${checkpoint.toolCalls} tool call${checkpoint.toolCalls === 1 ? "" : "s"}` +
                  (checkpoint.lastTool ? ` (last: ${checkpoint.lastTool})` : "") +
                  ` — retrying from scratch\n`,
              },
            });
            await this.clearCheckpoint(auditId, phase.id).catch(() => {});
          }
          await this.state.updatePhase(auditId, phase.id, {
            status: "pending",
            error: "previous run terminated before phase completed; retrying",
          });
          await this.quarantinePartialOutput(auditId, phase);
        }
        toRun.push(phase);
      }
      if (toRun.length === 0) {
        i += batch.length;
        continue;
      }

      // Emit phaseStart for all phases in the batch before running so a
      // concurrent renderer can pin them all on screen up-front.
      const startIndices = new Map<string, number>();
      for (const phase of toRun) {
        i++;
        startIndices.set(phase.id, i);
        await this.bus.emit({ kind: "phaseStart", auditId, phase, index: i, total });
      }

      // Run all phases in the batch concurrently. StateStore serializes its
      // own load+modify+save through an internal mutex, so two phases doing
      // updatePhase at the same time don't lose each other's writes.
      const results = await Promise.all(
        toRun.map((phase) =>
          this.runPhase(auditId, phase, command).then((res) => ({ phase, res })),
        ),
      );
      for (const { phase, res } of results) {
        if (!res.ok) {
          failedPhases.push(phase.id);
          if (this.opts.failurePolicy === "strict") aborted = true;
        }
      }
      if (this.opts.maxCost !== undefined && this.totalUsd >= this.opts.maxCost) {
        aborted = true;
      }
      if (aborted) break;
    }

    const status: AuditRecord["status"] = aborted
      ? "aborted"
      : failedPhases.length === 0
        ? "complete"
        : "failed";
    await this.state.updateAudit(auditId, {
      status,
      completed_at: new Date().toISOString(),
      usage: {
        input_tokens: this.totalIn,
        output_tokens: this.totalOut,
        cost_usd: round2(this.totalUsd),
      },
    });

    const findings = await summarizeFindings(archonDir);
    const tokens = { input: this.totalIn, output: this.totalOut };

    await this.bus.emit({
      kind: "auditEnd",
      auditId,
      status,
      usd: round2(this.totalUsd),
      tokens,
      findings,
    });

    // Snapshot tracked source files into file-state.json so future runs can
    // skip phases whose inputs are unchanged. Only fires on complete audits;
    // failed/aborted runs would taint the baseline. Git-only — when the
    // target isn't a repo, file enumeration is too ambiguous to be useful.
    if (status === "complete") {
      try {
        const files = listTrackedFiles(this.opts.targetDir);
        if (files.length > 0) {
          const completedPhaseIds = ordered
            .filter((p) => !skipReasons.has(p.id) && !failedPhases.includes(p.id))
            .map((p) => p.id);
          await this.state.recordFileSnapshot({
            targetDir: this.opts.targetDir,
            files,
            auditId,
            completedPhaseIds,
          });
        }
      } catch {
        // file-state snapshotting is advisory; never block the audit on it.
      }
    }

    // Strip is the absolute last step so it can't perturb per-phase state,
    // the audit-state.json write, the findings summary, or the auditEnd event.
    // Skipped on failed/aborted runs so users can resume or debug raw output.
    if (status === "complete" && this.opts.stripRaw) {
      await stripRawArtifacts(archonDir, {
        // Lite's historical --strip-raw behavior promotes raw drafts because
        // lite may never materialize full finding directories. Deep/balanced
        // drafts are intermediate debate artifacts and must not be promoted.
        promoteDrafts: this.opts.mode === "lite",
        keepConfirmWorkspace: this.opts.mode === "confirm",
      });
    }

    return {
      auditId,
      status,
      totalUsd: round2(this.totalUsd),
      totalTokens: tokens,
      findings,
      failedPhases,
      skippedPhases: skipped.map((p) => p.id),
    };
  }

  private async resolveAuditId(command: CommandDef, runnable: PhaseDef[]): Promise<string> {
    const state = await this.state.load();
    if (this.opts.resume) {
      // Pick the latest audit for this mode that didn't reach `complete`.
      // `in_progress` covers process-killed-mid-phase; `failed`/`aborted`
      // cover orderly terminal states (cost cap, strict failure, SIGINT).
      // Each is resumable: completed phases are skipped, pending re-runs,
      // stale in_progress phases get quarantined in runPhase prep.
      const existing = [...state.audits].reverse().find(
        (a) =>
          a.mode === command.mode &&
          (a.status === "in_progress" ||
            a.status === "failed" ||
            a.status === "aborted"),
      );
      if (existing) {
        if (existing.status !== "in_progress") {
          await this.state.updateAudit(existing.audit_id, {
            status: "in_progress",
            completed_at: null,
          });
        }
        return existing.audit_id;
      }
    }
    const auditId = buildAuditId();
    const phaseIds = runnable.map((p) => p.id);
    const git = this.opts.noGit
      ? { available: false, branch: null, commit: null, repository: null }
      : probeGit(this.opts.targetDir);
    const context = this.buildAuditContext();
    const record = newAuditRecord({
      audit_id: auditId,
      mode: command.mode as AuditMode,
      agent_sdk: this.opts.adapter.id,
      model: this.opts.defaultModel ?? null,
      commit: git.commit,
      branch: git.branch,
      repository: git.repository,
      phaseIds,
      ...compact({ context, triggeredVia: this.opts.triggeredVia }),
    });
    await this.state.appendAudit(record);
    return auditId;
  }

  private buildAuditContext(): AuditContext | undefined {
    const ctx: AuditContext = {};
    if (typeof this.opts.focus === "string" && this.opts.focus.length > 0) {
      ctx.focus = this.opts.focus;
    }
    if (typeof this.opts.expectedBehaviors === "string" && this.opts.expectedBehaviors.length > 0) {
      ctx.expected_behaviors = this.opts.expectedBehaviors;
    }
    return ctx.focus === undefined && ctx.expected_behaviors === undefined ? undefined : ctx;
  }

  private async runPhase(
    auditId: string,
    phase: PhaseDef,
    command: CommandDef,
  ): Promise<{ ok: boolean; usd: number; tokens: { input: number; output: number }; durationMs: number; error?: string }> {
    const startedAt = new Date().toISOString();
    await this.state.updatePhase(auditId, phase.id, { status: "in_progress", started_at: startedAt });

    const { systemPrompt, userPrompt, tools } = await this.buildPrompts(phase, command, auditId);
    const transientRetries = this.opts.transientRetries ?? 3;
    const transientBaseDelayMs = 1000;
    const quotaMaxRetries = this.opts.quotaMaxRetries ?? parseIntEnv(process.env.ARCHON_QUOTA_MAX_RETRIES, 5);
    const quotaDelayMs = this.opts.quotaBackoffMs ?? parseIntEnv(process.env.ARCHON_QUOTA_BACKOFF_MS, 60 * 60 * 1000);
    const maxAttempts = Math.max(transientRetries, quotaMaxRetries);

    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let durationMs = 0;
    let ok = false;
    let error: string | undefined;

    for (let attempt = 0; attempt <= maxAttempts; attempt++) {
      const result = await this.driveAdapterOnce({
        systemPrompt,
        userPrompt,
        tools,
        auditId,
        phase,
        command,
      });
      usd = result.usd;
      tokens = result.tokens;
      durationMs = result.durationMs;
      ok = result.ok;
      error = result.error;

      if (ok) break;

      // Quota-limit retries: long wall-clock sleep (default 1h × 5), bypass the
      // sawProgress short-circuit since the user explicitly wants us to wait
      // out the quota reset rather than fail the audit.
      if (result.quotaLimit) {
        if (attempt >= quotaMaxRetries) break;
        const minutes = Math.round(quotaDelayMs / 60000);
        await this.bus.emit({
          kind: "phaseAdapterEvent",
          auditId,
          phase,
          event: {
            kind: "textDelta",
            text: `[quota limit hit — sleeping ${minutes}m before retry ${attempt + 1}/${quotaMaxRetries} — ${error ?? "usage limit reached"}]\n`,
          },
        });
        await sleepInterruptible(quotaDelayMs, this.combinedAbortSignal());
        if (this.combinedAbortSignal().aborted) break;
        continue;
      }

      // Ordinary transient retry: short exponential backoff, only if no
      // progress events were emitted (mid-stream retry would replay events).
      if (!result.transient || result.sawProgress || attempt >= transientRetries) break;
      const delay = transientBaseDelayMs * Math.pow(2, attempt);
      await this.bus.emit({
        kind: "phaseAdapterEvent",
        auditId,
        phase,
        event: { kind: "textDelta", text: `[retry ${attempt + 1}/${transientRetries} after ${delay}ms — ${error ?? "transient error"}]\n` },
      });
      await new Promise((r) => setTimeout(r, delay));
    }

    this.totalUsd += usd;
    this.totalIn += tokens.input;
    this.totalOut += tokens.output;
    this.maybeWarnCost(auditId);

    if (!ok && !error) {
      ok = false;
      error = "phase finished without a success event";
    }

    if (!ok) {
      await this.quarantinePartialOutput(auditId, phase);
    }

    await this.state.updatePhase(auditId, phase.id, {
      status: ok ? "complete" : "failed",
      ...(ok
        ? { completed_at: new Date().toISOString() }
        : {
            failed_at: new Date().toISOString(),
            ...(error !== undefined ? { error } : {}),
          }),
    });
    await this.bus.emit({
      kind: "phaseEnd",
      auditId,
      phase,
      ok,
      usd,
      tokens,
      durationMs,
      ...(error !== undefined ? { error } : {}),
    });

    return { ok, usd, tokens, durationMs, ...(error !== undefined ? { error } : {}) };
  }

  private async buildPrompts(
    phase: PhaseDef,
    command: CommandDef,
    auditId: string,
  ): Promise<{ systemPrompt: string; userPrompt: string; tools: string[] }> {
    let systemPrompt: string;
    let tools: string[] = [];
    if (phase.agent) {
      const agent = await this.opts.loader.loadAgent(phase.agent, { variant: this.contentVariant() });
      systemPrompt = agent.body.trim();
      tools = agent.tools ?? [];
    } else {
      // Inline phase: derive tools from the command-def's allowed-tools field.
      systemPrompt =
        `You are an inline executor for the "${command.mode}" audit pipeline. ` +
        `Run phase "${phase.id}: ${phase.title}" exactly as specified in the command-def below.\n\n` +
        command.body;
      tools = parseToolsField(command.allowed_tools_raw);
    }
    if (!this.opts.interactive) {
      // AskUserQuestion blocks indefinitely in non-interactive runtime; strip it.
      tools = tools.filter((t) => !/^AskUserQuestion(\b|\()/i.test(t));
    }
    const userPrompt = composeUserPrompt(phase, command, auditId, this.opts.targetDir, compact({
      focus: this.opts.focus,
      expectedBehaviors: this.opts.expectedBehaviors,
      liveTarget: this.opts.liveTarget,
    }));
    return { systemPrompt, userPrompt, tools };
  }

  private contentVariant(): ContentVariant {
    return this.opts.adapter.platform === "codex" ? "sdk" : "default";
  }

  private async driveAdapterOnce(args: {
    systemPrompt: string;
    userPrompt: string;
    tools: string[];
    auditId: string;
    phase: PhaseDef;
    command: CommandDef;
  }): Promise<{
    ok: boolean;
    usd: number;
    tokens: { input: number; output: number };
    durationMs: number;
    error?: string;
    transient: boolean;
    quotaLimit: boolean;
    sawProgress: boolean;
  }> {
    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let durationMs = 0;
    let ok = false;
    let error: string | undefined;
    let firstError: Error | null = null;
    let transient = false;
    let quotaLimit = false;
    let sawProgress = false;

    const startedAt = Date.now();
    let toolCalls = 0;
    let lastTool: string | undefined;
    const checkpointEvery = 5; // tool calls between checkpoint flushes
    const flushCheckpoint = async (): Promise<void> => {
      await this.writeCheckpoint(args.auditId, args.phase.id, {
        startedAt,
        toolCalls,
        ...(lastTool !== undefined ? { lastTool } : {}),
        usd,
        tokens,
        sawProgress,
      });
    };

    try {
      for await (const event of this.opts.adapter.run({
        systemPrompt: args.systemPrompt,
        userPrompt: args.userPrompt,
        tools: args.tools,
        cwd: this.opts.targetDir,
        ...(this.opts.defaultModel ? { model: this.opts.defaultModel } : {}),
        abortSignal: this.combinedAbortSignal(),
        ...(this.opts.debug ? { debug: true } : {}),
        label: `${args.command.mode}:${args.phase.id}`,
      })) {
        await this.bus.emit({ kind: "phaseAdapterEvent", auditId: args.auditId, phase: args.phase, event });
        if (event.kind === "rateLimits") {
          await this.bus.emit({ kind: "rateLimits", auditId: args.auditId, data: event.data });
        }
        if (event.kind === "textDelta" || event.kind === "toolCall") {
          sawProgress = true;
        }
        if (!quotaLimit && adapterEventHasQuotaLimit(event)) {
          quotaLimit = true;
        }
        if (!transient && adapterEventHasRetryableError(event)) {
          transient = true;
        }
        if (event.kind === "toolCall") {
          toolCalls++;
          lastTool = event.tool;
          if (toolCalls % checkpointEvery === 0) {
            // Fire-and-forget: the adapter event loop must not block on a
            // checkpoint write. If it loses a write the next tick will retry.
            void flushCheckpoint().catch(() => {});
          }
        }
        if (event.kind === "finish") {
          usd = event.usd;
          tokens = event.tokens;
          durationMs = event.durationMs;
          ok = event.ok;
          if (!event.ok) error = event.reason;
        }
        if (event.kind === "error" && !firstError) {
          firstError = event.cause;
          transient = transient || event.transient === true || adapterEventHasRetryableError(event);
        }
      }
    } catch (err) {
      firstError = err as Error;
      transient = isTransientError(err);
      quotaLimit = quotaLimit || valueContainsQuotaLimit(err);
    }

    // On success: drop the checkpoint. On failure / abort: keep it so the
    // next resume can surface what was lost.
    if (ok) {
      await this.clearCheckpoint(args.auditId, args.phase.id).catch(() => {});
    } else {
      await flushCheckpoint().catch(() => {});
    }

    if (firstError && !error) {
      error = firstError.message;
    }

    return {
      ok,
      usd,
      tokens,
      durationMs,
      ...(error !== undefined ? { error } : {}),
      transient,
      quotaLimit,
      sawProgress,
    };
  }

  private async quarantinePartialOutput(auditId: string, phase: PhaseDef): Promise<void> {
    const archonDir = this.opts.archonDir ?? join(this.opts.targetDir, "archon");
    const draftsDir = join(archonDir, "findings-draft");
    const archive = join(archonDir, ".archive", auditId, phase.id);
    if (!existsSync(draftsDir)) return;

    // Match drafts to this phase using two signals:
    //   1. Frontmatter `phase_id:` / `phase:` (authoritative when present).
    //   2. Longest filename-prefix match against the audit's phase IDs.
    // Longest-prefix prevents phase "1" from quarantining a "1a-…" draft when
    // both phases exist (deep.md has 1a/1b/2-15, no bare "1", but the rule
    // future-proofs us).
    const allPhaseIds = (await this.opts.loader.loadCommand(this.opts.mode, { variant: this.contentVariant() })).phases.map((p) => p.id);
    const matches: string[] = [];
    for (const entry of readdirSync(draftsDir)) {
      const owner = await detectDraftOwner({ draftsDir, entry, allPhaseIds });
      if (owner === phase.id) matches.push(entry);
    }
    if (matches.length === 0) return;
    await mkdir(archive, { recursive: true });
    for (const f of matches) {
      try {
        await rename(join(draftsDir, f), join(archive, f));
      } catch {
        /* best-effort */
      }
    }
  }

  private checkpointPath(auditId: string, phaseId: string): string {
    const archonDir = this.opts.archonDir ?? join(this.opts.targetDir, "archon");
    return join(archonDir, ".checkpoint", encodePathSegment(auditId), `${encodePathSegment(phaseId)}.json`);
  }

  /**
   * Persist phase progress mid-stream so an interrupted phase leaves a record
   * the next run can surface and bill against the chained budget. The phase
   * itself still has to restart from scratch — adapters don't expose
   * conversation replay so we can't resume mid-conversation.
   */
  private async writeCheckpoint(
    auditId: string,
    phaseId: string,
    data: { startedAt: number; toolCalls: number; lastTool?: string; usd: number; tokens: { input: number; output: number }; sawProgress: boolean },
  ): Promise<void> {
    const payload = {
      audit_id: auditId,
      phase_id: phaseId,
      started_at_ms: data.startedAt,
      updated_at_ms: Date.now(),
      tool_calls: data.toolCalls,
      ...(data.lastTool !== undefined ? { last_tool: data.lastTool } : {}),
      usd: round2(data.usd),
      tokens: data.tokens,
      saw_progress: data.sawProgress,
    };
    await atomicWrite(this.checkpointPath(auditId, phaseId), JSON.stringify(payload, null, 2) + "\n");
  }

  private async clearCheckpoint(auditId: string, phaseId: string): Promise<void> {
    try {
      await unlink(this.checkpointPath(auditId, phaseId));
    } catch {
      /* missing is fine */
    }
  }

  /**
   * Read a checkpoint left behind by a prior interrupted attempt, if any.
   * Returns the cost+tokens that should be rolled into the audit total even
   * though the phase itself will run again from scratch.
   */
  private async loadCheckpoint(
    auditId: string,
    phaseId: string,
  ): Promise<{ usd: number; tokens: { input: number; output: number }; toolCalls: number; lastTool: string | null } | null> {
    const path = this.checkpointPath(auditId, phaseId);
    if (!existsSync(path)) return null;
    try {
      const raw = await readFile(path, "utf8");
      const json = JSON.parse(raw) as {
        usd?: number;
        tokens?: { input: number; output: number };
        tool_calls?: number;
        last_tool?: string;
      };
      return {
        usd: typeof json.usd === "number" ? json.usd : 0,
        tokens: json.tokens ?? { input: 0, output: 0 },
        toolCalls: json.tool_calls ?? 0,
        lastTool: json.last_tool ?? null,
      };
    } catch {
      return null;
    }
  }

  private maybeWarnCost(auditId: string): void {
    if (this.opts.maxCost === undefined) return;
    const cap = this.opts.maxCost;
    const thresholds = [0.5, 0.75, 0.9, 1.0];
    for (const t of thresholds) {
      const at = cap * t;
      if (this.totalUsd >= at && this.warnedAtUsd < at) {
        this.warnedAtUsd = at;
        void this.bus.emit({ kind: "costWarn", auditId, usd: round2(this.totalUsd), cap });
      }
    }
    // At-or-over the cap: fire the internal abort signal so any pending /
    // next adapter call terminates immediately rather than waiting for the
    // between-phase check. AbortController.abort() is idempotent.
    if (this.totalUsd >= cap) this.costAbort.abort();
  }

  private startFindingsWatcher(archonDir: string, auditId: string): () => void {
    return startFindingsWatcher({
      archonDir,
      auditId,
      targetDir: this.opts.targetDir,
      bus: this.bus,
    });
  }
}

/**
 * Watch `archon/findings-draft/` and `archon/findings/` for new `.md` files
 * and emit `findingDiscovered` events on the bus. Used by both the per-phase
 * orchestrator and the slash-command handoff driver.
 *
 * Uses `fs.watch(dir, { recursive: true })`. macOS supports this natively;
 * Linux requires Node ≥ 20.0.0 (the recursive flag was finalized then and is
 * implemented via inotify). On older Node or unusual filesystems the watch
 * may silently stop reporting nested events — drafts written to subdirs
 * won't show up as `+ finding:` lines, but quarantine and final reporting
 * are unaffected because they read the directory directly.
 */
export function startFindingsWatcher(args: {
  archonDir: string;
  auditId: string;
  targetDir: string;
  bus: OrchestratorBus;
}): () => void {
  const { archonDir, auditId, targetDir, bus } = args;
  const findingsDraft = join(archonDir, "findings-draft");
  const findingsFinal = join(archonDir, "findings");
  const findingsTheoretical = join(archonDir, "findings-theoretical");
  const seen = new Set<string>();
  const watchers: Array<{ close: () => void }> = [];
  for (const dir of [findingsDraft, findingsFinal, findingsTheoretical]) {
    mkdir(dir, { recursive: true }).catch(() => {});
    try {
      const w = fsWatch(dir, { recursive: true }, (_eventType, filename) => {
        if (!filename) return;
        if (typeof filename !== "string") return;
        if (!filename.endsWith(".md")) return;
        const full = join(dir, filename);
        // macOS FSEvents prefix-matches paths, so a watcher on `findings/`
        // also fires for sibling `findings-draft/` writes with a filename
        // like `-draft/foo.md` — producing a phantom `findings/-draft/foo.md`
        // that doesn't exist on disk. Drop events whose resolved path isn't
        // a real file inside the watched dir.
        if (!existsSync(full)) return;
        if (seen.has(full)) return;
        seen.add(full);
        void bus.emit({
          kind: "findingDiscovered",
          auditId,
          phaseId: null,
          path: full,
          relPath: relative(targetDir, full),
        });
      });
      watchers.push({ close: () => w.close() });
    } catch {
      /* dir may not exist yet on this platform; ignore */
    }
  }
  return () => watchers.forEach((w) => w.close());
}

/**
 * Decide which phase produced a draft entry. Reads frontmatter from the
 * entry (or its primary `.md` file if it's a directory) and, failing that,
 * falls back to longest-prefix match against the known phase IDs. Returns
 * null when no signal is available so the entry isn't quarantined by mistake.
 */
async function detectDraftOwner(args: {
  draftsDir: string;
  entry: string;
  allPhaseIds: string[];
}): Promise<string | null> {
  const { draftsDir, entry, allPhaseIds } = args;
  const full = join(draftsDir, entry);

  // 1. Frontmatter signal: scan a representative .md inside the entry.
  const mdPaths: string[] = [];
  try {
    const s = statSync(full);
    if (s.isFile() && entry.toLowerCase().endsWith(".md")) {
      mdPaths.push(full);
    } else if (s.isDirectory()) {
      for (const child of readdirSync(full)) {
        if (child.toLowerCase().endsWith(".md")) mdPaths.push(join(full, child));
      }
    }
  } catch {
    return null;
  }
  for (const p of mdPaths) {
    try {
      const head = (await readFile(p, "utf8")).slice(0, 2048);
      const m = head.match(/^[ \t]*(?:phase[_-]?id|phase)\s*:\s*["']?([\w.-]+)["']?\s*$/im);
      if (m && m[1] && allPhaseIds.includes(m[1])) return m[1];
    } catch {
      /* keep trying */
    }
  }

  // 2. Filename-prefix signal: longest matching phase id wins. Case-insensitive
  // because draft naming conventions drift across agents (V1 vs v1, etc.).
  const lower = entry.toLowerCase();
  let best: string | null = null;
  for (const id of allPhaseIds) {
    const pfx = `${id.toLowerCase()}-`;
    if (lower.startsWith(pfx) && (best === null || id.length > best.length)) {
      best = id;
    }
  }
  return best;
}

export function parseToolsField(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function composeUserPrompt(
  phase: PhaseDef,
  command: CommandDef,
  auditId: string,
  targetDir: string,
  context: { focus?: string; expectedBehaviors?: string; liveTarget?: string } = {},
): string {
  // The command body uses $ARGUMENTS as a placeholder for trailing slash-command
  // args. In headless mode there's no slash command, so we substitute the live
  // target (or empty string) before truncating — leaving the literal token
  // would mislead the agent.
  const argSubstitution = context.liveTarget ?? "";
  const bodyWithArgs = command.body.replace(/\$ARGUMENTS\b/g, argSubstitution);
  const lines = [
    `Audit ID: ${auditId}`,
    `Mode: ${command.mode}`,
    `Phase: ${phase.id} — ${phase.title}`,
    `Target directory: ${targetDir}`,
    `State file: archon/audit-state.json`,
  ];
  if (typeof context.liveTarget === "string" && context.liveTarget.length > 0) {
    lines.push(`Live target: ${context.liveTarget}`);
  }
  lines.push(
    ``,
    `Execute this phase as defined in the command-def's prose body.`,
    `When finished, mark phase ${phase.id} complete in archon/audit-state.json.`,
    ``,
    `--- COMMAND-DEF BODY (for reference) ---`,
    bodyWithArgs,
  );
  if (typeof context.focus === "string" && context.focus.length > 0) {
    lines.push(
      ``,
      `--- AUDIT FOCUS (user-supplied) ---`,
      `Prioritize the following areas. This is a hint, not a hard restriction —`,
      `if you discover a high-severity issue outside these areas, still report it.`,
      ``,
      context.focus,
    );
  }
  if (typeof context.expectedBehaviors === "string" && context.expectedBehaviors.length > 0) {
    lines.push(
      ``,
      `--- EXPECTED BEHAVIORS (user-supplied) ---`,
      `The behaviors described below are intentional design decisions, NOT`,
      `vulnerabilities. Do not file findings for issues that match these`,
      `descriptions. If a finding overlaps, note the overlap and exclude it.`,
      ``,
      context.expectedBehaviors,
    );
  }
  return lines.join("\n");
}

/**
 * Make an audit-id or phase-id safe to use as a filename. Audit IDs are ISO
 * timestamps, which contain `:` (illegal on Windows / awkward in shells), so
 * replace anything outside [A-Za-z0-9._-] with `_`.
 */
function encodePathSegment(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]+/g, "_");
}

/**
 * Strip raw audit byproducts so the user is left with just the artifacts they
 * care about. Always preserved at the top level of `archon/`:
 *   - durable state files (`audit-state.json`, `file-state.json`, revisit state)
 *   - `findings/` (finalized confirmed findings)
 *   - `findings-theoretical/` (finalized theoretical / unconfirmed findings)
 *   - `attack-surface/` (recon outputs)
 *   - `confirm-workspace/` when requested (confirmation evidence + staging)
 *   - `quarantine/` (merge/manual-review output)
 *   - `*.md` (mode reports: final-audit-report.md, confirmation-report.md, …)
 *
 * Legacy lite runs can opt into promoting leftover markdown drafts into
 * `findings/` before deleting `findings-draft/`. Deep/balanced/confirm output
 * must not promote drafts: raw drafts are intermediate workspace state, while
 * finalized findings live in bucket directories with `draft.md` + `report.md`.
 */
export interface StripRawArtifactsOptions {
  /** Promote leftover top-level markdown drafts into findings/ before pruning. */
  promoteDrafts?: boolean;
  /** Preserve confirm-workspace/ evidence and verdict staging. */
  keepConfirmWorkspace?: boolean;
}

export async function stripRawArtifacts(
  archonDir: string,
  options: StripRawArtifactsOptions = {},
): Promise<void> {
  const promoteDrafts = options.promoteDrafts ?? true;
  const keepConfirmWorkspace = options.keepConfirmWorkspace ?? true;
  const findingsDraft = join(archonDir, "findings-draft");
  const findingsFinal = join(archonDir, "findings");

  // Promote any leftover drafts only for modes where drafts are the final-ish
  // output shape (historically lite). Deep/balanced/chamber drafts should be
  // discarded after their canonical finding directories have been written.
  if (promoteDrafts) {
    try {
      const drafts = await readdir(findingsDraft);
      if (drafts.length > 0) {
        await mkdir(findingsFinal, { recursive: true });
        for (const name of drafts) {
          if (!name.toLowerCase().endsWith(".md")) continue;
          const src = join(findingsDraft, name);
          const dst = join(findingsFinal, name);
          try {
            await stat(dst);
            // Final already exists — leave it; don't clobber.
          } catch {
            await rename(src, dst).catch(() => {});
          }
        }
      }
    } catch {
      // findings-draft may not exist; nothing to promote.
    }
  }

  let entries: string[];
  try {
    entries = await readdir(archonDir);
  } catch {
    return;
  }

  for (const name of entries) {
    if (shouldKeep(name, { keepConfirmWorkspace })) continue;
    await rm(join(archonDir, name), { recursive: true, force: true }).catch(() => {});
  }
}

/** Finalized finding buckets: confirmed (`findings/`) + theoretical (`findings-theoretical`). */
const FINALIZED_FINDING_DIRS: readonly string[] = ["findings", "findings-theoretical"];

const DURABLE_STATE_FILES = new Set([
  "audit-state.json",
  "file-state.json",
  "revisit-audit-state.json",
]);

const DURABLE_DIRS = new Set([
  "attack-surface",
  "findings",
  "findings-theoretical",
  "quarantine",
]);

function shouldKeep(
  name: string,
  options: { keepConfirmWorkspace: boolean },
): boolean {
  if (DURABLE_STATE_FILES.has(name)) return true;
  if (DURABLE_DIRS.has(name)) return true;
  if (options.keepConfirmWorkspace && name === "confirm-workspace") return true;
  if (name.toLowerCase().endsWith(".md")) return true;
  return false;
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

export async function summarizeFindings(
  archonDir: string,
): Promise<{ total: number; bySeverity: Record<string, number> }> {
  const bySeverity: Record<string, number> = {};
  let total = 0;
  for (const sub of [...FINALIZED_FINDING_DIRS, "findings-draft"]) {
    const dir = join(archonDir, sub);
    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }
    for (const name of entries) {
      if (!name.toLowerCase().endsWith(".md")) continue;
      total++;
      let body = "";
      try {
        body = await readFile(join(dir, name), "utf8");
      } catch {
        continue;
      }
      const sev = parseSeverity(body) ?? "Unknown";
      bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    }
  }
  return { total, bySeverity: sortSeverity(bySeverity) };
}

function parseSeverity(body: string): string | null {
  // Matches both "**Severity**: High" and "- Severity: High" / "Severity: High".
  const m = body.match(/severity\s*\*?\*?\s*:\s*\*?\*?\s*([A-Za-z]+)/i);
  if (!m || !m[1]) return null;
  const raw = m[1].toLowerCase();
  for (const canonical of SEVERITY_ORDER) {
    if (canonical.toLowerCase() === raw) return canonical;
  }
  return m[1].charAt(0).toUpperCase() + m[1].slice(1).toLowerCase();
}

function sortSeverity(counts: Record<string, number>): Record<string, number> {
  const ordered: Record<string, number> = {};
  for (const k of SEVERITY_ORDER) {
    if (counts[k] !== undefined) ordered[k] = counts[k];
  }
  for (const k of Object.keys(counts)) {
    if (!SEVERITY_ORDER.includes(k)) ordered[k] = counts[k]!;
  }
  return ordered;
}

