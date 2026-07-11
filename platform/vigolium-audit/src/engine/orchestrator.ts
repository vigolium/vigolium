import { mkdir, rename } from "fs/promises";
import { join } from "path";
import { existsSync, readdirSync } from "fs";
import type { Adapter } from "../adapters/adapter.js";
import type { ContentLoader, ContentVariant } from "../content-loader.js";
import { OrchestratorBus, type OrchestratorEvent } from "./events.js";
import { scheduleBatches, topologicalOrder } from "./phase.js";
import { StateStore, buildAuditId, findResumableAudit, newAuditRecord } from "./state.js";
import type { AuditContext, AuditMode, AuditRecord, CommandDef, PhaseDef } from "./types.js";
import { listTrackedFiles, probeGit } from "./git.js";
import { compact, round2 } from "./util.js";
import { resolveRetryConfig, runWithRetry } from "./retry.js";
import { adapterEventHasQuotaLimit, adapterEventHasRetryableError, isTransientError, quotaResetDelayMs, valueContainsQuotaLimit } from "../adapters/claude-events.js";
import { CheckpointStore } from "./checkpoint.js";
import { CostManager } from "./cost.js";
import { detectDraftOwner, startFindingsWatcher, summarizeFindings } from "./findings.js";
import { finalizeOutput } from "./redact-artifacts.js";
import { composeUserPrompt, parseToolsField } from "./prompts.js";
import { evaluatePhaseArtifacts, formatArtifactFailures } from "./artifact-gates.js";
import { archivePriorCoreArtifacts, isCoreAuditMode } from "./artifact-lifecycle.js";

export interface OrchestratorOptions {
  adapter: Adapter;
  loader: ContentLoader;
  targetDir: string;
  mode: AuditMode;
  resultsDir?: string;
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
   * Default: 5. Overridable via `VIGOLIUM_AUDIT_QUOTA_MAX_RETRIES` env var.
   * Unlike ordinary transient retries, the quota path *does* retry mid-stream
   * — the alternative is throwing away the whole audit, and progress events
   * from the failed attempt are already on disk (findings-draft, state).
   */
  quotaMaxRetries?: number;
  /**
   * Delay between quota-limit retry attempts in milliseconds. Default: 3,600,000
   * (1 hour). Overridable via `VIGOLIUM_AUDIT_QUOTA_BACKOFF_MS` env var. Tests set this
   * to a tiny value so the retry loop doesn't actually sleep an hour.
   */
  quotaBackoffMs?: number;
  /** Verbose adapter mode: forwarded to AdapterRunInput.debug per phase. */
  debug?: boolean;
  /**
   * When true, strip raw scanner output / draft findings / codeql/semgrep
   * workspaces from `vigolium-results/` after a `complete` run. Always kept when
   * stripping runs: durable state JSON, `findings/`, `findings-theoretical/`,
   * `attack-surface/`, `confirm-workspace/` (when relevant), and top-level
   * `*.md` reports. Stripping is skipped on `failed`/`aborted` so users can
   * resume or debug.
   */
  stripRaw?: boolean;
  /**
   * When the post-`complete` strip runs, retain DB snapshots and skip
   * scrubbing secrets from `confirm-workspace/` JSON + logs. The junk sweep
   * still runs. Default: redact. See `RunOptions.keepSecrets`.
   */
  keepSecrets?: boolean;
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
  private readonly checkpoints: CheckpointStore;
  /**
   * Cumulative spend + token tracker. Owns the cost-cap policy and the internal
   * abort signal fired when the cap is breached (composed with `opts.abortSignal`
   * so adapters see one signal that fires on either SIGINT or budget exhaustion).
   */
  private readonly cost: CostManager;
  /**
   * Phase IDs of the running command, cached from `run()` so per-failure
   * quarantine doesn't re-parse the command YAML on every failed phase.
   */
  private allPhaseIds: string[] | null = null;
  /** Start of the active audit, used to reject untouched artifacts from older fresh runs. */
  private activeAuditStartedAtMs: number | undefined;

  constructor(private readonly opts: OrchestratorOptions) {
    const resultsDir = opts.resultsDir ?? join(opts.targetDir, "vigolium-results");
    this.state = new StateStore(resultsDir);
    this.checkpoints = new CheckpointStore(resultsDir);
    this.cost = new CostManager(opts.maxCost, (args) => {
      // Fire-and-forget: a cost-warning listener must never abort the audit.
      // Swallow listener failures so an unhandled rejection can't crash us.
      void this.bus.emit({ kind: "costWarn", ...args }).catch(() => {});
    });
  }

  /**
   * Combined abort signal: user SIGINT or cost cap. Adapter calls listen to
   * this so they terminate the moment either fires.
   */
  private combinedAbortSignal(): AbortSignal {
    const user = this.opts.abortSignal;
    if (!user) return this.cost.signal;
    if (user.aborted) return user;
    return AbortSignal.any([user, this.cost.signal]);
  }

  on(listener: (e: OrchestratorEvent) => void | Promise<void>): () => void {
    return this.bus.on(listener);
  }

  async run(): Promise<OrchestratorResult> {
    const resultsDir = this.opts.resultsDir ?? join(this.opts.targetDir, "vigolium-results");
    await mkdir(resultsDir, { recursive: true });

    const command = await this.opts.loader.loadCommand(this.opts.mode, { variant: this.contentVariant() });
    this.allPhaseIds = command.phases.map((p) => p.id);
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

    const stopFindingsWatch = this.startFindingsWatcher(resultsDir, auditId);
    let watchStopped = false;
    const stopWatchOnce = (): void => {
      if (watchStopped) return;
      watchStopped = true;
      stopFindingsWatch();
    };

    try {
      return await this.runInner({ resultsDir, auditId, command, ordered, runnable, skipped, skipReasons });
    } finally {
      stopWatchOnce();
    }
  }

  private async runInner(args: {
    resultsDir: string;
    auditId: string;
    command: CommandDef;
    ordered: PhaseDef[];
    runnable: PhaseDef[];
    skipped: PhaseDef[];
    skipReasons: Map<string, string>;
  }): Promise<OrchestratorResult> {
    const { resultsDir, auditId, command, ordered, runnable, skipped, skipReasons } = args;

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
      if (this.opts.abortSignal?.aborted || this.cost.signal.aborted) {
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
        if (phaseStatus === "skipped") continue;
        if (phaseStatus === "complete") {
          const gate = await evaluatePhaseArtifacts(phase, resultsDir, this.artifactGateOptions());
          if (gate.ok || phase.completion?.enforcement === "advisory") continue;
          const missing = formatArtifactFailures(gate).join("; ");
          await this.bus.emit({
            kind: "phaseAdapterEvent",
            auditId,
            phase,
            event: {
              kind: "textDelta",
              text: `[artifact-gate] completed phase no longer satisfies its contract; rerunning: ${missing}\n`,
            },
          });
          await this.state.updatePhase(auditId, phase.id, {
            status: "pending",
            error: `artifact contract failed during resume: ${missing}`,
          });
        }
        if (phaseStatus === "in_progress") {
          const checkpoint = await this.checkpoints.load(auditId, phase.id);
          if (checkpoint) {
            // Roll the prior attempt's spend in silently — it was already
            // reported, so it must not re-trip warnings or the cap here.
            this.cost.addSilently(checkpoint.usd, checkpoint.tokens);
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
            await this.checkpoints.clear(auditId, phase.id).catch(() => {});
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
      if (this.cost.overCap) {
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
        input_tokens: this.cost.tokens.input,
        output_tokens: this.cost.tokens.output,
        cost_usd: round2(this.cost.usd),
      },
    });

    const findings = await summarizeFindings(resultsDir);
    const tokens = this.cost.tokens;

    await this.bus.emit({
      kind: "auditEnd",
      auditId,
      status,
      usd: round2(this.cost.usd),
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
      await finalizeOutput(resultsDir, {
        // Lite's historical --strip-raw behavior promotes raw drafts because
        // lite may never materialize full finding directories. Deep/balanced
        // drafts are intermediate debate artifacts and must not be promoted.
        promoteDrafts: this.opts.mode === "lite",
        keepConfirmWorkspace: this.opts.mode === "confirm",
        // Sweep scanner scratch and (unless opted out) redact confirm-workspace
        // secrets as part of the same final pass.
        ...(this.opts.keepSecrets ? { keepSecrets: true } : {}),
      });
    }

    return {
      auditId,
      status,
      totalUsd: round2(this.cost.usd),
      totalTokens: tokens,
      findings,
      failedPhases,
      skippedPhases: skipped.map((p) => p.id),
    };
  }

  private async resolveAuditId(command: CommandDef, runnable: PhaseDef[]): Promise<string> {
    const state = await this.state.load();
    if (this.opts.resume) {
      const existing = findResumableAudit(state.audits, command.mode as AuditMode);
      if (existing) {
        const startedAtMs = Date.parse(existing.started_at);
        this.activeAuditStartedAtMs = Number.isFinite(startedAtMs) ? startedAtMs : undefined;
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
    if (state.audits.length > 0 && isCoreAuditMode(command.mode as AuditMode)) {
      const resultsDir = this.opts.resultsDir ?? join(this.opts.targetDir, "vigolium-results");
      await archivePriorCoreArtifacts(resultsDir, auditId);
    }
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
      historyAvailable: git.available,
      phaseIds,
      ...compact({ context, triggeredVia: this.opts.triggeredVia }),
    });
    this.activeAuditStartedAtMs = Date.parse(record.started_at);
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
    const resultsDir = this.opts.resultsDir ?? join(this.opts.targetDir, "vigolium-results");
    const startedAt = new Date().toISOString();
    await this.state.updatePhase(auditId, phase.id, { status: "in_progress", started_at: startedAt });

    const { systemPrompt, userPrompt, tools } = await this.buildPrompts(phase, command, auditId);
    const retryConfig = resolveRetryConfig({
      ...(this.opts.quotaMaxRetries !== undefined ? { quotaMaxRetries: this.opts.quotaMaxRetries } : {}),
      ...(this.opts.quotaBackoffMs !== undefined ? { quotaBackoffMs: this.opts.quotaBackoffMs } : {}),
      ...(this.opts.transientRetries !== undefined ? { transientMaxRetries: this.opts.transientRetries } : {}),
      // The orchestrator drives one adapter call per phase, so a transient retry
      // after progress would replay events — skip it. Quota retries still apply.
      skipTransientAfterProgress: true,
      defaults: { quotaMaxRetries: 5, transientMaxRetries: 3, transientBaseDelayMs: 1000 },
    });

    let usd = 0;
    let tokens = { input: 0, output: 0 };
    let durationMs = 0;
    let ok = false;
    let error: string | undefined;

    await runWithRetry(retryConfig, {
      abortSignal: this.combinedAbortSignal(),
      attempt: async () => {
        const result = await this.driveAdapterOnce({ systemPrompt, userPrompt, tools, auditId, phase, command });
        usd += result.usd;
        tokens = {
          input: tokens.input + result.tokens.input,
          output: tokens.output + result.tokens.output,
        };
        durationMs += result.durationMs;
        // Record every attempt immediately so failed retries count toward the
        // budget and can prevent another costly attempt from starting.
        this.cost.record(auditId, result.usd, result.tokens);
        ok = result.ok;
        error = result.error;
        return {
          ok: result.ok,
          quotaLimit: result.quotaLimit,
          transient: result.transient,
          sawProgress: result.sawProgress,
          parsedQuotaDelayMs: result.parsedQuotaDelayMs,
          error: result.error,
        };
      },
      note: async (text) => {
        await this.bus.emit({ kind: "phaseAdapterEvent", auditId, phase, event: { kind: "textDelta", text } });
      },
      probe: () => this.opts.adapter.probe(),
    });

    let adapterFailed = !ok;

    if (ok && phase.completion) {
      let gate = await evaluatePhaseArtifacts(phase, resultsDir, this.artifactGateOptions());
      const repairAttempts = phase.completion.repair_attempts;
      for (
        let attempt = 1;
        !gate.ok && attempt <= repairAttempts && !this.cost.signal.aborted;
        attempt++
      ) {
        const failures = formatArtifactFailures(gate);
        await this.bus.emit({
          kind: "phaseAdapterEvent",
          auditId,
          phase,
          event: {
            kind: "textDelta",
            text:
              `[artifact-gate] repair ${attempt}/${repairAttempts}: ` +
              `${failures.join("; ")}\n`,
          },
        });

        const repair = await this.driveAdapterOnce({
          systemPrompt,
          userPrompt: this.buildArtifactRepairPrompt(phase, failures),
          tools,
          auditId,
          phase,
          command,
          labelSuffix: `repair-${attempt}`,
        });
        usd += repair.usd;
        tokens = {
          input: tokens.input + repair.tokens.input,
          output: tokens.output + repair.tokens.output,
        };
        durationMs += repair.durationMs;
        this.cost.record(auditId, repair.usd, repair.tokens);

        if (!repair.ok) {
          if (phase.completion.enforcement === "required") {
            ok = false;
            adapterFailed = true;
            error = repair.error ?? `artifact repair ${attempt} failed`;
          } else {
            await this.bus.emit({
              kind: "phaseAdapterEvent",
              auditId,
              phase,
              event: {
                kind: "textDelta",
                text: `[artifact-gate] advisory repair failed; continuing: ${repair.error ?? "unknown adapter error"}\n`,
              },
            });
          }
          break;
        }
        gate = await evaluatePhaseArtifacts(phase, resultsDir, this.artifactGateOptions());
      }

      if (ok && !gate.ok) {
        const detail = formatArtifactFailures(gate).join("; ");
        if (phase.completion.enforcement === "required") {
          ok = false;
          error = `artifact contract failed: ${detail}`;
        } else {
          await this.bus.emit({
            kind: "phaseAdapterEvent",
            auditId,
            phase,
            event: { kind: "textDelta", text: `[artifact-gate] advisory artifacts missing: ${detail}\n` },
          });
        }
      }
    }

    if (!ok && !error) {
      ok = false;
      error = "phase finished without a success event";
    }

    if (!ok && adapterFailed) {
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

  private artifactGateOptions(): { notBeforeMs?: number } {
    return !isCoreAuditMode(this.opts.mode) || this.activeAuditStartedAtMs === undefined
      ? {}
      : { notBeforeMs: this.activeAuditStartedAtMs };
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
        `Run phase "${phase.id}: ${phase.title}" exactly as specified in the command-def below. ` +
        `The engine exclusively owns vigolium-results/audit-state.json; never edit phase state yourself.\n\n` +
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
    labelSuffix?: string;
  }): Promise<{
    ok: boolean;
    usd: number;
    tokens: { input: number; output: number };
    durationMs: number;
    error?: string;
    transient: boolean;
    quotaLimit: boolean;
    sawProgress: boolean;
    parsedQuotaDelayMs: number | null;
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
    let parsedQuotaDelayMs: number | null = null;

    const startedAt = Date.now();
    let toolCalls = 0;
    let lastTool: string | undefined;
    const checkpointEvery = 5; // tool calls between checkpoint flushes
    const flushCheckpoint = async (): Promise<void> => {
      await this.checkpoints.write(args.auditId, args.phase.id, {
        startedAt,
        toolCalls,
        ...(lastTool !== undefined ? { lastTool } : {}),
        usd,
        tokens,
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
        label: `${args.command.mode}:${args.phase.id}${args.labelSuffix ? `:${args.labelSuffix}` : ""}`,
      })) {
        await this.bus.emit({ kind: "phaseAdapterEvent", auditId: args.auditId, phase: args.phase, event });
        if (event.kind === "rateLimits") {
          await this.bus.emit({ kind: "rateLimits", auditId: args.auditId, data: event.data });
        }
        if (event.kind === "textDelta" || event.kind === "toolCall") {
          sawProgress = true;
        }
        if (adapterEventHasQuotaLimit(event)) {
          quotaLimit = true;
          // Prefer the soonest streamed "resets at" delay so the retry sleeps
          // exactly until the quota clears rather than a fixed fallback.
          const delay = quotaResetDelayMs(event);
          if (delay !== null && (parsedQuotaDelayMs === null || delay < parsedQuotaDelayMs)) {
            parsedQuotaDelayMs = delay;
          }
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
      await this.checkpoints.clear(args.auditId, args.phase.id).catch(() => {});
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
      parsedQuotaDelayMs,
    };
  }

  private buildArtifactRepairPrompt(phase: PhaseDef, failures: string[]): string {
    return [
      `Artifact repair for phase ${phase.id} — ${phase.title}.`,
      `Write only the missing or invalid phase-owned artifacts listed below.`,
      `Do not rerun completed analysis, modify unrelated artifacts, or edit vigolium-results/audit-state.json.`,
      ...failures.map((failure) => `- ${failure}`),
      `Finish after the artifacts are repaired; the engine will validate them deterministically.`,
    ].join("\n");
  }

  private async quarantinePartialOutput(auditId: string, phase: PhaseDef): Promise<void> {
    const resultsDir = this.opts.resultsDir ?? join(this.opts.targetDir, "vigolium-results");
    const draftsDir = join(resultsDir, "findings-draft");
    const archive = join(resultsDir, ".archive", auditId, phase.id);
    if (!existsSync(draftsDir)) return;

    // Match drafts to this phase using two signals:
    //   1. Frontmatter `phase_id:` / `phase:` (authoritative when present).
    //   2. Longest filename-prefix match against the audit's phase IDs.
    // Longest-prefix prevents phase "1" from quarantining a "1a-…" draft when
    // both phases exist (deep.md has 1a/1b/2-15, no bare "1", but the rule
    // future-proofs us).
    // Cached by run(); fall back to a load only if quarantine is somehow
    // reached before the command was parsed (defensive — shouldn't happen).
    const allPhaseIds =
      this.allPhaseIds ??
      (await this.opts.loader.loadCommand(this.opts.mode, { variant: this.contentVariant() })).phases.map((p) => p.id);
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

  private startFindingsWatcher(resultsDir: string, auditId: string): () => void {
    return startFindingsWatcher({
      resultsDir,
      auditId,
      targetDir: this.opts.targetDir,
      bus: this.bus,
    });
  }
}
