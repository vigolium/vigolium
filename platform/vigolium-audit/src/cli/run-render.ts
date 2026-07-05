import chalk from "chalk";
import type { AdapterEvent } from "../adapters/adapter.js";
import type { OrchestratorEvent } from "../engine/events.js";
import type { OrchestratorResult } from "../engine/orchestrator.js";
import type { AuditMode } from "../engine/types.js";
import { round2 } from "../engine/util.js";
import type { PreflightEstimate } from "./cost-preflight.js";
import { severityColor, statusArrow } from "./util.js";

export function emitJsonEvent(payload: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(payload) + "\n");
}

export function emitStepSummary(args: {
  json: boolean;
  requested: AuditMode;
  resolved: AuditMode;
  result: OrchestratorResult;
  isChain: boolean;
}): void {
  const { json, requested, resolved, result: r, isChain } = args;
  if (json) {
    emitJsonEvent({
      kind: "result",
      auditId: r.auditId,
      requestedMode: requested,
      resolvedMode: resolved,
      status: r.status,
      totalUsd: r.totalUsd,
      totalTokens: r.totalTokens,
      findings: r.findings,
      failedPhases: r.failedPhases,
      skippedPhases: r.skippedPhases,
    });
    return;
  }
  const color = r.status === "complete" ? chalk.green : r.status === "failed" ? chalk.red : chalk.blue;
  const tag = isChain ? `[vigolium-audit ${requested}]` : `[vigolium-audit]`;
  console.log(
    color(
      `\n${tag} ${r.status} — audit ${chalk.magenta(r.auditId)} — ${chalk.yellow(`$${r.totalUsd.toFixed(2)}`)} ` +
        `— ${chalk.magenta(formatTokens(r.totalTokens.input))} token in / ${chalk.magenta(formatTokens(r.totalTokens.output))} token out ` +
        (r.failedPhases.length > 0 ? `failed: ${r.failedPhases.join(", ")} ` : "") +
        (r.skippedPhases.length > 0 ? `skipped: ${r.skippedPhases.join(", ")}` : ""),
    ),
  );
  console.log(`${color(`${tag} findings:`)} ${formatFindings(r.findings)}`);
}

export function emitChainSummary(args: {
  json: boolean;
  modes: AuditMode[];
  stepResults: Array<{ requested: AuditMode; resolved: AuditMode; result: OrchestratorResult }>;
  stoppedReason: "complete" | "non-complete" | "fatal" | "budget" | "aborted";
  aggUsd: number;
  maxCost: number | undefined;
}): void {
  const { json, modes, stepResults, stoppedReason, aggUsd, maxCost } = args;
  const ranCount = stepResults.length;
  const allComplete = ranCount === modes.length && stepResults.every((s) => s.result.status === "complete");
  const aggIn = stepResults.reduce((s, r) => s + r.result.totalTokens.input, 0);
  const aggOut = stepResults.reduce((s, r) => s + r.result.totalTokens.output, 0);
  const aggFindings = stepResults.reduce((s, r) => s + r.result.findings.total, 0);
  if (json) {
    emitJsonEvent({
      kind: "chainResult",
      modes,
      ran: ranCount,
      stoppedReason,
      allComplete,
      totalUsd: round2(aggUsd),
      totalTokens: { input: aggIn, output: aggOut },
      totalFindings: aggFindings,
      ...(maxCost !== undefined ? { maxCost } : {}),
      steps: stepResults.map((s) => ({
        requestedMode: s.requested,
        resolvedMode: s.resolved,
        auditId: s.result.auditId,
        status: s.result.status,
        usd: s.result.totalUsd,
        findings: s.result.findings.total,
      })),
    });
    return;
  }
  const color = allComplete ? chalk.green : stoppedReason === "aborted" || stoppedReason === "budget" ? chalk.blue : chalk.red;
  const stepLine = stepResults
    .map((s) => `${s.requested}${s.requested !== s.resolved ? `→${s.resolved}` : ""}:${s.result.status}`)
    .join(" ");
  const skipped = modes.slice(ranCount);
  const skippedLine = skipped.length > 0 ? ` skipped: ${skipped.join(",")}` : "";
  console.log(
    color(
      `\n[chain] ${allComplete ? "complete" : stoppedReason} — ${ranCount}/${modes.length} modes — ` +
        `$${aggUsd.toFixed(2)}${maxCost !== undefined ? ` of $${maxCost.toFixed(2)}` : ""} — ${formatTokenPair({ input: aggIn, output: aggOut })} tok — ${aggFindings} findings`,
    ),
  );
  console.log(color(`[chain] ${stepLine}${skippedLine}`));
}

function formatFindings(findings: { total: number; bySeverity: Record<string, number> }): string {
  if (findings.total === 0) return "0";
  const parts = Object.entries(findings.bySeverity).map(
    ([sev, n]) => severityColor(sev)(`${sev}: ${n}`),
  );
  return `${findings.total} total — ${parts.join(", ")}`;
}

/**
 * Compact human-readable token count. Long-running deep audits chew through
 * tens of millions of tokens — `12345678` is unreadable mid-stream where
 * everything else is colorized and tight. Conventions:
 *   < 1k   → raw integer ("523")
 *   < 10k  → "1.2k"  (one decimal, useful when the order of magnitude shifts)
 *   < 1M   → "234k"  (integer — the decimal is noise)
 *   < 10M  → "1.5M"
 *   >= 10M → "23M"
 * Always non-negative; negative inputs are treated as 0 (defensive — the
 * adapter shouldn't emit negatives but we don't want to format "-NaN").
 */
export function formatTokens(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0";
  if (n < 1_000) return String(Math.round(n));
  if (n < 10_000) return `${(n / 1_000).toFixed(1)}k`;
  if (n < 1_000_000) return `${Math.round(n / 1_000)}k`;
  if (n < 10_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  return `${Math.round(n / 1_000_000)}M`;
}

function formatTokenPair(t: { input: number; output: number }): string {
  return `${formatTokens(t.input)}/${formatTokens(t.output)}`;
}

/**
 * Compact human-readable duration. Phase ends and audit ends print
 * `durationMs` directly off the wire, which for a multi-hour deep-mode run
 * looks like `8421319ms` — useless at a glance. Conventions:
 *   < 1s    → "234ms"
 *   < 60s   → "12.3s"   (one decimal, since seconds resolution matters)
 *   < 60m   → "5m 30s"
 *   >= 60m  → "2h 15m"
 */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "0ms";
  if (ms < 1_000) return `${Math.round(ms)}ms`;
  const totalSeconds = ms / 1_000;
  if (totalSeconds < 60) return `${totalSeconds.toFixed(1)}s`;
  const totalMinutes = Math.floor(totalSeconds / 60);
  const seconds = Math.round(totalSeconds - totalMinutes * 60);
  if (totalMinutes < 60) return `${totalMinutes}m ${seconds}s`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes - hours * 60;
  return `${hours}h ${minutes}m`;
}

/**
 * NDJSON event logger: each OrchestratorEvent becomes one JSON line on stdout.
 * Phases get serialized as { id, title, agent } so consumers don't have to
 * track schema-version of internal types.
 */
export function makeJsonLogger(): (e: OrchestratorEvent) => void {
  const phaseSummary = (p: { id: string; title: string; agent: string | null }): {
    id: string;
    title: string;
    agent: string | null;
  } => ({ id: p.id, title: p.title, agent: p.agent });

  return (event: OrchestratorEvent) => {
    switch (event.kind) {
      case "auditStart":
        emitJsonEvent({
          kind: "auditStart",
          auditId: event.auditId,
          mode: event.mode,
          totalPhases: event.totalPhases,
          runnablePhases: event.runnablePhases,
        });
        return;
      case "phaseStart":
        emitJsonEvent({
          kind: "phaseStart",
          auditId: event.auditId,
          phase: phaseSummary(event.phase),
          index: event.index,
          total: event.total,
        });
        return;
      case "phaseSkip":
        emitJsonEvent({
          kind: "phaseSkip",
          auditId: event.auditId,
          phase: phaseSummary(event.phase),
          reason: event.reason,
        });
        return;
      case "phaseAdapterEvent":
        emitJsonEvent({
          kind: "phaseAdapterEvent",
          auditId: event.auditId,
          phaseId: event.phase.id,
          event: serializeAdapterEvent(event.event),
        });
        return;
      case "phaseEnd":
        emitJsonEvent({
          kind: "phaseEnd",
          auditId: event.auditId,
          phase: phaseSummary(event.phase),
          ok: event.ok,
          usd: event.usd,
          tokens: event.tokens,
          durationMs: event.durationMs,
          ...(event.error !== undefined ? { error: event.error } : {}),
          ...(event.synthetic ? { synthetic: true } : {}),
        });
        return;
      case "findingDiscovered":
        emitJsonEvent({
          kind: "findingDiscovered",
          auditId: event.auditId,
          phaseId: event.phaseId,
          path: event.path,
          relPath: event.relPath,
        });
        return;
      case "costWarn":
        emitJsonEvent({ kind: "costWarn", auditId: event.auditId, usd: event.usd, cap: event.cap });
        return;
      case "auditEnd":
        emitJsonEvent({
          kind: "auditEnd",
          auditId: event.auditId,
          status: event.status,
          usd: event.usd,
          tokens: event.tokens,
          findings: event.findings,
        });
        return;
    }
  };
}

export function serializeAdapterEvent(e: AdapterEvent): Record<string, unknown> {
  switch (e.kind) {
    case "error":
      return { kind: "error", message: e.cause.message, transient: e.transient ?? false };
    default:
      return { ...e } as Record<string, unknown>;
  }
}

type LineLogger = ((e: OrchestratorEvent) => void) & { drain: () => Promise<void> };

export function makeLineLogger(opts: { debug: boolean; streaming?: boolean } = { debug: false }): LineLogger {
  const { debug, streaming = false } = opts;
  // Default truncation lengths; --debug widens them.
  const inputCap = debug ? 800 : 240;
  const outputCap = debug ? 2000 : 500;
  const thinkingCap = debug ? 1000 : 300;
  const streamCharDelayMs = 5; // ~200 chars/sec — brisk but visibly typewriter

  // Async output queue: only used when streaming is on. Tool calls and other
  // non-text events go through it too, so they appear AFTER any in-flight
  // typewriter animation (preserving chronological order).
  const tasks: Array<() => Promise<void>> = [];
  let pumping = false;
  const pumpStart = (): void => {
    if (pumping) return;
    pumping = true;
    void (async () => {
      while (tasks.length > 0) {
        const t = tasks.shift()!;
        try {
          await t();
        } catch {
          /* swallow — render-path errors shouldn't crash the run */
        }
      }
      pumping = false;
    })();
  };
  const enqueue = (t: () => Promise<void>): void => {
    tasks.push(t);
    pumpStart();
  };
  const drain = async (): Promise<void> => {
    if (!streaming) return;
    while (pumping || tasks.length > 0) await new Promise<void>((r) => setTimeout(r, 5));
  };

  // Print a complete line. Routes through the queue when streaming so it
  // doesn't jump ahead of in-flight typewriter output.
  const printLine = (s: string): void => {
    if (streaming) enqueue(async () => void process.stdout.write(s + "\n"));
    else process.stdout.write(s + "\n");
  };

  // Track active phases so we can prefix concurrent output with the phase id.
  // When only one phase is running, the prefix is omitted to keep the log
  // identical to the historical serial layout.
  const activePhases = new Set<string>();
  const phaseTextBuffers = new Map<string, string>();
  const phaseTag = (phaseId: string): string =>
    activePhases.size > 1 ? chalk.dim(`[${phaseId}] `) : "";

  const writeAgentLine = (phaseId: string, line: string): void => {
    const prefix = `  ${chalk.magenta("●")} ${phaseTag(phaseId)}`;
    if (line.length === 0) {
      printLine("");
      return;
    }
    if (streaming) {
      enqueue(async () => {
        process.stdout.write(prefix);
        for (const ch of line) {
          process.stdout.write(ch);
          await new Promise<void>((r) => setTimeout(r, streamCharDelayMs));
        }
        process.stdout.write("\n");
      });
    } else {
      process.stdout.write(`${prefix}${line}\n`);
    }
  };
  const writeAgentLines = (phaseId: string, chunk: string): void => {
    const body = chunk.endsWith("\n") ? chunk.slice(0, -1) : chunk;
    if (body.length === 0) {
      printLine("");
      return;
    }
    for (const line of body.split("\n")) writeAgentLine(phaseId, line);
  };
  const flushBuffer = (phaseId: string): void => {
    const buf = phaseTextBuffers.get(phaseId) ?? "";
    if (buf.length === 0) return;
    const chunk = buf.endsWith("\n") ? buf : buf + "\n";
    phaseTextBuffers.set(phaseId, "");
    writeAgentLines(phaseId, chunk);
  };
  const flushAllBuffers = (): void => {
    for (const id of phaseTextBuffers.keys()) flushBuffer(id);
  };

  // The session event arrives from the adapter after phaseStart fires, so we
  // defer the first phase header until session lands — that lets us print
  // session between [audit …] and [phase L1] instead of under the phase.
  let sessionPrinted = false;
  let deferredPhaseHeader: string | null = null;
  const flushDeferredHeader = (): void => {
    if (deferredPhaseHeader === null) return;
    printLine(deferredPhaseHeader);
    deferredPhaseHeader = null;
  };

  // Render the session-id line plus a one-line summary of what the session
  // actually loaded (plugins / agents / commands / skills / model / perm).
  // Called from both the deferred-header path and the regular switch branch
  // so the formatting stays in lockstep.
  const printSessionAndLoaded = (
    e: Extract<AdapterEvent, { kind: "session" }>,
  ): void => {
    printLine(`${statusArrow("Session")} Session:   ${chalk.cyan(e.sessionId)}`);
    const parts: string[] = [];
    if (e.plugins && e.plugins.length > 0) {
      parts.push(`plugin=${chalk.cyan(e.plugins.map((p) => p.name).join(","))}`);
    }
    if (e.agents) parts.push(`agents=${chalk.cyan(e.agents.length)}`);
    if (e.commands) parts.push(`commands=${chalk.cyan(e.commands.length)}`);
    if (e.skills) parts.push(`skills=${chalk.cyan(e.skills.length)}`);
    if (e.model) parts.push(`model=${chalk.cyan(e.model)}`);
    if (e.permissionMode) parts.push(`perm=${chalk.cyan(e.permissionMode)}`);
    if (parts.length > 0) {
      printLine(`${statusArrow("Loaded")} Loaded:    ${parts.join(chalk.dim(" · "))}`);
    }
  };

  const handle = (event: OrchestratorEvent): void => {
    switch (event.kind) {
      case "auditStart":
        printLine(
          `${statusArrow("Audit")} Audit:     ${chalk.cyan(event.auditId)} ` +
            chalk.dim(`(${event.runnablePhases}/${event.totalPhases} phases)`),
        );
        break;
      case "phaseStart": {
        activePhases.add(event.phase.id);
        phaseTextBuffers.set(event.phase.id, "");
        const header =
          chalk.blue(`\n[phase ${event.phase.id}] ${event.phase.title} (${event.index}/${event.total})`) +
          ` agent=${event.phase.agent ?? "(inline)"}`;
        if (!sessionPrinted) deferredPhaseHeader = header;
        else printLine(header);
        break;
      }
      case "phaseSkip":
        flushDeferredHeader();
        printLine(`[phase ${event.phase.id}] skipped — ${event.reason}`);
        break;
      case "phaseAdapterEvent": {
        const e = event.event;
        const phaseId = event.phase.id;
        if (e.kind === "session" && !sessionPrinted) {
          printSessionAndLoaded(e);
          sessionPrinted = true;
          flushDeferredHeader();
          break;
        }
        flushDeferredHeader();
        // Flush this phase's pending text before non-text events so messages
        // appear interleaved with tool calls in chronological order. Codex
        // emits `agent_message` items as a single textDelta with no trailing
        // newline, so this is the only chance to print them in-flow.
        if (e.kind !== "textDelta") flushBuffer(phaseId);
        switch (e.kind) {
          case "textDelta": {
            const buf = (phaseTextBuffers.get(phaseId) ?? "") + e.text;
            const lastNl = buf.lastIndexOf("\n");
            if (lastNl >= 0) {
              writeAgentLines(phaseId, buf.slice(0, lastNl + 1));
              phaseTextBuffers.set(phaseId, buf.slice(lastNl + 1));
            } else {
              phaseTextBuffers.set(phaseId, buf);
            }
            break;
          }
          case "toolCall": {
            const param = debug ? truncate(JSON.stringify(e.input), inputCap) : truncate(toolHeadline(e.input), inputCap);
            printLine(`  ${phaseTag(phaseId)}` + chalk.green(`ƒ ${e.tool}`) + (param ? chalk.dim(" · ") + chalk.cyan(param) : ""));
            break;
          }
          case "toolResult": {
            const out = typeof e.output === "string" ? e.output : JSON.stringify(e.output);
            const preview = truncate(oneLine(out), outputCap);
            if (preview) {
              const arrowSym = e.isError ? chalk.red("✗") : e.partial ? chalk.dim("↢") : chalk.dim("←");
              const body = e.isError ? chalk.red(preview) : chalk.gray(preview);
              printLine(`    ${phaseTag(phaseId)}${arrowSym} ${body}`);
            }
            break;
          }
          case "thinking": {
            const lines = e.text.split("\n").map((l) => l.trimEnd()).filter((l) => l.length > 0);
            for (const line of lines) {
              printLine(chalk.dim(`  ${phaseTag(phaseId)}⏚ `) + chalk.dim(truncate(line, thinkingCap)));
            }
            break;
          }
          case "session":
            printSessionAndLoaded(e);
            break;
          case "error":
            printLine(
              chalk.red(
                `  ${phaseTag(phaseId)}! adapter error${e.transient ? " [transient]" : ""}: ${debug && e.cause.stack ? e.cause.stack : e.cause.message}`,
              ),
            );
            break;
          default:
            break;
        }
        break;
      }
      case "phaseEnd":
        flushDeferredHeader();
        flushBuffer(event.phase.id);
        activePhases.delete(event.phase.id);
        phaseTextBuffers.delete(event.phase.id);
        if (event.ok) {
          if (event.synthetic) {
            printLine(chalk.green(`  ✓ ${event.phase.id} done ${chalk.dim("(handoff — usage tallied at run end)")}`));
          } else {
            printLine(
              chalk.green(
                `  ✓ ${event.phase.id} done — ${chalk.magenta(`$${event.usd.toFixed(2)}`)} — ${chalk.magenta(formatTokenPair(event.tokens))} tok — ${chalk.magenta(formatDuration(event.durationMs))}`,
              ),
            );
          }
        } else if (event.synthetic) {
          printLine(chalk.red(`  ✗ ${event.phase.id} failed — ${event.error ?? "(no message)"} ${chalk.dim("(handoff)")}`));
        } else {
          printLine(
            chalk.red(`  ✗ ${event.phase.id} failed — ${event.error ?? "(no message)"} — $${event.usd.toFixed(2)}`),
          );
        }
        break;
      case "findingDiscovered":
        flushDeferredHeader();
        printLine(chalk.green(`  + finding: ${event.relPath}`));
        break;
      case "costWarn":
        flushDeferredHeader();
        printLine(`  ! cost ${event.usd.toFixed(2)} of cap ${event.cap.toFixed(2)}`);
        break;
      case "auditEnd":
        flushDeferredHeader();
        flushAllBuffers();
        if (debug)
          printLine(
            `[audit ${event.auditId}] ${event.status} (cost $${event.usd.toFixed(2)}, ` +
              `${formatTokenPair(event.tokens)} tok, ${event.findings.total} findings)`,
          );
        break;
    }
  };
  return Object.assign(handle, { drain });
}

/**
 * Pull a single human-friendly headline from a tool call's input — the
 * one piece of context most worth reading in a fast-scrolling log.
 *   Bash   → input.command
 *   Read   → input.file_path
 *   Edit   → input.file_path
 *   Write  → input.file_path
 *   Glob   → input.pattern
 *   Grep   → input.pattern
 *   WebFetch → input.url
 *   WebSearch → input.query
 *   Task   → input.subagent_type / input.description
 * Falls back to compact JSON for unknown tool shapes.
 */
function toolHeadline(input: unknown): string {
  if (input === null || input === undefined) return "";
  if (typeof input !== "object") return String(input);
  const i = input as Record<string, unknown>;
  if (typeof i.agent_type === "string" && typeof i.message === "string") {
    return `${i.agent_type}: ${i.message}`;
  }
  if (typeof i.agent_id === "string") {
    return typeof i.nickname === "string" ? `${i.agent_id} (${i.nickname})` : i.agent_id;
  }
  for (const key of ["command", "file_path", "path", "pattern", "url", "query", "agent_type", "subagent_type", "message", "description"]) {
    const v = i[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  const compact = JSON.stringify(input);
  return compact === "{}" ? "" : compact;
}

function oneLine(s: string): string {
  return s.replace(/\r?\n/g, " ⏎ ").replace(/\s{2,}/g, " ");
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n) + `…(+${s.length - n}b)`;
}

export function emitCostPreflight(args: {
  json: boolean;
  est: PreflightEstimate;
  remainingBudget: number | undefined;
  aggUsd: number;
  maxCost: number | undefined;
}): void {
  const { json, est, remainingBudget, maxCost } = args;
  const overBudget = remainingBudget !== undefined && est.estimatedUsd > remainingBudget;
  if (json) {
    emitJsonEvent({
      kind: "costPreflight",
      mode: est.mode,
      avgPerPhase: est.avgPerPhase,
      expectedRunnablePhases: est.expectedRunnablePhases,
      estimatedUsd: est.estimatedUsd,
      sampleSize: est.sampleSize,
      fromBaseline: est.fromBaseline,
      remainingBudget: remainingBudget ?? null,
      overBudget,
    });
    return;
  }
  const tag = chalk.blue("[preflight]");
  const source = est.fromBaseline
    ? chalk.dim(`baseline $${est.avgPerPhase}/phase`)
    : chalk.dim(`avg $${est.avgPerPhase}/phase from ${est.sampleSize} prior run${est.sampleSize === 1 ? "" : "s"}`);
  const projection = `~${chalk.magenta(`$${est.estimatedUsd.toFixed(2)}`)} for ${est.expectedRunnablePhases} phases`;
  if (overBudget && maxCost !== undefined) {
    console.log(
      `${tag} ${chalk.yellow("warn")} ${projection} exceeds remaining budget ` +
        chalk.yellow(`$${remainingBudget?.toFixed(2)} of $${maxCost.toFixed(2)}`) +
        ` — ${source}`,
    );
  } else {
    console.log(`${tag} ${projection} — ${source}`);
  }
}
