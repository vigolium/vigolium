import type { OrchestratorBus } from "./events.js";
import { StateStore } from "./state.js";
import type { AuditRecord, PhaseDef, PhaseStatus } from "./types.js";

/**
 * Poll vigolium-results/audit-state.json during a handoff run and emit synthetic
 * phaseStart/phaseEnd events when the agents transition phases.
 *
 * Handoff drivers (claude-handoff, codex-handoff) hand off the whole audit to
 * the native runtime and only see one adapter event stream. Without polling,
 * --json consumers and the line renderer can't tell that 6 phases worth of
 * work happened in the middle of that one stream. The poller bridges that
 * gap by surfacing audit-state.json deltas as orchestrator events.
 *
 * Cost / token totals on the synthetic phaseEnd are zeroed and the event is
 * tagged `synthetic: true` — the handoff already charges the whole run's
 * cost in its final phaseEnd, and we can't tell from state alone how much
 * each phase cost. Consumers should branch on `synthetic` rather than render
 * the zeros as if they were real measurements.
 */
export function startHandoffPoller(args: {
  resultsDir: string;
  bus: OrchestratorBus;
  /** Audit IDs that already existed before the handoff started. New audits are reported. */
  knownAuditIds: Set<string>;
  /** Existing audit IDs intentionally being resumed; treat them as ours. */
  trackedAuditIds?: Set<string>;
  /** Provisional id used by the driver until the real audit-state record appears. */
  provisionalAuditId: string;
  /** Optional override; default 1500 ms is fast enough to feel live without thrashing disk. */
  intervalMs?: number;
}): () => void {
  const { resultsDir, bus, knownAuditIds, trackedAuditIds, provisionalAuditId } = args;
  const intervalMs = args.intervalMs ?? 1500;
  const store = new StateStore(resultsDir);

  const seen = new Map<string, Map<string, PhaseStatus>>();
  let phaseCounter = 0;
  let stopped = false;

  const phaseDef = (phaseId: string, title?: string): PhaseDef => ({
    id: phaseId,
    title: title ?? `${phaseId} (handoff)`,
    agent: null,
    requires_git: false,
    depends_on: [],
    parallel_with: [],
  });

  const tick = async (): Promise<void> => {
    if (stopped) return;
    let state: { audits: AuditRecord[] };
    try {
      state = await store.load();
    } catch {
      return;
    }
    for (const audit of state.audits) {
      const isOurs = trackedAuditIds?.has(audit.audit_id) === true || !knownAuditIds.has(audit.audit_id);
      if (!isOurs) continue;
      let perPhase = seen.get(audit.audit_id);
      if (!perPhase) {
        perPhase = new Map();
        seen.set(audit.audit_id, perPhase);
      }
      for (const [phaseId, phase] of Object.entries(audit.phases)) {
        const prev = perPhase.get(phaseId);
        if (prev === phase.status) continue;
        perPhase.set(phaseId, phase.status);

        if (phase.status === "in_progress" && prev !== "in_progress") {
          phaseCounter++;
          await bus.emit({
            kind: "phaseStart",
            auditId: audit.audit_id,
            phase: phaseDef(phaseId),
            index: phaseCounter,
            total: Object.keys(audit.phases).length,
          });
        } else if (phase.status === "complete" && prev !== "complete") {
          await bus.emit({
            kind: "phaseEnd",
            auditId: audit.audit_id,
            phase: phaseDef(phaseId),
            ok: true,
            usd: 0,
            tokens: { input: 0, output: 0 },
            durationMs: 0,
            synthetic: true,
          });
        } else if (phase.status === "failed" && prev !== "failed") {
          await bus.emit({
            kind: "phaseEnd",
            auditId: audit.audit_id,
            phase: phaseDef(phaseId),
            ok: false,
            usd: 0,
            tokens: { input: 0, output: 0 },
            durationMs: 0,
            synthetic: true,
            ...(phase.error !== undefined ? { error: phase.error } : {}),
          });
        } else if (phase.status === "skipped" && prev !== "skipped") {
          await bus.emit({
            kind: "phaseSkip",
            auditId: audit.audit_id,
            phase: phaseDef(phaseId),
            reason: phase.error ?? "skipped by agents",
          });
        }
      }
    }
  };

  // Use setInterval but coalesce ticks so a slow disk doesn't queue overlapping
  // ones. Bound each tick with a timeout: on a slow/stuck filesystem the
  // in-flight slot frees after TICK_TIMEOUT_MS so the next interval can retry
  // instead of the live view appearing frozen for the whole audit.
  const TICK_TIMEOUT_MS = Math.max(intervalMs * 4, 5000);
  let inFlight: Promise<void> | null = null;
  const timer = setInterval(() => {
    if (inFlight) return;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<void>((r) => {
      timeoutHandle = setTimeout(r, TICK_TIMEOUT_MS);
    });
    inFlight = Promise.race([tick(), timeout]).finally(() => {
      clearTimeout(timeoutHandle);
      inFlight = null;
    });
  }, intervalMs);

  // Reference the provisional id to silence the lint warning on a parameter
  // that future callers may want for correlation — currently we always read
  // the real audit_id from state.
  void provisionalAuditId;

  return () => {
    stopped = true;
    clearInterval(timer);
  };
}

/**
 * Resolve a handoff's final audit status. Prefers whatever the agents
 * recorded in audit-state.json; falls back to abort/ok signals only when
 * the agents left the audit `in_progress` (truncated run, network drop).
 */
export function deriveHandoffStatus(args: {
  recordedStatus: AuditRecord["status"] | undefined;
  aborted: boolean;
  ok: boolean;
}): "complete" | "failed" | "aborted" {
  const r = args.recordedStatus;
  if (r === "complete" || r === "failed" || r === "aborted") return r;
  if (args.aborted) return "aborted";
  return args.ok ? "complete" : "failed";
}
