import { join } from "path";
import { StateStore } from "../engine/state.js";
import { round2 } from "../engine/util.js";
import type { AuditMode, AuditRecord } from "../engine/types.js";

export interface PreflightEstimate {
  mode: AuditMode;
  /** Average historical cost per *completed* phase for this mode, in USD. */
  avgPerPhase: number;
  /** Number of phases we expect to run (excludes git-gated + refresh-excluded). */
  expectedRunnablePhases: number;
  /** Point estimate: avgPerPhase * expectedRunnablePhases. */
  estimatedUsd: number;
  /** Number of historical audits the average is computed from. */
  sampleSize: number;
  /** True when we have zero history for this mode and the estimate is a guess. */
  fromBaseline: boolean;
}

/**
 * Baseline used when no historical data is available. Calibrated to the
 * 2026-Q1 average per-phase cost of an opus/sonnet run with prompt caching;
 * intentionally on the high side so the warning isn't too quiet to be useful.
 */
const BASELINE_USD_PER_PHASE = 0.75;

/**
 * Read `vigolium-results/audit-state.json` for the target and estimate this run's cost
 * from prior audits. Returns null when there's no state at all; callers
 * should treat that as "no estimate, no warning."
 */
export async function estimateCost(args: {
  targetDir: string;
  mode: AuditMode;
  runnablePhases: number;
}): Promise<PreflightEstimate | null> {
  const store = new StateStore(join(args.targetDir, "vigolium-results"));
  let state: { audits: AuditRecord[] };
  try {
    state = await store.load();
  } catch {
    return null;
  }

  const sameMode = state.audits.filter((a) => a.mode === args.mode && a.status === "complete" && a.usage);
  if (sameMode.length === 0) {
    return {
      mode: args.mode,
      avgPerPhase: BASELINE_USD_PER_PHASE,
      expectedRunnablePhases: args.runnablePhases,
      estimatedUsd: round2(BASELINE_USD_PER_PHASE * args.runnablePhases),
      sampleSize: 0,
      fromBaseline: true,
    };
  }

  let totalUsd = 0;
  let totalCompletedPhases = 0;
  for (const audit of sameMode) {
    const completed = Object.values(audit.phases).filter((p) => p.status === "complete").length;
    if (completed === 0) continue;
    totalUsd += audit.usage?.cost_usd ?? 0;
    totalCompletedPhases += completed;
  }
  if (totalCompletedPhases === 0) {
    return {
      mode: args.mode,
      avgPerPhase: BASELINE_USD_PER_PHASE,
      expectedRunnablePhases: args.runnablePhases,
      estimatedUsd: round2(BASELINE_USD_PER_PHASE * args.runnablePhases),
      sampleSize: 0,
      fromBaseline: true,
    };
  }

  const avgPerPhase = totalUsd / totalCompletedPhases;
  return {
    mode: args.mode,
    avgPerPhase: round2(avgPerPhase),
    expectedRunnablePhases: args.runnablePhases,
    estimatedUsd: round2(avgPerPhase * args.runnablePhases),
    sampleSize: sameMode.length,
    fromBaseline: false,
  };
}

