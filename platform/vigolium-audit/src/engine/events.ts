import type { AdapterEvent, RateLimitsSnapshot } from "../adapters/adapter.js";
import type { PhaseDef, AuditMode } from "./types.js";

/**
 * Orchestrator-level events. These wrap AdapterEvents with phase context and
 * add lifecycle events for the TUI / logger.
 */
export type OrchestratorEvent =
  | { kind: "auditStart"; auditId: string; mode: AuditMode; totalPhases: number; runnablePhases: number }
  | { kind: "phaseStart"; auditId: string; phase: PhaseDef; index: number; total: number }
  | { kind: "phaseSkip"; auditId: string; phase: PhaseDef; reason: string }
  | { kind: "phaseAdapterEvent"; auditId: string; phase: PhaseDef; event: AdapterEvent }
  | { kind: "phaseEnd"; auditId: string; phase: PhaseDef; ok: boolean; usd: number; tokens: { input: number; output: number }; durationMs: number; error?: string; synthetic?: boolean }
  | { kind: "findingDiscovered"; auditId: string; phaseId: string | null; path: string; relPath: string }
  | { kind: "costWarn"; auditId: string; usd: number; cap: number }
  | { kind: "rateLimits"; auditId: string; data: RateLimitsSnapshot }
  | {
      kind: "auditEnd";
      auditId: string;
      status: "complete" | "failed" | "aborted";
      usd: number;
      tokens: { input: number; output: number };
      findings: { total: number; bySeverity: Record<string, number> };
    };

/**
 * Minimal, dependency-free pub/sub used by the orchestrator. Async listeners
 * are awaited in registration order so the TUI can keep up with bursts.
 */
export class OrchestratorBus {
  private listeners: Array<(e: OrchestratorEvent) => void | Promise<void>> = [];

  on(listener: (e: OrchestratorEvent) => void | Promise<void>): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  async emit(event: OrchestratorEvent): Promise<void> {
    for (const l of this.listeners) {
      try {
        await l(event);
      } catch (err) {
        // Listener errors must not corrupt the audit; log via stderr only.
        process.stderr.write(`[vigolium-audit] event listener error: ${(err as Error).message}\n`);
      }
    }
  }
}
