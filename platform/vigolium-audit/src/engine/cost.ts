import { round2 } from "./util.js";

export interface CostWarnArgs {
  auditId: string;
  usd: number;
  cap: number;
}

/**
 * Tracks cumulative spend + token usage for one audit run and owns the cost-cap
 * policy: it emits warnings as configurable thresholds are crossed and fires an
 * internal abort signal the moment the cap is reached so in-flight and pending
 * adapter calls terminate immediately rather than waiting for a between-phase
 * check. Extracted from the Orchestrator so the budget logic is testable in
 * isolation and the orchestrator no longer juggles four bare counters.
 */
export class CostManager {
  private _usd = 0;
  private _in = 0;
  private _out = 0;
  private warnedAtUsd = 0;
  private readonly abort = new AbortController();
  private static readonly THRESHOLDS = [0.5, 0.75, 0.9, 1.0];

  constructor(
    private readonly maxCost: number | undefined,
    private readonly onWarn: (args: CostWarnArgs) => void,
  ) {}

  get usd(): number {
    return this._usd;
  }
  get tokens(): { input: number; output: number } {
    return { input: this._in, output: this._out };
  }
  /** Abort signal that fires when the cap is reached. Idempotent. */
  get signal(): AbortSignal {
    return this.abort.signal;
  }
  /** True once cumulative spend has reached the configured cap. */
  get overCap(): boolean {
    return this.maxCost !== undefined && this._usd >= this.maxCost;
  }

  /**
   * Add cost/tokens without evaluating thresholds. Used for rolling a prior
   * attempt's checkpoint into the total during resume prep, which must not
   * re-emit warnings or trip the cap (it reflects spend already reported).
   */
  addSilently(usd: number, tokens: { input: number; output: number }): void {
    this._usd += usd;
    this._in += tokens.input;
    this._out += tokens.output;
  }

  /** Add a completed phase's cost/tokens, then evaluate warnings + the cap. */
  record(auditId: string, usd: number, tokens: { input: number; output: number }): void {
    this.addSilently(usd, tokens);
    if (this.maxCost === undefined) return;
    const cap = this.maxCost;
    for (const t of CostManager.THRESHOLDS) {
      const at = cap * t;
      if (this._usd >= at && this.warnedAtUsd < at) {
        this.warnedAtUsd = at;
        this.onWarn({ auditId, usd: round2(this._usd), cap });
      }
    }
    if (this._usd >= cap) this.abort.abort();
  }
}
