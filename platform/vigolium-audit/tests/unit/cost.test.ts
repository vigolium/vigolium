import { describe, expect, test } from "bun:test";
import { CostManager, type CostWarnArgs } from "../../src/engine/cost.js";

const noTokens = { input: 0, output: 0 };

describe("CostManager", () => {
  test("accumulates spend and tokens", () => {
    const cm = new CostManager(undefined, () => {});
    cm.record("a", 1.5, { input: 10, output: 5 });
    cm.record("a", 2.0, { input: 20, output: 8 });
    expect(cm.usd).toBeCloseTo(3.5);
    expect(cm.tokens).toEqual({ input: 30, output: 13 });
  });

  test("never warns or caps without a maxCost", () => {
    const warns: CostWarnArgs[] = [];
    const cm = new CostManager(undefined, (a) => warns.push(a));
    cm.record("a", 1000, noTokens);
    expect(warns).toHaveLength(0);
    expect(cm.overCap).toBe(false);
    expect(cm.signal.aborted).toBe(false);
  });

  test("emits each threshold warning exactly once as spend climbs", () => {
    const warns: CostWarnArgs[] = [];
    const cm = new CostManager(10, (a) => warns.push(a));
    cm.record("a", 4, noTokens); // 40% — below 50%, no warning
    expect(warns).toHaveLength(0);
    cm.record("a", 2, noTokens); // 60% — crosses 50%
    cm.record("a", 2, noTokens); // 80% — crosses 75%
    expect(warns.map((w) => w.usd)).toEqual([6, 8]);
  });

  test("fires the abort signal and reports overCap at the cap", () => {
    const cm = new CostManager(10, () => {});
    cm.record("a", 9, noTokens);
    expect(cm.overCap).toBe(false);
    expect(cm.signal.aborted).toBe(false);
    cm.record("a", 1, noTokens); // hits 100%
    expect(cm.overCap).toBe(true);
    expect(cm.signal.aborted).toBe(true);
  });

  test("crossing several thresholds in one record emits each once and caps", () => {
    const warns: CostWarnArgs[] = [];
    const cm = new CostManager(10, (a) => warns.push(a));
    cm.record("a", 10, noTokens); // jumps 0 → 100% in one shot
    // 50/75/90/100 all crossed → four warnings, then abort.
    expect(warns).toHaveLength(4);
    expect(cm.signal.aborted).toBe(true);
  });

  test("addSilently rolls spend in without warning or capping", () => {
    const warns: CostWarnArgs[] = [];
    const cm = new CostManager(10, (a) => warns.push(a));
    cm.addSilently(20, { input: 5, output: 5 });
    expect(cm.usd).toBe(20);
    expect(warns).toHaveLength(0);
    expect(cm.signal.aborted).toBe(false); // silent roll-in never trips the cap
    expect(cm.overCap).toBe(true); // but the getter still reflects reality
  });
});
