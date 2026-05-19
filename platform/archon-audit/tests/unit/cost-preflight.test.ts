import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { estimateCost } from "../../src/cli/cost-preflight.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
  tempDirs.length = 0;
});

function makeTarget(state?: object): string {
  const dir = mkdtempSync(join(tmpdir(), "archon-preflight-"));
  tempDirs.push(dir);
  if (state) {
    mkdirSync(join(dir, "archon"), { recursive: true });
    writeFileSync(join(dir, "archon", "audit-state.json"), JSON.stringify(state));
  }
  return dir;
}

describe("estimateCost", () => {
  test("returns baseline estimate when no archon/ exists", async () => {
    const target = makeTarget();
    const est = await estimateCost({ targetDir: target, mode: "lite", runnablePhases: 3 });
    expect(est).not.toBeNull();
    expect(est!.fromBaseline).toBe(true);
    expect(est!.sampleSize).toBe(0);
    expect(est!.expectedRunnablePhases).toBe(3);
    expect(est!.estimatedUsd).toBeGreaterThan(0);
  });

  test("returns baseline when state has no prior audits for this mode", async () => {
    const target = makeTarget({
      schema_version: 1,
      audits: [
        {
          audit_id: "a1",
          commit: null,
          branch: null,
          repository: null,
          mode: "deep",
          model: null,
          agent_sdk: "claude-cli",
          started_at: "2026-01-01T00:00:00Z",
          completed_at: "2026-01-01T01:00:00Z",
          status: "complete",
          phases: { "1": { status: "complete" }, "2": { status: "complete" } },
          usage: { input_tokens: 100, output_tokens: 50, cost_usd: 4.0 },
        },
      ],
    });
    const est = await estimateCost({ targetDir: target, mode: "lite", runnablePhases: 3 });
    expect(est!.fromBaseline).toBe(true);
  });

  test("averages cost-per-phase across prior runs of the same mode", async () => {
    const target = makeTarget({
      schema_version: 1,
      audits: [
        {
          audit_id: "a1",
          commit: null,
          branch: null,
          repository: null,
          mode: "lite",
          model: null,
          agent_sdk: "claude-cli",
          started_at: "2026-01-01T00:00:00Z",
          completed_at: "2026-01-01T01:00:00Z",
          status: "complete",
          phases: { L1: { status: "complete" }, L2: { status: "complete" }, L3: { status: "complete" } },
          usage: { input_tokens: 0, output_tokens: 0, cost_usd: 3.0 }, // $1/phase
        },
        {
          audit_id: "a2",
          commit: null,
          branch: null,
          repository: null,
          mode: "lite",
          model: null,
          agent_sdk: "claude-cli",
          started_at: "2026-02-01T00:00:00Z",
          completed_at: "2026-02-01T01:00:00Z",
          status: "complete",
          phases: { L1: { status: "complete" }, L2: { status: "complete" }, L3: { status: "complete" } },
          usage: { input_tokens: 0, output_tokens: 0, cost_usd: 6.0 }, // $2/phase
        },
      ],
    });
    const est = await estimateCost({ targetDir: target, mode: "lite", runnablePhases: 3 });
    expect(est!.fromBaseline).toBe(false);
    expect(est!.sampleSize).toBe(2);
    // 6 phases total, $9 total → $1.50/phase × 3 phases = $4.50
    expect(est!.avgPerPhase).toBe(1.5);
    expect(est!.estimatedUsd).toBe(4.5);
  });

  test("ignores incomplete audits", async () => {
    const target = makeTarget({
      schema_version: 1,
      audits: [
        {
          audit_id: "a1",
          commit: null,
          branch: null,
          repository: null,
          mode: "lite",
          model: null,
          agent_sdk: "claude-cli",
          started_at: "2026-01-01T00:00:00Z",
          completed_at: null,
          status: "failed",
          phases: { L1: { status: "complete" } },
          usage: { input_tokens: 0, output_tokens: 0, cost_usd: 10.0 },
        },
      ],
    });
    const est = await estimateCost({ targetDir: target, mode: "lite", runnablePhases: 3 });
    expect(est!.fromBaseline).toBe(true);
  });
});
