import { describe, expect, test, afterEach, beforeEach, spyOn } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { statusCommand } from "../../src/cli/status.js";

function makeTarget(state: object): string {
  const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-status-test-"));
  mkdirSync(join(dir, "vigolium-results"), { recursive: true });
  writeFileSync(join(dir, "vigolium-results", "audit-state.json"), JSON.stringify(state));
  return dir;
}

describe("statusCommand", () => {
  const tempDirs: string[] = [];
  let exitSpy: ReturnType<typeof spyOn>;
  let stdoutSpy: ReturnType<typeof spyOn>;
  let stderrSpy: ReturnType<typeof spyOn>;

  beforeEach(() => {
    exitSpy = spyOn(process, "exit").mockImplementation(((..._a: unknown[]): never => undefined as never) as never);
    stdoutSpy = spyOn(process.stdout, "write").mockImplementation((() => true) as never);
    stderrSpy = spyOn(console, "error").mockImplementation((() => {}) as never);
    spyOn(console, "log").mockImplementation((() => {}) as never);
  });

  afterEach(() => {
    for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
    tempDirs.length = 0;
    exitSpy.mockRestore();
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  test("emits NDJSON for a complete audit", async () => {
    const target = makeTarget({
      schema_version: 1,
      audits: [
        {
          audit_id: "a-1",
          commit: "abc1234",
          branch: "main",
          repository: null,
          mode: "lite",
          model: null,
          agent_sdk: "claude-cli",
          started_at: "2026-05-11T00:00:00.000Z",
          completed_at: "2026-05-11T00:05:00.000Z",
          status: "complete",
          phases: { L1: { status: "complete" }, L2: { status: "skipped" } },
          usage: { input_tokens: 100, output_tokens: 50, cost_usd: 0.25 },
        },
      ],
    });
    tempDirs.push(target);

    await statusCommand(target, { json: true });

    const writes = (stdoutSpy.mock.calls as unknown as [string][]).map((c) => c[0]).join("");
    const parsed = JSON.parse(writes);
    expect(parsed.kind).toBe("status");
    expect(parsed.audit.id).toBe("a-1");
    expect(parsed.audit.status).toBe("complete");
    expect(parsed.audit.phases.complete).toBe(1);
    expect(parsed.audit.phases.skipped).toBe(1);
    expect(parsed.audit.durationMs).toBe(5 * 60 * 1000);
  });

  test("fails cleanly when vigolium-results/ is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-status-empty-"));
    tempDirs.push(dir);

    await statusCommand(dir, { json: true });
    expect(exitSpy).toHaveBeenCalledWith(2);
    const writes = (stdoutSpy.mock.calls as unknown as [string][]).map((c) => c[0]).join("");
    const parsed = JSON.parse(writes);
    expect(parsed.ok).toBe(false);
    expect(parsed.error).toContain("no vigolium-results/ directory");
  });

  test("fails cleanly when audit-state.json has no audits", async () => {
    const target = makeTarget({ schema_version: 1, audits: [] });
    tempDirs.push(target);

    await statusCommand(target, { json: true });
    expect(exitSpy).toHaveBeenCalledWith(2);
  });
});
