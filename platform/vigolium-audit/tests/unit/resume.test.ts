import { describe, expect, test, afterEach, beforeEach, spyOn } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { pickResumableAudit, resumeCommand } from "../../src/cli/resume.js";
import type { AuditRecord } from "../../src/engine/types.js";

function audit(overrides: Partial<AuditRecord>): AuditRecord {
  return {
    audit_id: "a-x",
    commit: null,
    branch: null,
    repository: null,
    mode: "deep",
    model: null,
    agent_sdk: "claude-cli",
    started_at: "2026-05-12T00:00:00.000Z",
    completed_at: null,
    status: "complete",
    phases: {},
    ...overrides,
  };
}

function makeTarget(state: object): string {
  const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-resume-test-"));
  mkdirSync(join(dir, "vigolium-results"), { recursive: true });
  writeFileSync(join(dir, "vigolium-results", "audit-state.json"), JSON.stringify(state));
  return dir;
}

describe("pickResumableAudit", () => {
  test("returns null when no audits exist", () => {
    expect(pickResumableAudit([])).toBeNull();
  });

  test("returns null when every audit is complete", () => {
    expect(
      pickResumableAudit([
        audit({ audit_id: "a-1", status: "complete" }),
        audit({ audit_id: "a-2", status: "complete" }),
      ]),
    ).toBeNull();
  });

  test("prefers in_progress over aborted and failed", () => {
    const picked = pickResumableAudit([
      audit({ audit_id: "a-1", status: "failed" }),
      audit({ audit_id: "a-2", status: "aborted" }),
      audit({ audit_id: "a-3", status: "in_progress" }),
    ]);
    expect(picked?.audit_id).toBe("a-3");
  });

  test("prefers aborted over failed when no in_progress exists", () => {
    const picked = pickResumableAudit([
      audit({ audit_id: "a-1", status: "failed" }),
      audit({ audit_id: "a-2", status: "aborted" }),
    ]);
    expect(picked?.audit_id).toBe("a-2");
  });

  test("returns latest in_progress when multiple exist", () => {
    const picked = pickResumableAudit([
      audit({ audit_id: "a-1", status: "in_progress" }),
      audit({ audit_id: "a-2", status: "complete" }),
      audit({ audit_id: "a-3", status: "in_progress" }),
    ]);
    expect(picked?.audit_id).toBe("a-3");
  });
});

describe("resumeCommand", () => {
  const tempDirs: string[] = [];
  let exitSpy: ReturnType<typeof spyOn>;
  let stdoutSpy: ReturnType<typeof spyOn>;

  beforeEach(() => {
    exitSpy = spyOn(process, "exit").mockImplementation(((..._a: unknown[]): never => undefined as never) as never);
    stdoutSpy = spyOn(process.stdout, "write").mockImplementation((() => true) as never);
    spyOn(console, "error").mockImplementation((() => {}) as never);
    spyOn(console, "log").mockImplementation((() => {}) as never);
  });

  afterEach(() => {
    for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
    tempDirs.length = 0;
    exitSpy.mockRestore();
    stdoutSpy.mockRestore();
  });

  test("errors in JSON mode when vigolium-results/ is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-resume-noresults-"));
    tempDirs.push(dir);
    await resumeCommand(dir, { json: true });
    const writes = (stdoutSpy.mock.calls as unknown as [string][]).map((c) => c[0]).join("");
    const parsed = JSON.parse(writes);
    expect(parsed.kind).toBe("resume");
    expect(parsed.ok).toBe(false);
    expect(parsed.error).toMatch(/no vigolium-results\//);
    expect(exitSpy).toHaveBeenCalledWith(2);
  });

  test("errors when every audit is already complete", async () => {
    const target = makeTarget({
      schema_version: 1,
      audits: [audit({ audit_id: "a-1", status: "complete" })],
    });
    tempDirs.push(target);
    await resumeCommand(target, { json: true });
    const writes = (stdoutSpy.mock.calls as unknown as [string][]).map((c) => c[0]).join("");
    const parsed = JSON.parse(writes);
    expect(parsed.kind).toBe("resume");
    expect(parsed.ok).toBe(false);
    expect(parsed.error).toMatch(/already complete/);
  });

  test("errors when audit-state.json has no audits at all", async () => {
    const target = makeTarget({ schema_version: 1, audits: [] });
    tempDirs.push(target);
    await resumeCommand(target, { json: true });
    const writes = (stdoutSpy.mock.calls as unknown as [string][]).map((c) => c[0]).join("");
    const parsed = JSON.parse(writes);
    expect(parsed.ok).toBe(false);
    expect(parsed.error).toMatch(/no audits recorded/);
  });
});
