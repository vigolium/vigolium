import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { evaluatePhaseArtifacts } from "../../src/engine/artifact-gates.js";
import type { PhaseDef } from "../../src/engine/types.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs.length = 0;
});

function resultsDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "vigolium-artifact-gate-"));
  tempDirs.push(dir);
  return dir;
}

function phase(artifacts: NonNullable<PhaseDef["completion"]>["artifacts"]): PhaseDef {
  return {
    id: "T1",
    title: "Test",
    agent: null,
    requires_git: false,
    parallel_with: [],
    depends_on: [],
    completion: { artifacts, repair_attempts: 1, enforcement: "required" },
  };
}

describe("artifact completion gates", () => {
  test("requires a regular file with size, content, and valid JSON", async () => {
    const dir = resultsDir();
    const p = phase([{
      kind: "file",
      path: "reports/result.json",
      min_bytes: 12,
      contains: ["status"],
      json: true,
    }]);

    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(false);
    mkdirSync(join(dir, "reports"), { recursive: true });
    writeFileSync(join(dir, "reports", "result.json"), "not json status");
    expect((await evaluatePhaseArtifacts(p, dir)).failures[0]?.message).toContain("invalid JSON");
    writeFileSync(join(dir, "reports", "result.json"), '{"status":"ok"}\n');
    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(true);
  });

  test("can reject otherwise-valid artifacts that predate a fresh audit", async () => {
    const dir = resultsDir();
    mkdirSync(join(dir, "reports"), { recursive: true });
    const path = join(dir, "reports", "result.md");
    writeFileSync(path, "current-looking output");
    const old = new Date(Date.now() - 60_000);
    utimesSync(path, old, old);
    const p = phase([{
      kind: "file",
      path: "reports/result.md",
      min_bytes: 1,
      contains: [],
      json: false,
    }]);

    const stale = await evaluatePhaseArtifacts(p, dir, { notBeforeMs: Date.now() });
    expect(stale.ok).toBe(false);
    expect(stale.failures[0]?.message).toContain("predates the active audit");
    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(true); // resume/no freshness gate
  });

  test("supports glob and any-of contracts", async () => {
    const dir = resultsDir();
    const p = phase([{
      kind: "any",
      rules: [
        { kind: "file", path: "no-findings.md", min_bytes: 5, contains: [], json: false },
        { kind: "glob", pattern: "drafts/*.md", min_matches: 2, each_min_bytes: 3 },
      ],
    }]);

    mkdirSync(join(dir, "drafts"), { recursive: true });
    writeFileSync(join(dir, "drafts", "a.md"), "aaa");
    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(false);
    writeFileSync(join(dir, "drafts", "b.md"), "bbb");
    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(true);
  });

  test("validates required content only in selected glob matches", async () => {
    const dir = resultsDir();
    mkdirSync(join(dir, "drafts"), { recursive: true });
    writeFileSync(join(dir, "drafts", "invalid.md"), "Verdict: INVALID\n");
    writeFileSync(join(dir, "drafts", "valid.md"), "Verdict: VALID\n");
    const p = phase([{
      kind: "glob",
      pattern: "drafts/*.md",
      min_matches: 0,
      each_min_bytes: 1,
      select_contains: ["Verdict: VALID"],
      each_contains: ["Triage-Priority:"],
    }]);

    const failed = await evaluatePhaseArtifacts(p, dir);
    expect(failed.ok).toBe(false);
    expect(failed.failures[0]?.message).toContain("Triage-Priority:");
    writeFileSync(join(dir, "drafts", "valid.md"), "Verdict: VALID\nTriage-Priority: P1\n");
    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(true);
  });

  test("rejects symlinks as completion artifacts", async () => {
    const dir = resultsDir();
    const outside = join(dir, "outside.txt");
    writeFileSync(outside, "valid contents");
    mkdirSync(join(dir, "reports"), { recursive: true });
    symlinkSync(outside, join(dir, "reports", "linked.txt"));
    const p = phase([{
      kind: "file",
      path: "reports/linked.txt",
      min_bytes: 1,
      contains: [],
      json: false,
    }]);
    const result = await evaluatePhaseArtifacts(p, dir);
    expect(result.ok).toBe(false);
    expect(result.failures[0]?.message).toContain("not a regular file");
  });

  test("rejects regular files reached through a parent symlink escape", async () => {
    const dir = resultsDir();
    const outside = resultsDir();
    mkdirSync(join(outside, "reports"), { recursive: true });
    writeFileSync(join(outside, "reports", "result.md"), "valid contents");
    symlinkSync(join(outside, "reports"), join(dir, "linked-parent"));
    const p = phase([{
      kind: "file",
      path: "linked-parent/result.md",
      min_bytes: 1,
      contains: [],
      json: false,
    }]);
    const result = await evaluatePhaseArtifacts(p, dir);
    expect(result.ok).toBe(false);
    expect(result.failures[0]?.message).toContain("resolves outside");
  });

  test("requires a complete report in every confirmed and theoretical finding", async () => {
    const dir = resultsDir();
    mkdirSync(join(dir, "findings", "H1-one"), { recursive: true });
    mkdirSync(join(dir, "findings-theoretical", "M1-two"), { recursive: true });
    writeFileSync(join(dir, "findings", "H1-one", "report.md"), "x".repeat(12));
    const p = phase([{
      kind: "finding_reports",
      roots: ["findings", "findings-theoretical"],
      filename: "report.md",
      min_bytes: 10,
      allow_empty: true,
      manifest_lists: ["findings", "theoretical"],
    }]);

    const failed = await evaluatePhaseArtifacts(p, dir);
    expect(failed.ok).toBe(false);
    expect(failed.failures[0]?.message).toContain("findings-theoretical/M1-two/report.md");
    writeFileSync(join(dir, "findings-theoretical", "M1-two", "report.md"), "y".repeat(12));
    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(true);
  });

  test("does not let an empty findings tree pass when the manifest names findings", async () => {
    const dir = resultsDir();
    mkdirSync(join(dir, "findings-draft"), { recursive: true });
    writeFileSync(
      join(dir, "findings-draft", "consolidation-manifest.json"),
      JSON.stringify({ findings: [{ id: "H1" }], theoretical: [{ id: "M1" }] }),
    );
    const p = phase([{
      kind: "finding_reports",
      roots: ["findings", "findings-theoretical"],
      filename: "report.md",
      min_bytes: 10,
      allow_empty: true,
      manifest_path: "findings-draft/consolidation-manifest.json",
      manifest_lists: ["findings", "theoretical"],
    }]);

    const missing = await evaluatePhaseArtifacts(p, dir);
    expect(missing.ok).toBe(false);
    expect(missing.failures[0]?.message).toContain("manifest finding H1");

    mkdirSync(join(dir, "findings", "H1-one"), { recursive: true });
    mkdirSync(join(dir, "findings-theoretical", "M1-two"), { recursive: true });
    writeFileSync(join(dir, "findings", "H1-one", "report.md"), "x".repeat(12));
    writeFileSync(join(dir, "findings-theoretical", "M1-two", "report.md"), "y".repeat(12));
    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(true);
  });

  test("ignores non-finding directories inside finalized buckets", async () => {
    const dir = resultsDir();
    mkdirSync(join(dir, "findings", "notes"), { recursive: true });
    mkdirSync(join(dir, "findings-draft"), { recursive: true });
    writeFileSync(
      join(dir, "findings-draft", "consolidation-manifest.json"),
      JSON.stringify({ findings: [], theoretical: [] }),
    );
    const p = phase([{
      kind: "finding_reports",
      roots: ["findings", "findings-theoretical"],
      filename: "report.md",
      min_bytes: 10,
      allow_empty: true,
      manifest_path: "findings-draft/consolidation-manifest.json",
      manifest_lists: ["findings", "theoretical"],
    }]);

    expect((await evaluatePhaseArtifacts(p, dir)).ok).toBe(true);
  });
});
