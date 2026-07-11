import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { archivePriorCoreArtifacts } from "../../src/engine/artifact-lifecycle.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs.length = 0;
});

describe("archivePriorCoreArtifacts", () => {
  test("moves phase-owned outputs while preserving durable state and other mode metadata", async () => {
    const root = mkdtempSync(join(tmpdir(), "vigolium-artifact-lifecycle-"));
    tempDirs.push(root);
    const results = join(root, "vigolium-results");
    mkdirSync(join(results, "attack-surface"), { recursive: true });
    mkdirSync(join(results, "findings", "H1-old"), { recursive: true });
    mkdirSync(join(results, "confirm-workspace"), { recursive: true });
    writeFileSync(join(results, "attack-surface", "knowledge-base-report.md"), "old kb");
    writeFileSync(join(results, "findings", "H1-old", "report.md"), "old report");
    writeFileSync(join(results, "final-audit-report.md"), "old final");
    writeFileSync(join(results, "audit-state.json"), '{"schema_version":1,"audits":[]}');
    writeFileSync(join(results, "file-state.json"), '{"schema_version":1,"files":{}}');
    writeFileSync(join(results, "INFO.md"), "operator context");
    writeFileSync(join(results, "confirmation-report.md"), "confirmation history");

    const moved = await archivePriorCoreArtifacts(results, "2026-07-11T12:34:56.000Z");
    expect(moved).toEqual(["attack-surface", "findings", "final-audit-report.md"]);
    expect(existsSync(join(results, "attack-surface"))).toBe(false);
    const archive = join(results, ".archive", "pre-run", "2026-07-11T12_34_56.000Z");
    expect(readFileSync(join(archive, "attack-surface", "knowledge-base-report.md"), "utf8")).toBe("old kb");
    expect(readFileSync(join(archive, "findings", "H1-old", "report.md"), "utf8")).toBe("old report");
    for (const preserved of [
      "audit-state.json",
      "file-state.json",
      "INFO.md",
      "confirmation-report.md",
      "confirm-workspace",
    ]) {
      expect(existsSync(join(results, preserved)), preserved).toBe(true);
    }
  });
});
