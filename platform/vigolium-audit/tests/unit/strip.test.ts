import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { stripRawArtifacts } from "../../src/engine/strip-artifacts.js";

function seedResultsDir(): { target: string; resultsDir: string } {
  const target = mkdtempSync(join(tmpdir(), "vigolium-audit-strip-unit-"));
  const resultsDir = join(target, "vigolium-results");
  mkdirSync(resultsDir, { recursive: true });
  writeFileSync(join(resultsDir, "audit-state.json"), '{"schema_version":1,"audits":[]}');
  writeFileSync(join(resultsDir, "file-state.json"), '{"files":[]}');
  writeFileSync(join(resultsDir, "final-audit-report.md"), "# Final\n");
  mkdirSync(join(resultsDir, "attack-surface"), { recursive: true });
  writeFileSync(join(resultsDir, "attack-surface", "recon.md"), "# Recon\n");
  mkdirSync(join(resultsDir, "findings"), { recursive: true });
  writeFileSync(
    join(resultsDir, "findings", "L2-001.md"),
    "## L2-001\n- Severity: High\n",
  );
  // Raw byproducts.
  mkdirSync(join(resultsDir, "findings-draft"), { recursive: true });
  writeFileSync(
    join(resultsDir, "findings-draft", "L3-001.md"),
    "## L3-001\n- Severity: Medium\n",
  );
  writeFileSync(
    join(resultsDir, "findings-draft", "L2-001.md"),
    "## L2-001 DRAFT\n",
  );
  mkdirSync(join(resultsDir, "semgrep-res"), { recursive: true });
  writeFileSync(join(resultsDir, "semgrep-res", "raw.json"), "{}");
  mkdirSync(join(resultsDir, ".archive", "audit-1", "L1"), { recursive: true });
  writeFileSync(join(resultsDir, ".archive", "audit-1", "L1", "stale.md"), "");
  return { target, resultsDir };
}

describe("stripRawArtifacts", () => {
  test("preserves allowlist; strips raw byproducts", async () => {
    const { resultsDir } = seedResultsDir();
    await stripRawArtifacts(resultsDir);

    expect(existsSync(join(resultsDir, "audit-state.json"))).toBe(true);
    expect(existsSync(join(resultsDir, "file-state.json"))).toBe(true);
    expect(existsSync(join(resultsDir, "final-audit-report.md"))).toBe(true);
    expect(existsSync(join(resultsDir, "attack-surface"))).toBe(true);
    expect(existsSync(join(resultsDir, "findings"))).toBe(true);

    expect(existsSync(join(resultsDir, "findings-draft"))).toBe(false);
    expect(existsSync(join(resultsDir, "semgrep-res"))).toBe(false);
    expect(existsSync(join(resultsDir, ".archive"))).toBe(false);
  });

  test("promotes leftover drafts into findings/ without clobbering finals", async () => {
    const { resultsDir } = seedResultsDir();
    await stripRawArtifacts(resultsDir);

    const finals = readdirSync(join(resultsDir, "findings")).sort();
    // L2-001 was already in findings/ (final wins, draft discarded).
    // L3-001 only existed as a draft → promoted.
    expect(finals).toEqual(["L2-001.md", "L3-001.md"]);

    // The original (non-clobbered) L2-001 final body is intact.
    const l2 = await import("fs/promises").then((m) =>
      m.readFile(join(resultsDir, "findings", "L2-001.md"), "utf8"),
    );
    expect(l2).toContain("Severity: High");
    expect(l2).not.toContain("DRAFT");
  });

  test("idempotent: running strip twice is a no-op on already-stripped tree", async () => {
    const { resultsDir } = seedResultsDir();
    await stripRawArtifacts(resultsDir);
    const after1 = readdirSync(resultsDir).sort();
    await stripRawArtifacts(resultsDir);
    const after2 = readdirSync(resultsDir).sort();
    expect(after2).toEqual(after1);
  });

  test("can strip deep-style workspaces without promoting raw drafts", async () => {
    const { resultsDir } = seedResultsDir();
    mkdirSync(join(resultsDir, "confirm-workspace"), { recursive: true });
    writeFileSync(join(resultsDir, "confirm-workspace", "findings-inventory.json"), "{}");
    mkdirSync(join(resultsDir, "codeql-artifacts-prior-round"), { recursive: true });
    writeFileSync(join(resultsDir, "attack-pattern-registry.json"), "{}");

    await stripRawArtifacts(resultsDir, { promoteDrafts: false, keepConfirmWorkspace: false });

    expect(existsSync(join(resultsDir, "findings-draft"))).toBe(false);
    expect(existsSync(join(resultsDir, "findings", "L3-001.md"))).toBe(false);
    expect(existsSync(join(resultsDir, "confirm-workspace"))).toBe(false);
    expect(existsSync(join(resultsDir, "codeql-artifacts-prior-round"))).toBe(false);
    expect(existsSync(join(resultsDir, "attack-pattern-registry.json"))).toBe(false);
    expect(existsSync(join(resultsDir, "file-state.json"))).toBe(true);
  });

  test("preserves confirm-workspace by default for completed confirm outputs", async () => {
    const { resultsDir } = seedResultsDir();
    mkdirSync(join(resultsDir, "confirm-workspace"), { recursive: true });
    writeFileSync(join(resultsDir, "confirm-workspace", "env-connection.json"), "{}");

    await stripRawArtifacts(resultsDir);

    expect(existsSync(join(resultsDir, "confirm-workspace", "env-connection.json"))).toBe(true);
  });

  test("preserves arbitrary top-level *.md reports (mode-specific names)", async () => {
    const { resultsDir } = seedResultsDir();
    writeFileSync(join(resultsDir, "confirmation-report.md"), "# Confirm\n");
    writeFileSync(join(resultsDir, "merge-report.md"), "# Merge\n");
    await stripRawArtifacts(resultsDir);
    expect(existsSync(join(resultsDir, "confirmation-report.md"))).toBe(true);
    expect(existsSync(join(resultsDir, "merge-report.md"))).toBe(true);
  });
});
