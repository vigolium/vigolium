import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { stripRawArtifacts } from "../../src/engine/orchestrator.js";

function seedArchonDir(): { target: string; archonDir: string } {
  const target = mkdtempSync(join(tmpdir(), "archon-strip-unit-"));
  const archonDir = join(target, "archon");
  mkdirSync(archonDir, { recursive: true });
  writeFileSync(join(archonDir, "audit-state.json"), '{"schema_version":1,"audits":[]}');
  writeFileSync(join(archonDir, "file-state.json"), '{"files":[]}');
  writeFileSync(join(archonDir, "final-audit-report.md"), "# Final\n");
  mkdirSync(join(archonDir, "attack-surface"), { recursive: true });
  writeFileSync(join(archonDir, "attack-surface", "recon.md"), "# Recon\n");
  mkdirSync(join(archonDir, "findings"), { recursive: true });
  writeFileSync(
    join(archonDir, "findings", "L2-001.md"),
    "## L2-001\n- Severity: High\n",
  );
  // Raw byproducts.
  mkdirSync(join(archonDir, "findings-draft"), { recursive: true });
  writeFileSync(
    join(archonDir, "findings-draft", "L3-001.md"),
    "## L3-001\n- Severity: Medium\n",
  );
  writeFileSync(
    join(archonDir, "findings-draft", "L2-001.md"),
    "## L2-001 DRAFT\n",
  );
  mkdirSync(join(archonDir, "semgrep-res"), { recursive: true });
  writeFileSync(join(archonDir, "semgrep-res", "raw.json"), "{}");
  mkdirSync(join(archonDir, ".archive", "audit-1", "L1"), { recursive: true });
  writeFileSync(join(archonDir, ".archive", "audit-1", "L1", "stale.md"), "");
  return { target, archonDir };
}

describe("stripRawArtifacts", () => {
  test("preserves allowlist; strips raw byproducts", async () => {
    const { archonDir } = seedArchonDir();
    await stripRawArtifacts(archonDir);

    expect(existsSync(join(archonDir, "audit-state.json"))).toBe(true);
    expect(existsSync(join(archonDir, "file-state.json"))).toBe(true);
    expect(existsSync(join(archonDir, "final-audit-report.md"))).toBe(true);
    expect(existsSync(join(archonDir, "attack-surface"))).toBe(true);
    expect(existsSync(join(archonDir, "findings"))).toBe(true);

    expect(existsSync(join(archonDir, "findings-draft"))).toBe(false);
    expect(existsSync(join(archonDir, "semgrep-res"))).toBe(false);
    expect(existsSync(join(archonDir, ".archive"))).toBe(false);
  });

  test("promotes leftover drafts into findings/ without clobbering finals", async () => {
    const { archonDir } = seedArchonDir();
    await stripRawArtifacts(archonDir);

    const finals = readdirSync(join(archonDir, "findings")).sort();
    // L2-001 was already in findings/ (final wins, draft discarded).
    // L3-001 only existed as a draft → promoted.
    expect(finals).toEqual(["L2-001.md", "L3-001.md"]);

    // The original (non-clobbered) L2-001 final body is intact.
    const l2 = await import("fs/promises").then((m) =>
      m.readFile(join(archonDir, "findings", "L2-001.md"), "utf8"),
    );
    expect(l2).toContain("Severity: High");
    expect(l2).not.toContain("DRAFT");
  });

  test("idempotent: running strip twice is a no-op on already-stripped tree", async () => {
    const { archonDir } = seedArchonDir();
    await stripRawArtifacts(archonDir);
    const after1 = readdirSync(archonDir).sort();
    await stripRawArtifacts(archonDir);
    const after2 = readdirSync(archonDir).sort();
    expect(after2).toEqual(after1);
  });

  test("can strip deep-style workspaces without promoting raw drafts", async () => {
    const { archonDir } = seedArchonDir();
    mkdirSync(join(archonDir, "confirm-workspace"), { recursive: true });
    writeFileSync(join(archonDir, "confirm-workspace", "findings-inventory.json"), "{}");
    mkdirSync(join(archonDir, "codeql-artifacts-prior-round"), { recursive: true });
    writeFileSync(join(archonDir, "attack-pattern-registry.json"), "{}");

    await stripRawArtifacts(archonDir, { promoteDrafts: false, keepConfirmWorkspace: false });

    expect(existsSync(join(archonDir, "findings-draft"))).toBe(false);
    expect(existsSync(join(archonDir, "findings", "L3-001.md"))).toBe(false);
    expect(existsSync(join(archonDir, "confirm-workspace"))).toBe(false);
    expect(existsSync(join(archonDir, "codeql-artifacts-prior-round"))).toBe(false);
    expect(existsSync(join(archonDir, "attack-pattern-registry.json"))).toBe(false);
    expect(existsSync(join(archonDir, "file-state.json"))).toBe(true);
  });

  test("preserves confirm-workspace by default for completed confirm outputs", async () => {
    const { archonDir } = seedArchonDir();
    mkdirSync(join(archonDir, "confirm-workspace"), { recursive: true });
    writeFileSync(join(archonDir, "confirm-workspace", "env-connection.json"), "{}");

    await stripRawArtifacts(archonDir);

    expect(existsSync(join(archonDir, "confirm-workspace", "env-connection.json"))).toBe(true);
  });

  test("preserves arbitrary top-level *.md reports (mode-specific names)", async () => {
    const { archonDir } = seedArchonDir();
    writeFileSync(join(archonDir, "confirmation-report.md"), "# Confirm\n");
    writeFileSync(join(archonDir, "merge-report.md"), "# Merge\n");
    await stripRawArtifacts(archonDir);
    expect(existsSync(join(archonDir, "confirmation-report.md"))).toBe(true);
    expect(existsSync(join(archonDir, "merge-report.md"))).toBe(true);
  });
});
