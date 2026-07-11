import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs.length = 0;
});

describe("validate_phase_output.py", () => {
  test("validates confirmed and theoretical findings as one durable result", () => {
    const root = mkdtempSync(join(tmpdir(), "vigolium-output-validator-"));
    tempDirs.push(root);
    const results = join(root, "vigolium-results");
    const confirmed = join(results, "findings", "H1-confirmed");
    const theoretical = join(results, "findings-theoretical", "M1-theoretical");
    mkdirSync(join(confirmed, "evidence"), { recursive: true });
    mkdirSync(theoretical, { recursive: true });
    mkdirSync(join(results, "findings-draft"), { recursive: true });

    writeFileSync(join(confirmed, "draft.md"), "Verdict: VALID\nPoC-Status: executed\n");
    writeFileSync(join(confirmed, "report.md"), `# H1\n${"x".repeat(600)}`);
    writeFileSync(join(confirmed, "poc.py"), "print('ok')\n");
    writeFileSync(join(theoretical, "draft.md"), "Verdict: VALID\nPoC-Status: blocked\n");
    writeFileSync(join(theoretical, "report.md"), `# M1\n${"y".repeat(600)}`);
    writeFileSync(
      join(results, "findings-draft", "consolidation-manifest.json"),
      JSON.stringify({ findings: [{ id: "H1" }], theoretical: [{ id: "M1" }] }),
    );
    writeFileSync(
      join(results, "audit-state.json"),
      JSON.stringify({ schema_version: 1, audits: [{ mode: "balanced" }] }),
    );
    writeFileSync(
      join(results, "final-audit-report.md"),
      `# Final Audit Report\n\nH1 confirmed. M1 theoretical.\n${"z".repeat(220)}`,
    );

    const script = resolve(
      import.meta.dir,
      "../../src/content/skills/audit/hooks/scripts/validate_phase_output.py",
    );
    const valid = spawnSync("python3", [script, "all", results], { encoding: "utf8" });
    expect(valid.status, valid.stderr).toBe(0);

    writeFileSync(join(theoretical, "draft.md"), "Verdict: VALID\nPoC-Status: executed\n");
    const invalid = spawnSync("python3", [script, "all", results], { encoding: "utf8" });
    expect(invalid.status).toBe(1);
    expect(invalid.stderr).toContain("belongs in findings/");
  });
});
