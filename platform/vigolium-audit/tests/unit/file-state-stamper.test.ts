import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { StateStore } from "../../src/engine/state.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs.length = 0;
});

describe("stamp_file_state.py compatibility", () => {
  test("writes the canonical sha256/string-phase schema consumed by StateStore", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-file-state-stamper-"));
    tempDirs.push(target);
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(join(target, "src"), { recursive: true });
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(join(target, "src", "app.ts"), "export const value = 1;\n");
    writeFileSync(
      join(resultsDir, "audit-state.json"),
      JSON.stringify({
        schema_version: 1,
        audits: [{
          audit_id: "audit-1",
          mode: "deep",
          phases: { D1: { status: "complete" }, D12: { status: "complete" } },
        }],
      }),
    );

    const script = resolve(import.meta.dir, "../../src/content/skills/audit/scripts/stamp_file_state.py");
    const run = spawnSync("python3", [script, "--target", target], { encoding: "utf8" });
    expect(run.status, run.stderr).toBe(0);

    const state = await new StateStore(resultsDir).loadFileState();
    expect(state.files["src/app.ts"]?.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(state.files["src/app.ts"]?.last_audits).toEqual(["audit-1"]);
    expect(state.files["src/app.ts"]?.last_phases).toEqual(["D1", "D12"]);
  });
});
