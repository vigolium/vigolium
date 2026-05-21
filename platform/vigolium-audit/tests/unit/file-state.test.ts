import { describe, expect, test, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { createHash } from "crypto";
import { StateStore } from "../../src/engine/state.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
  tempDirs.length = 0;
});

function makeDir(): string {
  const d = mkdtempSync(join(tmpdir(), "vigolium-audit-filestate-"));
  tempDirs.push(d);
  return d;
}

describe("StateStore.recordFileSnapshot", () => {
  test("hashes tracked files and persists attribution", async () => {
    const target = makeDir();
    mkdirSync(join(target, "src"), { recursive: true });
    writeFileSync(join(target, "src", "a.ts"), "alpha\n");
    writeFileSync(join(target, "src", "b.ts"), "beta\n");

    const store = new StateStore(join(target, "vigolium-results"));
    await store.recordFileSnapshot({
      targetDir: target,
      files: ["src/a.ts", "src/b.ts"],
      auditId: "audit-1",
      completedPhaseIds: ["L1", "L2"],
    });

    const state = await store.loadFileState();
    const expectA = createHash("sha256").update("alpha\n").digest("hex");
    expect(state.files["src/a.ts"]!.sha256).toBe(expectA);
    expect(state.files["src/a.ts"]!.last_audits).toEqual(["audit-1"]);
    expect(state.files["src/a.ts"]!.last_phases).toEqual(["L1", "L2"]);
  });

  test("merges audits + phases without duplicates and caps at 5 entries", async () => {
    const target = makeDir();
    writeFileSync(join(target, "a.ts"), "x");
    const store = new StateStore(join(target, "vigolium-results"));

    for (let i = 1; i <= 7; i++) {
      await store.recordFileSnapshot({
        targetDir: target,
        files: ["a.ts"],
        auditId: `audit-${i}`,
        completedPhaseIds: [`P${i}`],
      });
    }
    const state = await store.loadFileState();
    expect(state.files["a.ts"]!.last_audits.length).toBe(5);
    expect(state.files["a.ts"]!.last_audits).toContain("audit-7");
    expect(state.files["a.ts"]!.last_audits).not.toContain("audit-1");
    expect(state.files["a.ts"]!.last_phases.length).toBe(5);
  });

  test("skips files that fail to read", async () => {
    const target = makeDir();
    writeFileSync(join(target, "exists.ts"), "y");
    const store = new StateStore(join(target, "vigolium-results"));

    await store.recordFileSnapshot({
      targetDir: target,
      files: ["exists.ts", "missing.ts"],
      auditId: "a",
      completedPhaseIds: ["Q"],
    });
    const state = await store.loadFileState();
    expect(state.files["exists.ts"]).toBeDefined();
    expect(state.files["missing.ts"]).toBeUndefined();
  });
});
