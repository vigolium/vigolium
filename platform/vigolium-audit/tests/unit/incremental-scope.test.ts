import { describe, expect, test, afterEach } from "bun:test";
import { spawnSync } from "child_process";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { computeIncrementalScope } from "../../src/cli/incremental-scope.js";
import { StateStore } from "../../src/engine/state.js";

const gitAvailable = spawnSync("git", ["--version"], { stdio: "ignore" }).status === 0;

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
  tempDirs.length = 0;
});

function gitRepo(): string {
  const d = mkdtempSync(join(tmpdir(), "vigolium-audit-incr-"));
  tempDirs.push(d);
  const run = (...args: string[]) => spawnSync("git", args, { cwd: d, stdio: "ignore" });
  run("init");
  run("config", "user.email", "t@t.t");
  run("config", "user.name", "t");
  return d;
}

function commitAll(dir: string): void {
  spawnSync("git", ["add", "-A"], { cwd: dir, stdio: "ignore" });
  spawnSync("git", ["commit", "-m", "x"], { cwd: dir, stdio: "ignore" });
}

describe.if(gitAvailable)("computeIncrementalScope round-trips the file-state snapshot", () => {
  test("reports a hash-mismatch with prior phases after a tracked file changes", async () => {
    const target = gitRepo();
    writeFileSync(join(target, "a.ts"), "v1\n");
    writeFileSync(join(target, "b.ts"), "stable\n");
    commitAll(target);

    // Producer: record the baseline (what the orchestrator does on a complete audit).
    const store = new StateStore(join(target, "vigolium-results"));
    await store.recordFileSnapshot({
      targetDir: target,
      files: ["a.ts", "b.ts"],
      auditId: "audit-1",
      completedPhaseIds: ["L1", "L2"],
    });

    // a.ts drifts; b.ts is untouched.
    writeFileSync(join(target, "a.ts"), "v2-changed\n");

    // Consumer: the same baseline the `incremental-scope` command reads.
    const scope = await computeIncrementalScope({ target });
    expect(scope.baselinePresent).toBe(true);

    const a = scope.changed.find((c) => c.path === "a.ts");
    expect(a?.reason).toBe("hash-mismatch");
    expect(a?.priorPhases).toEqual(["L1", "L2"]);
    expect(scope.changed.find((c) => c.path === "b.ts")).toBeUndefined();
    expect(scope.phasesPriorlyTouching).toEqual(["L1", "L2"]);
  });

  test("treats every tracked file as new when no baseline exists", async () => {
    const target = gitRepo();
    writeFileSync(join(target, "a.ts"), "x\n");
    commitAll(target);

    const scope = await computeIncrementalScope({ target });
    expect(scope.baselinePresent).toBe(false);
    // No baseline → 'missing-from-state' is suppressed (reason stays null), so
    // nothing is flagged; the first run has nothing to diff against.
    expect(scope.changed).toHaveLength(0);
  });

  test("flags a newly added file as missing-from-state once a baseline exists", async () => {
    const target = gitRepo();
    writeFileSync(join(target, "a.ts"), "x\n");
    commitAll(target);
    const store = new StateStore(join(target, "vigolium-results"));
    await store.recordFileSnapshot({ targetDir: target, files: ["a.ts"], auditId: "audit-1", completedPhaseIds: ["L1"] });

    writeFileSync(join(target, "new.ts"), "fresh\n");
    commitAll(target);

    const scope = await computeIncrementalScope({ target });
    const fresh = scope.changed.find((c) => c.path === "new.ts");
    expect(fresh?.reason).toBe("missing-from-state");
  });

  test("throws on a non-git target", async () => {
    const d = mkdtempSync(join(tmpdir(), "vigolium-audit-nogit-"));
    tempDirs.push(d);
    await expect(computeIncrementalScope({ target: d })).rejects.toThrow(/not a git repository/);
  });
});
