import { describe, expect, test } from "bun:test";
import { spawnSync } from "child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { resolveArchonDirSeed, repoSlug } from "../../src/cli/seed.js";
import type { AuditRecord, AuditState } from "../../src/engine/types.js";

/** Initialize a small two-commit bare-style repo we can clone from. */
function makeFixtureRepo(): { url: string; firstCommit: string; secondCommit: string; cleanup: () => void } {
  const root = mkdtempSync(join(tmpdir(), "archon-seed-test-fixture-"));
  const work = join(root, "work");
  const remote = join(root, "remote.git");
  mkdirSync(work, { recursive: true });
  run("git", ["init", "-b", "main", work]);
  run("git", ["-C", work, "config", "user.email", "test@example.com"]);
  run("git", ["-C", work, "config", "user.name", "test"]);
  writeFileSync(join(work, "README.md"), "first\n");
  run("git", ["-C", work, "add", "README.md"]);
  run("git", ["-C", work, "commit", "-m", "first"]);
  const firstCommit = run("git", ["-C", work, "rev-parse", "HEAD"]).stdout.trim();
  writeFileSync(join(work, "second.txt"), "second\n");
  run("git", ["-C", work, "add", "second.txt"]);
  run("git", ["-C", work, "commit", "-m", "second"]);
  const secondCommit = run("git", ["-C", work, "rev-parse", "HEAD"]).stdout.trim();
  // Bare clone the working dir into a "remote" so clones go through real git
  // transport machinery (file:// works fine with fetch-by-SHA on a local bare).
  run("git", ["clone", "--bare", work, remote]);
  // Allow fetch by arbitrary SHA on this bare clone (mirrors GitHub's default).
  run("git", ["-C", remote, "config", "uploadpack.allowReachableSHA1InWant", "true"]);
  run("git", ["-C", remote, "config", "uploadpack.allowAnySHA1InWant", "true"]);
  return {
    url: remote,
    firstCommit,
    secondCommit,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function run(bin: string, args: string[]): { stdout: string; stderr: string; status: number | null } {
  const r = spawnSync(bin, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (r.status !== 0) {
    throw new Error(`${bin} ${args.join(" ")} failed: ${r.stderr}`);
  }
  return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", status: r.status };
}

function writeAuditStateAt(archonDir: string, audit: AuditRecord): void {
  const state: AuditState = { schema_version: 1, audits: [audit] };
  writeFileSync(join(archonDir, "audit-state.json"), JSON.stringify(state, null, 2));
}

function makeAudit(overrides: Partial<AuditRecord>): AuditRecord {
  return {
    audit_id: "test-audit",
    commit: "deadbeef",
    branch: "main",
    repository: "git@github.com:fake/repo.git",
    mode: "deep",
    model: null,
    agent_sdk: "claude-code",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T01:00:00Z",
    status: "complete",
    phases: {},
    ...overrides,
  };
}

describe("repoSlug", () => {
  test("git@github.com:owner/repo.git → owner-repo", () => {
    expect(repoSlug("git@github.com:owner/repo.git")).toBe("owner-repo");
  });
  test("https://github.com/owner/repo → owner-repo", () => {
    expect(repoSlug("https://github.com/owner/repo")).toBe("owner-repo");
  });
  test("https://github.com/owner/repo.git → owner-repo", () => {
    expect(repoSlug("https://github.com/owner/repo.git")).toBe("owner-repo");
  });
  test("plain local path → basename", () => {
    expect(repoSlug("/tmp/some-repo")).toBe("some-repo");
  });
});

describe("resolveArchonDirSeed: validation", () => {
  test("missing directory → fatal", async () => {
    await expect(
      resolveArchonDirSeed({
        fromArchonDir: "/nonexistent/path/here",
        keepClone: false,
      }),
    ).rejects.toThrow(/not a directory/);
  });

  test("missing audit-state.json → fatal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "archon-seed-empty-"));
    try {
      await expect(
        resolveArchonDirSeed({ fromArchonDir: dir, keepClone: false }),
      ).rejects.toThrow(/no audit-state.json/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("audit-state with empty audits[] → fatal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "archon-seed-emptylist-"));
    try {
      writeFileSync(join(dir, "audit-state.json"), JSON.stringify({ schema_version: 1, audits: [] }));
      await expect(
        resolveArchonDirSeed({ fromArchonDir: dir, keepClone: false }),
      ).rejects.toThrow(/no audits to seed from/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("null repository → fatal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "archon-seed-norepo-"));
    try {
      writeAuditStateAt(dir, makeAudit({ repository: null }));
      await expect(
        resolveArchonDirSeed({ fromArchonDir: dir, keepClone: false }),
      ).rejects.toThrow(/no recorded repository URL/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("null commit → fatal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "archon-seed-nocommit-"));
    try {
      writeAuditStateAt(dir, makeAudit({ commit: null }));
      await expect(
        resolveArchonDirSeed({ fromArchonDir: dir, keepClone: false }),
      ).rejects.toThrow(/no recorded commit/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("--from-audit referencing unknown id → fatal", async () => {
    const fixture = makeFixtureRepo();
    const dir = mkdtempSync(join(tmpdir(), "archon-seed-badid-"));
    try {
      writeAuditStateAt(dir, makeAudit({ repository: fixture.url, commit: fixture.firstCommit }));
      await expect(
        resolveArchonDirSeed({
          fromArchonDir: dir,
          keepClone: false,
          fromAuditId: "no-such-audit",
        }),
      ).rejects.toThrow(/no-such-audit not found/);
    } finally {
      fixture.cleanup();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("--target points at a non-empty directory → fatal", async () => {
    const fixture = makeFixtureRepo();
    const dir = mkdtempSync(join(tmpdir(), "archon-seed-fulltarget-"));
    const target = mkdtempSync(join(tmpdir(), "archon-seed-target-"));
    writeFileSync(join(target, "leftover"), "x");
    try {
      writeAuditStateAt(dir, makeAudit({ repository: fixture.url, commit: fixture.firstCommit }));
      await expect(
        resolveArchonDirSeed({
          fromArchonDir: dir,
          targetOverride: target,
          keepClone: false,
        }),
      ).rejects.toThrow(/non-empty/);
    } finally {
      fixture.cleanup();
      rmSync(dir, { recursive: true, force: true });
      rmSync(target, { recursive: true, force: true });
    }
  });
});

describe("resolveArchonDirSeed: clone + sync-back happy path", () => {
  test("clones at pinned commit, copies archon/ in, syncs new files back, removes temp clone", async () => {
    const fixture = makeFixtureRepo();
    const fromDir = mkdtempSync(join(tmpdir(), "archon-seed-from-"));
    try {
      // Pin the older commit so the test verifies we don't end up on HEAD.
      writeAuditStateAt(fromDir, makeAudit({ repository: fixture.url, commit: fixture.firstCommit }));
      // A finding directory + report file that should land in the clone.
      mkdirSync(join(fromDir, "findings", "H1-test"), { recursive: true });
      writeFileSync(join(fromDir, "findings", "H1-test", "report.md"), "original report\n");

      const handle = await resolveArchonDirSeed({
        fromArchonDir: fromDir,
        keepClone: false,
      });

      // Working tree pinned to firstCommit, so second.txt should be absent.
      expect(existsSync(join(handle.clonedTargetDir, "README.md"))).toBe(true);
      expect(existsSync(join(handle.clonedTargetDir, "second.txt"))).toBe(false);
      // archon/ landed in the clone.
      expect(
        readFileSync(join(handle.clonedTargetDir, "archon", "findings", "H1-test", "report.md"), "utf8"),
      ).toBe("original report\n");

      // Simulate a confirm-mode run writing into the clone's archon/.
      writeFileSync(join(handle.clonedTargetDir, "archon", "confirmation-report.md"), "verified\n");
      writeFileSync(
        join(handle.clonedTargetDir, "archon", "findings", "H1-test", "report.md"),
        "updated report\n",
      );

      const cloneDir = handle.clonedTargetDir;
      await handle.cleanup();

      // Sync-back: new file present in original, existing file overwritten.
      expect(readFileSync(join(fromDir, "confirmation-report.md"), "utf8")).toBe("verified\n");
      expect(readFileSync(join(fromDir, "findings", "H1-test", "report.md"), "utf8")).toBe(
        "updated report\n",
      );

      // Temp clone wiped (parent of cloneDir is the mkdtemp root).
      expect(existsSync(cloneDir)).toBe(false);
    } finally {
      fixture.cleanup();
      rmSync(fromDir, { recursive: true, force: true });
    }
  });

  test("--keep-clone leaves the clone in place", async () => {
    const fixture = makeFixtureRepo();
    const fromDir = mkdtempSync(join(tmpdir(), "archon-seed-keep-"));
    try {
      writeAuditStateAt(fromDir, makeAudit({ repository: fixture.url, commit: fixture.secondCommit }));
      const handle = await resolveArchonDirSeed({
        fromArchonDir: fromDir,
        keepClone: true,
      });
      await handle.cleanup();
      expect(existsSync(handle.clonedTargetDir)).toBe(true);
      expect(existsSync(join(handle.clonedTargetDir, "second.txt"))).toBe(true);
      // Clean up manually since keepClone=true.
      rmSync(handle.clonedTargetDir, { recursive: true, force: true });
    } finally {
      fixture.cleanup();
      rmSync(fromDir, { recursive: true, force: true });
    }
  });

  test("--target overrides clone destination; clone is preserved", async () => {
    const fixture = makeFixtureRepo();
    const fromDir = mkdtempSync(join(tmpdir(), "archon-seed-target-from-"));
    const targetParent = mkdtempSync(join(tmpdir(), "archon-seed-target-parent-"));
    const target = join(targetParent, "explicit-clone");
    try {
      writeAuditStateAt(fromDir, makeAudit({ repository: fixture.url, commit: fixture.secondCommit }));
      const handle = await resolveArchonDirSeed({
        fromArchonDir: fromDir,
        targetOverride: target,
        keepClone: false,
      });
      expect(handle.clonedTargetDir).toBe(target);
      await handle.cleanup();
      // --target implies the user manages cleanup; the clone stays even though
      // keepClone is false.
      expect(existsSync(target)).toBe(true);
    } finally {
      fixture.cleanup();
      rmSync(fromDir, { recursive: true, force: true });
      rmSync(targetParent, { recursive: true, force: true });
    }
  });

  test("supports nested archon/ layout (project dir + archon/ subdir)", async () => {
    const fixture = makeFixtureRepo();
    const projectDir = mkdtempSync(join(tmpdir(), "archon-seed-nested-"));
    const archonDir = join(projectDir, "archon");
    mkdirSync(archonDir, { recursive: true });
    try {
      writeAuditStateAt(archonDir, makeAudit({ repository: fixture.url, commit: fixture.secondCommit }));
      writeFileSync(join(archonDir, "marker.txt"), "marker\n");
      const handle = await resolveArchonDirSeed({
        fromArchonDir: projectDir,
        keepClone: false,
      });
      // archon/ in the clone matches the input's archon/ contents.
      expect(readFileSync(join(handle.clonedTargetDir, "archon", "marker.txt"), "utf8")).toBe(
        "marker\n",
      );
      // Confirm sync-back lands in the original archon/ subdir.
      writeFileSync(join(handle.clonedTargetDir, "archon", "new.txt"), "new\n");
      await handle.cleanup();
      expect(readFileSync(join(archonDir, "new.txt"), "utf8")).toBe("new\n");
      // The project dir itself is not the archon dir, so files there are untouched.
      expect(readdirSync(projectDir).sort()).toEqual(["archon"]);
    } finally {
      fixture.cleanup();
      rmSync(projectDir, { recursive: true, force: true });
    }
  });

  test("cleanup is idempotent", async () => {
    const fixture = makeFixtureRepo();
    const fromDir = mkdtempSync(join(tmpdir(), "archon-seed-idem-"));
    try {
      writeAuditStateAt(fromDir, makeAudit({ repository: fixture.url, commit: fixture.secondCommit }));
      const handle = await resolveArchonDirSeed({
        fromArchonDir: fromDir,
        keepClone: false,
      });
      writeFileSync(join(handle.clonedTargetDir, "archon", "marker.txt"), "x\n");
      await handle.cleanup();
      await expect(handle.cleanup()).resolves.toBeUndefined();
      expect(readFileSync(join(fromDir, "marker.txt"), "utf8")).toBe("x\n");
    } finally {
      fixture.cleanup();
      rmSync(fromDir, { recursive: true, force: true });
    }
  });
});
