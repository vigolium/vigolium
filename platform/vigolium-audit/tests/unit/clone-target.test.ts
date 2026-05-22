import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawnSync } from "child_process";
import { cloneRemoteTarget, isRemoteTargetUrl, normalizeRemote } from "../../src/cli/clone-target.js";

describe("isRemoteTargetUrl", () => {
  test("https GitHub URL → remote", () => {
    expect(isRemoteTargetUrl("https://github.com/Yoast/wordpress-seo")).toBe(true);
  });
  test("https GitLab URL → remote", () => {
    expect(isRemoteTargetUrl("https://gitlab.com/owner/repo")).toBe(true);
  });
  test("https URL with .git suffix → remote", () => {
    expect(isRemoteTargetUrl("https://github.com/owner/repo.git")).toBe(true);
  });
  test("http (insecure) URL → remote", () => {
    expect(isRemoteTargetUrl("http://forge.internal/owner/repo")).toBe(true);
  });
  test("git:// URL → remote", () => {
    expect(isRemoteTargetUrl("git://host.example/owner/repo.git")).toBe(true);
  });
  test("ssh:// URL → remote", () => {
    expect(isRemoteTargetUrl("ssh://git@host.example/owner/repo.git")).toBe(true);
  });
  test("scp-style git@host:owner/repo → remote", () => {
    expect(isRemoteTargetUrl("git@github.com:owner/repo.git")).toBe(true);
  });
  test("plain relative path → local", () => {
    expect(isRemoteTargetUrl("./repo")).toBe(false);
  });
  test("absolute path → local", () => {
    expect(isRemoteTargetUrl("/tmp/repo")).toBe(false);
  });
  test("bare name → local", () => {
    expect(isRemoteTargetUrl("repo")).toBe(false);
  });
  test("empty string → false", () => {
    expect(isRemoteTargetUrl("")).toBe(false);
  });
  test("colon-less user@host → local (not a clonable URL)", () => {
    expect(isRemoteTargetUrl("user@host")).toBe(false);
  });
});

describe("normalizeRemote", () => {
  test("strips trailing .git", () => {
    expect(normalizeRemote("https://github.com/o/r.git")).toBe("https://github.com/o/r");
  });
  test("strips trailing slash", () => {
    expect(normalizeRemote("https://github.com/o/r/")).toBe("https://github.com/o/r");
  });
  test("strips trailing slash then .git", () => {
    expect(normalizeRemote("https://github.com/o/r.git/")).toBe("https://github.com/o/r");
  });
  test("no-op when already normal", () => {
    expect(normalizeRemote("https://github.com/o/r")).toBe("https://github.com/o/r");
  });
});

/** Init a bare "remote" repo we can clone from without network access. */
function makeBareRepo(): { url: string; cleanup: () => void } {
  const root = mkdtempSync(join(tmpdir(), "vigolium-audit-clone-test-fixture-"));
  const work = join(root, "work");
  const remote = join(root, "remote.git");
  mkdirSync(work);
  spawnSync("git", ["init", "-q", "-b", "main", work], { stdio: "ignore" });
  spawnSync("git", ["-C", work, "config", "user.email", "test@example.com"], { stdio: "ignore" });
  spawnSync("git", ["-C", work, "config", "user.name", "Test"], { stdio: "ignore" });
  writeFileSync(join(work, "README.md"), "hello\n");
  spawnSync("git", ["-C", work, "add", "."], { stdio: "ignore" });
  spawnSync("git", ["-C", work, "commit", "-q", "-m", "init"], { stdio: "ignore" });
  spawnSync("git", ["clone", "--bare", work, remote], { stdio: "ignore" });
  return {
    url: remote,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

describe("cloneRemoteTarget", () => {
  test("clones into ./<slug>/ under cwd, then reuses on a second call", () => {
    const fixture = makeBareRepo();
    const originalCwd = process.cwd();
    process.chdir(mkdtempSync(join(tmpdir(), "vigolium-audit-clone-target-cwd-")));
    // process.cwd() may differ from the mkdtempSync return value on macOS
    // (mkdtempSync returns /var/..., process.cwd() returns /private/var/...).
    // Use process.cwd() as the source of truth to avoid symlink false-negatives.
    const cwd = process.cwd();
    try {
      const first = cloneRemoteTarget(fixture.url);
      expect(first.reused).toBe(false);
      // The local-path bare repo has no owner/host so repoSlug falls back to
      // the basename ("remote.git" → "remote" after .git strip). What matters
      // is the directory is created under cwd and contains the README.
      expect(first.clonedTargetDir.startsWith(cwd)).toBe(true);
      expect(
        spawnSync("test", ["-f", join(first.clonedTargetDir, "README.md")]).status,
      ).toBe(0);

      const second = cloneRemoteTarget(fixture.url);
      expect(second.reused).toBe(true);
      expect(second.clonedTargetDir).toBe(first.clonedTargetDir);
    } finally {
      process.chdir(originalCwd);
      rmSync(cwd, { recursive: true, force: true });
      fixture.cleanup();
    }
  });

  test("refuses to clobber a non-empty non-git directory", () => {
    const fixture = makeBareRepo();
    const originalCwd = process.cwd();
    process.chdir(mkdtempSync(join(tmpdir(), "vigolium-audit-clone-target-clobber-")));
    const cwd = process.cwd();
    try {
      // Pre-create the slug directory with foreign content.
      const slug = "remote";
      mkdirSync(join(cwd, slug));
      writeFileSync(join(cwd, slug, "leftover"), "x");
      expect(() => cloneRemoteTarget(fixture.url)).toThrow(/non-empty but not a git checkout/);
    } finally {
      process.chdir(originalCwd);
      rmSync(cwd, { recursive: true, force: true });
      fixture.cleanup();
    }
  });
});
