import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync } from "fs";
import { writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawnSync } from "child_process";
import { probeGit } from "../../src/engine/git.js";

function gitAvailable(): boolean {
  return spawnSync("git", ["--version"], { stdio: "ignore" }).status === 0;
}

describe("probeGit", () => {
  test("detects git from a nested directory", () => {
    if (!gitAvailable()) return;
    const root = mkdtempSync(join(tmpdir(), "vigolium-audit-git-"));
    expect(spawnSync("git", ["init"], { cwd: root, stdio: "ignore" }).status).toBe(0);
    writeFileSync(join(root, "README.md"), "fixture\n");
    expect(spawnSync("git", ["add", "README.md"], { cwd: root, stdio: "ignore" }).status).toBe(0);
    expect(
      spawnSync(
        "git",
        ["-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "init"],
        { cwd: root, stdio: "ignore" },
      ).status,
    ).toBe(0);
    const nested = join(root, "packages", "app");
    mkdirSync(nested, { recursive: true });

    const info = probeGit(nested);
    expect(info.available).toBe(true);
    expect(info.repository).toBeNull();
  });
});
