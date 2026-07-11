import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { cleanupConfirmationResources } from "../../src/engine/confirmation-cleanup.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs.length = 0;
});

function fixture(): { resultsDir: string; workspace: string } {
  const root = mkdtempSync(join(tmpdir(), "vigolium-confirm-cleanup-"));
  tempDirs.push(root);
  const resultsDir = join(root, "vigolium-results");
  const workspace = join(resultsDir, "confirm-workspace");
  mkdirSync(workspace, { recursive: true });
  return { resultsDir, workspace };
}

describe("confirmation cleanup", () => {
  test("never evaluates an agent-authored cleanup command", async () => {
    const { resultsDir, workspace } = fixture();
    const sentinel = join(resultsDir, "must-not-exist");
    const session = "4d753f6d-49b7-47b2-a42d-d53dd5c13337";
    writeFileSync(join(workspace, ".lock"), JSON.stringify({ pid: 999999, session }));
    writeFileSync(
      join(workspace, "env-connection.json"),
      JSON.stringify({ session, cleanup_cmd: `touch ${sentinel}` }),
    );

    const result = await cleanupConfirmationResources(resultsDir);
    expect(result.session).toBe(session);
    expect(existsSync(sentinel)).toBe(false);
    expect(existsSync(join(workspace, ".lock"))).toBe(false);
  });

  test("rejects invalid session metadata and removes stale bookkeeping", async () => {
    const { resultsDir, workspace } = fixture();
    writeFileSync(join(workspace, ".lock"), JSON.stringify({ pid: process.pid, session: "$(unsafe)" }));
    writeFileSync(join(workspace, "app.pid"), String(process.pid));

    const result = await cleanupConfirmationResources(resultsDir);
    expect(result.session).toBeNull();
    expect(result.warnings.join(" ")).toContain("skipped container cleanup");
    expect(existsSync(join(workspace, ".lock"))).toBe(false);
    expect(existsSync(join(workspace, "app.pid"))).toBe(false);
  });
});
