import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  tempDirs.length = 0;
});

describe("consolidate_drafts.py", () => {
  test("writes an empty manifest when a clean audit produced no drafts", () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-consolidate-"));
    tempDirs.push(target);
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(resultsDir, { recursive: true });

    const script = resolve(
      import.meta.dir,
      "../../src/content/skills/audit/scripts/consolidate_drafts.py",
    );
    const run = spawnSync("python3", [script, resultsDir], { encoding: "utf8" });
    expect(run.status, run.stderr).toBe(1);

    const manifest = JSON.parse(
      readFileSync(join(resultsDir, "findings-draft", "consolidation-manifest.json"), "utf8"),
    ) as { findings: unknown[]; theoretical: unknown[]; dropped: unknown[] };
    expect(manifest.findings).toEqual([]);
    expect(manifest.theoretical).toEqual([]);
    expect(manifest.dropped).toEqual([]);
  });
});
