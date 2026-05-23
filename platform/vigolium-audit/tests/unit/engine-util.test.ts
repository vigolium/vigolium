import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { atomicWrite, sweepStaleTempFiles } from "../../src/engine/util.js";

describe("atomicWrite", () => {
  test("writes contents and leaves no staging file behind", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-atomic-"));
    const target = join(dir, "x.json");
    await atomicWrite(target, "hello");
    expect(readFileSync(target, "utf8")).toBe("hello");
    // The staging file must have been renamed away, not left next to the target.
    expect(readdirSync(dir)).toEqual(["x.json"]);
  });

  test("creates parent directories that don't exist yet", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-atomic-"));
    const target = join(dir, "nested", "deep", "x.json");
    await atomicWrite(target, "y");
    expect(readFileSync(target, "utf8")).toBe("y");
  });
});

describe("sweepStaleTempFiles", () => {
  test("removes orphaned staging files but preserves real files", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigolium-audit-sweep-"));
    writeFileSync(join(dir, "audit-state.json"), "{}");
    // Simulate two crashes mid-write that left staging files behind.
    writeFileSync(join(dir, "audit-state.json.tmp-vigolium.123.aaaa"), "partial");
    writeFileSync(join(dir, "file-state.json.tmp-vigolium.456.bbbb"), "partial");

    await sweepStaleTempFiles(dir);

    expect(readdirSync(dir)).toEqual(["audit-state.json"]);
  });

  test("is a non-throwing no-op on a missing directory", async () => {
    const missing = join(tmpdir(), "vigolium-audit-sweep-missing-zzz-does-not-exist");
    expect(existsSync(missing)).toBe(false);
    await sweepStaleTempFiles(missing); // must not throw
  });
});
