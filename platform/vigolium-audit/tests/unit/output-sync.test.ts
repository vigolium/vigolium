import { describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join, sep } from "path";
import { OutputSyncer, assertOutputNotNested, mirrorDir } from "../../src/engine/output-sync.js";

function seedSrc(): { src: string; dest: string } {
  const root = mkdtempSync(join(tmpdir(), "vigolium-audit-outsync-"));
  const src = join(root, "vigolium-results");
  const dest = join(root, "out");
  mkdirSync(src, { recursive: true });
  return { src, dest };
}

describe("mirrorDir", () => {
  test("no-op when src does not exist", async () => {
    const root = mkdtempSync(join(tmpdir(), "vigolium-audit-outsync-"));
    const src = join(root, "missing");
    const dest = join(root, "out");
    await mirrorDir(src, dest);
    expect(existsSync(dest)).toBe(false);
  });

  test("copies files and nested dirs from src to dest", async () => {
    const { src, dest } = seedSrc();
    writeFileSync(join(src, "audit-state.json"), '{"v":1}');
    mkdirSync(join(src, "findings"), { recursive: true });
    writeFileSync(join(src, "findings", "L2-001.md"), "# finding\n");

    await mirrorDir(src, dest);

    expect(readFileSync(join(dest, "audit-state.json"), "utf8")).toBe('{"v":1}');
    expect(readFileSync(join(dest, "findings", "L2-001.md"), "utf8")).toBe("# finding\n");
  });

  test("removes files in dest that no longer exist in src (true mirror)", async () => {
    const { src, dest } = seedSrc();
    writeFileSync(join(src, "a.txt"), "a");
    writeFileSync(join(src, "b.txt"), "b");
    await mirrorDir(src, dest);
    expect(existsSync(join(dest, "a.txt"))).toBe(true);
    expect(existsSync(join(dest, "b.txt"))).toBe(true);

    // Drop b.txt from src; mirror again.
    writeFileSync(join(src, "a.txt"), "a-updated");
    // Simulate deletion by re-creating src minus b.txt — easiest: just remove the file.
    const fs = await import("fs/promises");
    await fs.unlink(join(src, "b.txt"));

    await mirrorDir(src, dest);

    expect(readFileSync(join(dest, "a.txt"), "utf8")).toBe("a-updated");
    expect(existsSync(join(dest, "b.txt"))).toBe(false);
  });

  test("removes whole subtree in dest when its src counterpart disappears", async () => {
    const { src, dest } = seedSrc();
    mkdirSync(join(src, "findings-draft"), { recursive: true });
    writeFileSync(join(src, "findings-draft", "x.md"), "x");
    await mirrorDir(src, dest);
    expect(existsSync(join(dest, "findings-draft", "x.md"))).toBe(true);

    const fs = await import("fs/promises");
    await fs.rm(join(src, "findings-draft"), { recursive: true, force: true });
    await mirrorDir(src, dest);
    expect(existsSync(join(dest, "findings-draft"))).toBe(false);
  });
});

describe("assertOutputNotNested", () => {
  test("rejects exact match", () => {
    expect(() => assertOutputNotNested("/tmp/x/vigolium-results", "/tmp/x/vigolium-results")).toThrow(/cannot equal/);
  });

  test("rejects descendant", () => {
    expect(() => assertOutputNotNested(`/tmp/x/vigolium-results${sep}out`, "/tmp/x/vigolium-results")).toThrow(/inside the vigolium-results/);
  });

  test("allows sibling", () => {
    expect(() => assertOutputNotNested("/tmp/x/out", "/tmp/x/vigolium-results")).not.toThrow();
  });

  test("allows path with vigolium-results as substring but different segment", () => {
    expect(() => assertOutputNotNested("/tmp/vigolium-results-archive", "/tmp/vigolium-results")).not.toThrow();
  });
});

describe("OutputSyncer", () => {
  test("serializes concurrent sync calls", async () => {
    const { src, dest } = seedSrc();
    writeFileSync(join(src, "f.txt"), "v1");
    const syncer = new OutputSyncer(src, dest);

    // Fire three concurrent syncs — they should chain rather than racing.
    const p1 = syncer.sync();
    const p2 = syncer.sync();
    const p3 = syncer.sync();
    await Promise.all([p1, p2, p3]);

    expect(readFileSync(join(dest, "f.txt"), "utf8")).toBe("v1");
    expect(syncer.getLastError()).toBeNull();
  });

  test("captures errors via onError callback without throwing", async () => {
    // Point at a src path that exists but is a file, not a dir.
    const root = mkdtempSync(join(tmpdir(), "vigolium-audit-outsync-"));
    const badSrc = join(root, "notadir");
    writeFileSync(badSrc, "hi");
    const dest = join(root, "out");
    let captured: Error | null = null;
    const syncer = new OutputSyncer(badSrc, dest, (e) => {
      captured = e;
    });
    await syncer.sync();
    expect(captured).not.toBeNull();
    expect(syncer.getLastError()).not.toBeNull();
  });
});
