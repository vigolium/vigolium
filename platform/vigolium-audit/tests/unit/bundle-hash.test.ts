import { describe, expect, test } from "bun:test";
import { resolve } from "path";
import { bundleContentHash } from "../../src/content-loader.js";
import { collectBundleFiles } from "../../scripts/bundle-content.js";

describe("bundleContentHash", () => {
  test("is stable across key insertion order", () => {
    const a = bundleContentHash({ "a.md": "x", "b.md": "y" });
    const b = bundleContentHash({ "b.md": "y", "a.md": "x" });
    expect(a).toBe(b);
  });

  test("changes when any file content changes", () => {
    const base = bundleContentHash({ "a.md": "x" });
    expect(bundleContentHash({ "a.md": "x2" })).not.toBe(base);
  });

  test("changes when a file is added or removed", () => {
    const base = bundleContentHash({ "a.md": "x" });
    expect(bundleContentHash({ "a.md": "x", "b.md": "y" })).not.toBe(base);
  });

  test("does not collide on content/key boundary shifts", () => {
    // Without the NUL separators, {"ab":"c"} and {"a":"bc"} could hash alike.
    expect(bundleContentHash({ ab: "c" })).not.toBe(bundleContentHash({ a: "bc" }));
  });

  test("produces a 16-char hex string", () => {
    expect(bundleContentHash({ "a.md": "x" })).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe("content bundle resource closure", () => {
  test("includes non-Markdown text resources required by skills", () => {
    const contentRoot = resolve(import.meta.dir, "../../src/content");
    const files = collectBundleFiles(contentRoot);
    expect(files["skills/variant-analysis/resources/codeql/javascript.ql"]).toContain("import javascript");
    expect(files["skills/security-threat-model/LICENSE.txt"]).toBeDefined();
    expect(files["skills/audit/assets/icon.svg"]).toContain("<svg");
  });
});
