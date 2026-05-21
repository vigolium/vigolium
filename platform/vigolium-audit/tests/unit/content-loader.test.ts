import { describe, expect, test } from "bun:test";
import { mkdirSync, writeFileSync, mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { makeContentLoader, resolveRoots } from "../../src/content-loader.js";

describe("FilesystemContentLoader (real vendored content)", () => {
  const roots = resolveRoots();
  const loader = makeContentLoader(roots);

  test("lists all 9 commands", async () => {
    const cmds = await loader.listCommands();
    expect(cmds).toContain("deep");
    expect(cmds).toContain("lite");
    expect(cmds).toContain("confirm");
    expect(cmds.length).toBeGreaterThanOrEqual(9);
  });

  test("loads a known agent-def", async () => {
    const agent = await loader.loadAgent("cve-scout");
    expect(agent.name).toBe("cve-scout");
    expect(agent.description.length).toBeGreaterThan(0);
    expect(agent.body.length).toBeGreaterThan(100);
  });

  test("loads deep command-def with 12 phases", async () => {
    const def = await loader.loadCommand("deep");
    expect(def.mode as string).toBe("deep");
    expect(def.phases.length).toBe(12);
  });

  test("resolves skill dir for an embedded skill", async () => {
    const skills = await loader.listSkills();
    expect(skills.length).toBeGreaterThan(0);
    const dir = await loader.resolveSkillDir(skills[0]!);
    expect(dir).toContain(skills[0]!);
  });

  test("loads claude harness frontmatter", async () => {
    const cfg = await loader.loadHarness("claude");
    expect(cfg).toBeTruthy();
  });

  test("missing agent throws", async () => {
    await expect(loader.loadAgent("does-not-exist")).rejects.toThrow(/not found/);
  });
});

describe("FilesystemContentLoader (override resolution)", () => {
  test("user override shadows embedded agent", async () => {
    const roots = resolveRoots();
    const tmpOverride = mkdtempSync(join(tmpdir(), "vigolium-audit-override-"));
    mkdirSync(join(tmpOverride, "agents"), { recursive: true });
    writeFileSync(
      join(tmpOverride, "agents", "cve-scout.md"),
      "---\ndescription: overridden\n---\n\nLOCAL OVERRIDE BODY",
    );
    const loader = makeContentLoader({
      contentRoot: roots.contentRoot,
      overrideRoot: tmpOverride,
    });
    const agent = await loader.loadAgent("cve-scout");
    expect(agent.description).toBe("overridden");
    expect(agent.body).toContain("LOCAL OVERRIDE BODY");
  });
});
