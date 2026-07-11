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

  test("SDK prose variants cannot override canonical phase contracts", async () => {
    const contentRoot = mkdtempSync(join(tmpdir(), "vigolium-audit-content-"));
    const overrideRoot = mkdtempSync(join(tmpdir(), "vigolium-audit-overrides-"));
    mkdirSync(join(contentRoot, "command-defs"), { recursive: true });
    mkdirSync(join(contentRoot, "sdk-variants", "command-defs"), { recursive: true });
    const canonical = `---
description: canonical
mode: lite
allowed-tools: Bash, Read
phases:
  - id: L1
    title: Recon
    agent: null
    completion:
      artifacts:
        - kind: file
          path: attack-surface/recon.md
---

CANONICAL BODY`;
    const staleSdk = `---
description: stale
mode: lite
allowed-tools: Bash
phases:
  - id: L1
    title: Old Recon
    agent: null
---

SDK-SAFE BODY`;
    writeFileSync(join(contentRoot, "command-defs", "lite.md"), canonical);
    writeFileSync(join(contentRoot, "sdk-variants", "command-defs", "lite.md"), staleSdk);

    const loader = makeContentLoader({ contentRoot, overrideRoot });
    const loaded = await loader.loadCommand("lite", { variant: "sdk" });
    expect(loaded.description).toBe("canonical");
    expect(loaded.phases[0]?.title).toBe("Recon");
    expect(loaded.phases[0]?.completion?.enforcement).toBe("required");
    expect(loaded.body).toContain("SDK-SAFE BODY");
    expect(loaded.allowed_tools_raw).toBe("Bash");
  });
});
