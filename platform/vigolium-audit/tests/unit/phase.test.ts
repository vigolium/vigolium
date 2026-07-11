import { describe, expect, test } from "bun:test";
import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import { parseCommandDef, topologicalOrder } from "../../src/engine/phase.js";

const COMMAND_DEFS_DIR = join(import.meta.dir, "../../src/content/command-defs");

const expectedPhaseCount: Record<string, number> = {
  lite: 3,
  balanced: 9,
  deep: 12,
  diff: 1,
  confirm: 7,
  merge: 7,
  revisit: 10,
  reinvest: 3,
  longshot: 3,
  status: 0,
};

describe("parseCommandDef", () => {
  for (const file of readdirSync(COMMAND_DEFS_DIR)) {
    if (!file.endsWith(".md")) continue;
    const mode = file.replace(/\.md$/, "");
    test(`parses ${file} with expected phase count`, () => {
      const src = readFileSync(join(COMMAND_DEFS_DIR, file), "utf8");
      const def = parseCommandDef(src, file);
      expect(def.mode as string).toBe(mode);
      expect(def.description).toBeTruthy();
      expect(def.phases.length).toBe(expectedPhaseCount[mode]!);
    });
  }

  test("rejects missing frontmatter", () => {
    expect(() => parseCommandDef("no frontmatter here", "x.md")).toThrow(/missing YAML frontmatter/);
  });

  test("rejects unknown depends_on reference", () => {
    const bad = `---
description: bad
mode: lite
phases:
  - id: "1"
    title: A
    agent: null
    depends_on: ["does-not-exist"]
---

body`;
    expect(() => parseCommandDef(bad, "bad.md")).toThrow(/unknown phase/);
  });

  test("rejects dependency cycle", () => {
    const bad = `---
description: bad
mode: lite
phases:
  - id: "1"
    title: A
    agent: null
    depends_on: ["2"]
  - id: "2"
    title: B
    agent: null
    depends_on: ["1"]
---

body`;
    expect(() => parseCommandDef(bad, "bad.md")).toThrow(/cycle/);
  });

  test("parses deterministic completion contracts with defaults", () => {
    const src = `---
description: gate
mode: lite
phases:
  - id: L1
    title: Recon
    agent: null
    completion:
      artifacts:
        - kind: file
          path: attack-surface/recon.md
          contains: ["## Recon"]
---

body`;
    const def = parseCommandDef(src, "gate.md");
    expect(def.phases[0]?.completion?.repair_attempts).toBe(1);
    expect(def.phases[0]?.completion?.enforcement).toBe("required");
    expect(def.phases[0]?.completion?.artifacts[0]).toEqual({
      kind: "file",
      path: "attack-surface/recon.md",
      min_bytes: 1,
      contains: ["## Recon"],
      json: false,
    });
  });

  test("revisit consolidation waits for both variant branches", () => {
    const src = readFileSync(join(COMMAND_DEFS_DIR, "revisit.md"), "utf8");
    const def = parseCommandDef(src, "revisit.md");
    expect(def.phases.find((phase) => phase.id === "7")?.depends_on.sort()).toEqual(["5", "6"]);
  });

  test("lite finalization waits for the secrets scan", () => {
    const src = readFileSync(join(COMMAND_DEFS_DIR, "lite.md"), "utf8");
    const def = parseCommandDef(src, "lite.md");
    expect(def.phases.find((phase) => phase.id === "L3")?.depends_on.sort()).toEqual(["L1", "L2"]);
    expect(def.phases.find((phase) => phase.id === "L2")?.parallel_with).toEqual([]);
  });

  test("rejects artifact paths outside the results directory", () => {
    const src = `---
description: bad gate
mode: lite
phases:
  - id: L1
    title: Recon
    agent: null
    completion:
      artifacts:
        - kind: file
          path: ../outside.md
---

body`;
    expect(() => parseCommandDef(src, "bad-gate.md")).toThrow(/inside the results directory/);
  });
});

describe("topologicalOrder", () => {
  test("orders deep phases respecting depends_on", () => {
    const src = readFileSync(join(COMMAND_DEFS_DIR, "deep.md"), "utf8");
    const def = parseCommandDef(src, "deep.md");
    const ordered = topologicalOrder(def.phases);
    const seen = new Set<string>();
    for (const p of ordered) {
      for (const dep of p.depends_on) {
        expect(seen.has(dep)).toBe(true);
      }
      seen.add(p.id);
    }
    expect(ordered.length).toBe(def.phases.length);
  });
});

describe("longshot mode", () => {
  test("phase graph is enumerate -> hunt -> aggregate with declared agents", () => {
    const src = readFileSync(join(COMMAND_DEFS_DIR, "longshot.md"), "utf8");
    const def = parseCommandDef(src, "longshot.md");
    expect(def.mode).toBe("longshot");
    const ordered = topologicalOrder(def.phases);
    expect(ordered.map((p) => p.id)).toEqual(["1", "2", "3"]);
    expect(ordered[0]!.agent).toBeNull();
    expect(ordered[1]!.agent).toBe("longshot-prober");
    expect(ordered[2]!.agent).toBe("longshot-collector");
  });
});
