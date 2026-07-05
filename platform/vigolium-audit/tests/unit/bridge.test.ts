import { describe, expect, test } from "bun:test";
import { existsSync } from "fs";
import { join } from "path";
import {
  extractJsonBlock,
  resolveBridgeInvocation,
  GENERIC_ACTION,
} from "../../src/engine/bridge.js";
import { listBridgeTasks, loadBridgeTask } from "../../src/engine/bridge-tasks.js";
import { ALWAYS_ON_SKILL, buildBridgePlugin } from "../../src/engine/bridge-plugin.js";

describe("bridge task presets", () => {
  test("lists the built-in presets", () => {
    const tasks = listBridgeTasks();
    for (const t of ["triage", "exploit", "plan"]) expect(tasks).toContain(t);
  });

  test("loads triage with json output + schema + fp-check skill", async () => {
    const task = await loadBridgeTask("triage");
    expect(task.name).toBe("triage");
    expect(task.output).toBe("json");
    expect(task.outputSchema).toBeDefined();
    expect(task.skills).toContain("fp-check");
    expect(task.systemPrompt.length).toBeGreaterThan(0);
  });

  test("each preset references skills that exist in the content tree", async () => {
    for (const name of ["triage", "exploit", "plan"]) {
      const task = await loadBridgeTask(name);
      for (const skill of task.skills) {
        expect(existsSync(join(import.meta.dir, "../../src/content/skills", skill, "SKILL.md"))).toBe(true);
      }
    }
  });

  test("throws with available names on unknown task", async () => {
    await expect(loadBridgeTask("nope")).rejects.toThrow(/unknown bridge task/);
  });
});

describe("resolveBridgeInvocation", () => {
  const base = { platform: "claude" as const, cwd: "/tmp/target" };

  test("merges preset defaults with extra skills and always denies AskUserQuestion", async () => {
    const inv = await resolveBridgeInvocation({
      ...base,
      action: "triage",
      input: JSON.stringify({ id: "H1" }),
      skills: ["audit"],
    });
    expect(inv.output).toBe("json");
    expect(inv.skills).toContain("audit");
    expect(inv.skills).toContain("fp-check");
    expect(inv.disallowedTools).toContain("AskUserQuestion");
    expect(inv.bypassPermissions).toBe(true);
    expect(inv.systemPrompt).toContain("Required output schema");
    expect(inv.userPrompt).toContain("# Task input");
  });

  test("request model overrides preset model; output override wins", async () => {
    const inv = await resolveBridgeInvocation({
      ...base,
      action: "triage",
      prompt: "look at H1",
      model: "opus",
      output: "text",
    });
    expect(inv.model).toBe("opus");
    expect(inv.output).toBe("text");
  });

  test("generic run honors system-prompt override and json instruction", async () => {
    const inv = await resolveBridgeInvocation({
      ...base,
      action: GENERIC_ACTION,
      prompt: "summarize auth",
      systemPrompt: "Be terse.",
      output: "json",
    });
    expect(inv.systemPrompt).toContain("Be terse.");
    expect(inv.systemPrompt.trim()).toMatch(/nothing after it\.$/);
    // generic run adds no preset skills
    expect(inv.skills).toEqual([]);
  });

  test("throws when neither prompt nor input is provided", async () => {
    await expect(
      resolveBridgeInvocation({ ...base, action: "triage" }),
    ).rejects.toThrow(/no prompt or input/);
  });

  test("preamble only claims the scanner skill is loaded on a platform that loads it", async () => {
    const claude = await resolveBridgeInvocation({ ...base, action: "triage", input: "{}" });
    const codex = await resolveBridgeInvocation({ platform: "codex", cwd: base.cwd, action: "triage", input: "{}" });
    expect(claude.systemPrompt).toContain("skill is loaded");
    expect(codex.systemPrompt).not.toContain("skill is loaded");
    expect(codex.systemPrompt).toContain("Prefer vigolium's first-class CLI");
  });

  test("dedupes and sorts the skill set", async () => {
    const inv = await resolveBridgeInvocation({
      ...base,
      action: GENERIC_ACTION,
      prompt: "x",
      skills: ["audit", "audit", "codeql"],
    });
    expect(inv.skills).toEqual(["audit", "codeql"]);
  });
});

describe("extractJsonBlock", () => {
  test("pulls the last json fence", () => {
    const text = "```json\n{\"a\":1}\n```\nmore\n```json\n{\"b\":2}\n```";
    expect(extractJsonBlock(text)).toEqual({ value: { b: 2 } });
  });

  test("falls back to a generic fence that parses", () => {
    const text = "here:\n```\n{\"ok\":true}\n```";
    expect(extractJsonBlock(text)).toEqual({ value: { ok: true } });
  });

  test("falls back to the whole trimmed message", () => {
    expect(extractJsonBlock('  {"x":[1,2]}  ')).toEqual({ value: { x: [1, 2] } });
  });

  test("reports an error when there is no JSON", () => {
    const res = extractJsonBlock("no json here at all");
    expect("error" in res).toBe(true);
  });
});

describe("buildBridgePlugin", () => {
  test("always includes vigolium-scanner and copies requested skills", async () => {
    const plugin = await buildBridgePlugin(["audit"]);
    expect(plugin.loadedSkills).toContain(ALWAYS_ON_SKILL);
    expect(plugin.loadedSkills).toContain("audit");
    expect(plugin.missing).toEqual([]);
    expect(existsSync(join(plugin.dir, ".claude-plugin", "plugin.json"))).toBe(true);
    expect(existsSync(join(plugin.dir, "skills", ALWAYS_ON_SKILL, "SKILL.md"))).toBe(true);
    expect(existsSync(join(plugin.dir, "skills", "audit", "SKILL.md"))).toBe(true);
  });

  test("reports unresolved skills without throwing, and is deterministic", async () => {
    const a = await buildBridgePlugin(["does-not-exist-xyz"]);
    expect(a.missing).toContain("does-not-exist-xyz");
    expect(a.loadedSkills).toContain(ALWAYS_ON_SKILL);
    const b = await buildBridgePlugin(["does-not-exist-xyz"]);
    expect(b.dir).toBe(a.dir); // same skill set → same cached dir
  });
});
