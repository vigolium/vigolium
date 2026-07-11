import { describe, expect, test } from "bun:test";
import { existsSync } from "fs";
import { join } from "path";
import type { Adapter, AdapterEvent, AdapterRunInput } from "../../src/adapters/adapter.js";
import {
  describeInvocation,
  extractJsonBlock,
  plannedSkills,
  resolveBridgeInvocation,
  resolvePermission,
  runBridge,
  GENERIC_ACTION,
} from "../../src/engine/bridge.js";
import type { BridgeInvocation } from "../../src/engine/bridge.js";
import { listBridgeTasks, loadBridgeTask } from "../../src/engine/bridge-tasks.js";
import { ALWAYS_ON_SKILL, buildBridgePlugin } from "../../src/engine/bridge-plugin.js";
import type { ResolvedAdapterChoice } from "../../src/adapters/detect.js";

/** An adapter that replays a scripted event sequence per run() call. The Nth
 *  run() replays scripts[N] (last script repeats), so retries can be simulated. */
class ScriptedAdapter implements Adapter {
  readonly id = "scripted";
  readonly platform = "codex" as const; // codex ⇒ no plugin fs work, hermetic
  readonly description = "scripted test adapter";
  runs = 0;
  constructor(private readonly scripts: AdapterEvent[][]) {}
  async probe(): Promise<void> {}
  async *run(_input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    const script = this.scripts[this.runs] ?? this.scripts[this.scripts.length - 1] ?? [];
    this.runs += 1;
    for (const ev of script) yield ev;
  }
}

const finish = (over: Partial<Extract<AdapterEvent, { kind: "finish"; ok: true }>> = {}): AdapterEvent => ({
  kind: "finish",
  ok: true,
  result: "",
  usd: 0,
  tokens: { input: 0, output: 0 },
  durationMs: 0,
  ...over,
});

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

describe("honest skill inventory", () => {
  test("plannedSkills includes the always-on scanner on claude, nothing on codex", () => {
    expect(plannedSkills("claude", ["audit"])).toEqual([ALWAYS_ON_SKILL, "audit"].sort());
    expect(plannedSkills("codex", ["audit"])).toEqual([]);
  });

  const choice = { authSource: "subscription" } as unknown as ResolvedAdapterChoice;

  test("describeInvocation announces the loaded set (with scanner) + requested set", async () => {
    const inv = await resolveBridgeInvocation({
      platform: "claude",
      cwd: "/tmp/target",
      action: GENERIC_ACTION,
      prompt: "x",
      skills: ["audit"],
    });
    const desc = describeInvocation(inv, choice);
    expect(desc.skills).toContain(ALWAYS_ON_SKILL); // matches the real session
    expect(desc.skills).toContain("audit");
    expect(desc.requestedSkills).toEqual(["audit"]); // what the caller asked for
  });

  test("describeInvocation reports no loaded skills on codex (no plugin mechanism)", async () => {
    const inv = await resolveBridgeInvocation({
      platform: "codex",
      cwd: "/tmp/target",
      action: GENERIC_ACTION,
      prompt: "x",
      skills: ["audit"],
    });
    const desc = describeInvocation(inv, choice);
    expect(desc.skills).toEqual([]);
    expect(desc.requestedSkills).toEqual(["audit"]);
  });
});

describe("permission profiles", () => {
  test("resolvePermission maps each profile to sandbox / network / denies", () => {
    expect(resolvePermission("read-only", undefined)).toEqual({
      bypassPermissions: true,
      sandbox: "read-only",
      network: false,
      denyTools: ["Write", "Edit", "MultiEdit", "NotebookEdit"],
    });
    expect(resolvePermission("read-only", true).network).toBe(true); // opt-in override
    expect(resolvePermission("workspace-write", undefined)).toMatchObject({ sandbox: "workspace-write", network: true, denyTools: [] });
    expect(resolvePermission("full-access", undefined)).toMatchObject({ sandbox: "danger-full-access", network: true });
  });

  test("plan is read-only + no network and denies write tools", async () => {
    const inv = await resolveBridgeInvocation({ platform: "claude", cwd: "/t", action: "plan", input: "{}" });
    expect(inv.permission).toBe("read-only");
    expect(inv.sandbox).toBe("read-only");
    expect(inv.network).toBe(false);
    expect(inv.disallowedTools).toContain("Write");
    expect(inv.bypassPermissions).toBe(true); // headless: bypass, but write-denied
  });

  test("triage is read-only but network-enabled (replay)", async () => {
    const inv = await resolveBridgeInvocation({ platform: "claude", cwd: "/t", action: "triage", input: "{}" });
    expect(inv.permission).toBe("read-only");
    expect(inv.network).toBe(true);
  });

  test("exploit is workspace-write + network and does not deny write tools", async () => {
    const inv = await resolveBridgeInvocation({ platform: "claude", cwd: "/t", action: "exploit", input: "{}" });
    expect(inv.permission).toBe("workspace-write");
    expect(inv.sandbox).toBe("workspace-write");
    expect(inv.network).toBe(true);
    expect(inv.disallowedTools).not.toContain("Write");
  });

  test("raw run defaults to full-access; request can narrow it", async () => {
    const full = await resolveBridgeInvocation({ platform: "codex", cwd: "/t", action: GENERIC_ACTION, prompt: "x" });
    expect(full.permission).toBe("full-access");
    expect(full.sandbox).toBe("danger-full-access");

    const narrowed = await resolveBridgeInvocation({
      platform: "codex",
      cwd: "/t",
      action: GENERIC_ACTION,
      prompt: "x",
      permission: "read-only",
    });
    expect(narrowed.permission).toBe("read-only");
    expect(narrowed.sandbox).toBe("read-only");
  });
});

/** Resolve a codex invocation (no plugin build) for driving a ScriptedAdapter. */
async function codexInvocation(over: { output?: "json" | "text" } = {}): Promise<BridgeInvocation> {
  return resolveBridgeInvocation({
    platform: "codex",
    cwd: "/tmp/target",
    action: GENERIC_ACTION,
    prompt: "do the thing",
    ...(over.output ? { output: over.output } : {}),
  });
}

describe("runBridge result semantics", () => {
  test("transport ok + valid json ⇒ transportOk, contractOk, parsed output", async () => {
    const inv = await codexInvocation({ output: "json" });
    const adapter = new ScriptedAdapter([
      [
        { kind: "session", sessionId: "s1" },
        { kind: "textDelta", text: "```json\n{\"verdict\":\"exploitable\"}\n```" },
        finish({ result: "```json\n{\"verdict\":\"exploitable\"}\n```", usd: 0.01, tokens: { input: 5, output: 5 } }),
      ],
    ]);
    const res = await runBridge(inv, adapter);
    expect(res.transportOk).toBe(true);
    expect(res.ok).toBe(true);
    expect(res.contractOk).toBe(true);
    expect(res.output).toEqual({ verdict: "exploitable" });
    expect(res.attempts).toBe(1);
    expect(res.sessionId).toBe("s1");
  });

  test("transport ok + malformed json ⇒ contractOk false, output null, parse error", async () => {
    const inv = await codexInvocation({ output: "json" });
    const adapter = new ScriptedAdapter([[finish({ result: "sorry, no JSON for you" })]]);
    const res = await runBridge(inv, adapter);
    expect(res.transportOk).toBe(true);
    expect(res.ok).toBe(true); // ran fine — but the contract was not met
    expect(res.contractOk).toBe(false);
    expect(res.output).toBeNull();
    expect(res.outputParseError).toBeDefined();
  });

  test("text output leaves contractOk null (not requested)", async () => {
    const inv = await codexInvocation({ output: "text" });
    const adapter = new ScriptedAdapter([[finish({ result: "plain answer" })]]);
    const res = await runBridge(inv, adapter);
    expect(res.contractOk).toBeNull();
    expect(res.outputRaw).toBe("plain answer");
  });

  test("transport failure ⇒ transportOk false with the reason", async () => {
    const inv = await codexInvocation({ output: "text" });
    const adapter = new ScriptedAdapter([
      [{ kind: "finish", ok: false, reason: "hard failure", usd: 0, tokens: { input: 0, output: 0 }, durationMs: 0 }],
    ]);
    const res = await runBridge(inv, adapter);
    expect(res.transportOk).toBe(false);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("hard failure");
    expect(res.attempts).toBe(1);
  });

  test("retries a cold transient failure and accumulates usage across attempts", async () => {
    const inv = await codexInvocation({ output: "text" });
    const transient: AdapterEvent = {
      kind: "error",
      cause: Object.assign(new Error("503 Service Unavailable"), { status: 503 }),
      transient: true,
    };
    const adapter = new ScriptedAdapter([
      // attempt 1: transient error BEFORE any progress, then a failed finish
      [transient, { kind: "finish", ok: false, reason: "aborted", usd: 0.01, tokens: { input: 5, output: 5 }, durationMs: 40 }],
      // attempt 2: succeeds
      [
        { kind: "session", sessionId: "s2" },
        { kind: "textDelta", text: "done" },
        finish({ result: "done", usd: 0.02, tokens: { input: 10, output: 10 }, durationMs: 60 }),
      ],
    ]);
    const res = await runBridge(inv, adapter, {}, { retry: { transientBackoffMs: 1 } });
    expect(res.attempts).toBe(2);
    expect(res.ok).toBe(true);
    expect(res.usd).toBeCloseTo(0.03, 5); // cumulative across both attempts
    expect(res.tokens).toEqual({ input: 15, output: 15 });
    expect(res.error).toBeUndefined(); // cleared on the successful retry
    expect(res.outputRaw).toBe("done");
  });

  test("does not retry once progress has streamed (no side-effect replay)", async () => {
    const inv = await codexInvocation({ output: "text" });
    const adapter = new ScriptedAdapter([
      [
        { kind: "textDelta", text: "partial work" }, // progress first…
        { kind: "error", cause: Object.assign(new Error("503"), { status: 503 }), transient: true },
        { kind: "finish", ok: false, reason: "died mid-stream", usd: 0.01, tokens: { input: 1, output: 1 }, durationMs: 5 },
      ],
      [finish({ result: "should-not-run" })],
    ]);
    const res = await runBridge(inv, adapter, {}, { retry: { transientBackoffMs: 1 } });
    expect(res.attempts).toBe(1); // skipped: a replay could re-run side effects
    expect(adapter.runs).toBe(1);
    expect(res.ok).toBe(false);
  });
});
