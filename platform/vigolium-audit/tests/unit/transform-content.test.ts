import { describe, expect, test } from "bun:test";
import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import { RULES, transform, validate } from "../../scripts/transform-content.js";

const CONTENT_DIR = join(import.meta.dir, "../../src/content");

function ruleByName(name: string) {
  const rule = RULES.find((r) => r.name === name);
  if (!rule) throw new Error(`no rule named ${name}`);
  return rule;
}

describe("transform rules", () => {
  describe("strip-vigolium-audit-prefix", () => {
    const rule = ruleByName("strip-vigolium-audit-prefix");
    const cases: Array<[string, string]> = [
      ["dispatch `vigolium-audit:advisory-hunter`", "dispatch `advisory-hunter`"],
      ["the vigolium-audit:flow-tracer agent", "the flow-tracer agent"],
      ["vigolium-audit:poc-runner and vigolium-audit:cve-scout", "poc-runner and cve-scout"],
    ];
    for (const [input, expected] of cases) {
      test(JSON.stringify(input), () => expect(rule.apply(input)).toBe(expected));
    }
    test("leaves bare 'vigolium-audit' untouched", () => {
      expect(rule.apply("the vigolium-audit tool")).toBe("the vigolium-audit tool");
    });
  });

  describe("strip-run-in-background", () => {
    const rule = ruleByName("strip-run-in-background");
    test("removes the 'with run_in_background: true' suffix", () => {
      expect(rule.apply("spawn the agent with `run_in_background: true`")).toBe("spawn the agent");
    });
    test("removes a standalone flag mention", () => {
      expect(rule.apply("pass `run_in_background: true` here")).toBe("pass  here");
    });
    test("tolerates extra spacing in the flag", () => {
      expect(rule.apply("`run_in_background:   true`")).toBe("");
    });
  });

  describe("neutralize-spawn-language", () => {
    const rule = ruleByName("neutralize-spawn-language");
    const cases: Array<[string, string]> = [
      ["spawn `flow-tracer`", "(orchestrator dispatches `flow-tracer`)"],
      ["Spawn `cve-scout`.", "(orchestrator dispatches `cve-scout`)."],
      ["spawn `poc-runner` now", "(orchestrator dispatches `poc-runner`) now"],
    ];
    for (const [input, expected] of cases) {
      test(JSON.stringify(input), () => expect(rule.apply(input)).toBe(expected));
    }
    test("handles spawn `name` at end of string (the dropped-boundary regression)", () => {
      expect(rule.apply("then spawn `taint-tracer`")).toBe("then (orchestrator dispatches `taint-tracer`)");
    });
  });

  describe("drop-parallel-message-cue", () => {
    const rule = ruleByName("drop-parallel-message-cue");
    test("drops bolded 'In a single message,'", () => {
      expect(rule.apply("In a **single message**, dispatch both")).toBe("dispatch both");
    });
    test("drops lowercase 'in a single message'", () => {
      expect(rule.apply("Do it in a single message, please")).toBe("Do it please");
    });
  });

  describe("drop-claude-code-tool-mentions", () => {
    const rule = ruleByName("drop-claude-code-tool-mentions");
    test("neutralizes AskUserQuestion", () => {
      expect(rule.apply("call AskUserQuestion")).toBe("call (prompt user — interactive only)");
    });
    test("neutralizes the plan-tool family", () => {
      expect(rule.apply("TaskCreate then TaskUpdate")).toBe("(plan-tool — n/a) then (plan-tool — n/a)");
    });
  });
});

describe("full transform pipeline", () => {
  test("applies all rules together", () => {
    const input = "In a **single message**, spawn `flow-tracer` with `run_in_background: true` via vigolium-audit:probe-lead";
    const out = transform(input);
    expect(out).toBe("(orchestrator dispatches `flow-tracer`) via probe-lead");
  });

  test("is idempotent on already-transformed output", () => {
    const input = "spawn `cve-scout` with `run_in_background: true`";
    const once = transform(input);
    expect(transform(once)).toBe(once);
  });
});

describe("validators", () => {
  test("flag claude-shaped markup that survives", () => {
    const issues = validate("dispatch `vigolium-audit:advisory-hunter` now");
    expect(issues.map((i) => i.rule)).toContain("no-vigolium-audit-prefix");
  });

  test("ignore tokens inside fenced code blocks", () => {
    const issues = validate("```\nvigolium-audit:advisory-hunter\n```\n");
    expect(issues).toHaveLength(0);
  });

  test("ignore tokens on the description: frontmatter line", () => {
    const issues = validate("description: spawn `flow-tracer` to trace flows\n");
    expect(issues).toHaveLength(0);
  });

  test("pass clean transformed text", () => {
    expect(validate(transform("spawn `flow-tracer` with `run_in_background: true`"))).toHaveLength(0);
  });
});

describe("real content never regresses after transform", () => {
  function mdFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) out.push(...mdFiles(full));
      else if (entry.name.endsWith(".md")) out.push(full);
    }
    return out;
  }

  for (const kind of ["agent-defs", "command-defs"]) {
    const dir = join(CONTENT_DIR, kind);
    for (const file of mdFiles(dir)) {
      test(`${kind}/${file.slice(dir.length + 1)} transforms cleanly`, () => {
        const issues = validate(transform(readFileSync(file, "utf8")));
        expect(issues).toHaveLength(0);
      });
    }
  }
});
