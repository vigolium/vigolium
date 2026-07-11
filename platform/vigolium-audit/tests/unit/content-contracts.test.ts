import { describe, expect, test } from "bun:test";
import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import { parse as parseYaml } from "yaml";
import { parseCommandDef } from "../../src/engine/phase.js";

const CONTENT = join(import.meta.dir, "../../src/content");
const COMMANDS = join(CONTENT, "command-defs");
const AGENTS = join(CONTENT, "agent-defs");

function command(mode: string) {
  return parseCommandDef(readFileSync(join(COMMANDS, `${mode}.md`), "utf8"), `${mode}.md`);
}

describe("content execution contracts", () => {
  test("every core audit phase declares an executable completion contract", () => {
    for (const mode of ["lite", "balanced", "deep"]) {
      for (const phase of command(mode).phases) {
        expect(phase.completion, `${mode}:${phase.id}`).toBeDefined();
        expect(phase.completion!.artifacts.length, `${mode}:${phase.id}`).toBeGreaterThan(0);
      }
    }
    expect(command("balanced").phases.find((phase) => phase.id === "B6")?.completion?.enforcement).toBe(
      "advisory",
    );
    expect(command("deep").phases.find((phase) => phase.id === "D9")?.completion?.enforcement).toBe(
      "advisory",
    );
  });

  test("every phase agent exists and Codex dispatch modes do not exclude a required role", () => {
    const agents = new Set(
      readdirSync(AGENTS)
        .filter((name) => name.endsWith(".md"))
        .map((name) => name.replace(/\.md$/, "")),
    );
    const harness = parseYaml(
      readFileSync(join(CONTENT, "harnesses", "codex", "frontmatter.yaml"), "utf8"),
    ) as { exclude?: string[] };
    const excluded = new Set(harness.exclude ?? []);

    for (const file of readdirSync(COMMANDS).filter((name) => name.endsWith(".md"))) {
      const def = command(file.replace(/\.md$/, ""));
      for (const phase of def.phases) {
        if (!phase.agent) continue;
        expect(agents.has(phase.agent), `${def.mode}:${phase.id}:${phase.agent}`).toBe(true);
        if (["lite", "balanced", "deep", "revisit", "confirm"].includes(def.mode)) {
          expect(excluded.has(phase.agent), `Codex excludes ${def.mode}:${phase.agent}`).toBe(false);
        }
      }
    }
  });

  test("core commands preserve gate inputs for engine validation", () => {
    for (const mode of ["lite", "balanced", "deep"]) {
      const source = readFileSync(join(COMMANDS, `${mode}.md`), "utf8");
      expect(source).toContain("Engine-Owned Audit State");
      expect(source).not.toMatch(/delete\s+`?vigolium-results\/audit-state\.json/);
      expect(source).not.toContain("rm -rf vigolium-results/findings-draft/");
      expect(source).toMatch(/clean no-findings/i);
    }
    expect(readFileSync(join(COMMANDS, "revisit.md"), "utf8")).toMatch(/clean no-new-findings/i);
  });

  test("audit skill stays concise and contains no legacy destructive state workflow", () => {
    const source = readFileSync(join(CONTENT, "skills", "audit", "SKILL.md"), "utf8");
    expect(source.split(/\r?\n/).length).toBeLessThanOrEqual(200);
    expect(source).not.toMatch(/rm\s+-f\s+vigolium-results\/audit-state\.json/);
    expect(source).not.toContain("10-Phase Workflow");
    expect(source).toContain("Artifact sufficiency");

    const validator = readFileSync(
      join(CONTENT, "skills", "audit", "hooks", "scripts", "validate_phase_output.py"),
      "utf8",
    );
    expect(validator).not.toContain("Phase 15");
    expect(validator).not.toContain("P11-LITE");
    expect(validator).toContain('("findings", "findings-theoretical")');
  });

  test("Codex dispatch preserves canonical deep probing and deterministic finalization", () => {
    const source = readFileSync(
      join(CONTENT, "harnesses", "codex", "agents-dispatch.md"),
      "utf8",
    );
    expect(source).toContain("## Trusted CLI State Authority (CRITICAL)");
    expect(source).toContain("### D6: Deep Probe");
    for (const agent of [
      "vigolium-audit:probe-lead",
      "vigolium-audit:goal-backtracer",
      "vigolium-audit:assumption-breaker",
      "vigolium-audit:evidence-collector",
    ]) {
      expect(source).toContain(agent);
    }
    expect(source.match(/consolidate_drafts\.py/g)?.length ?? 0).toBeGreaterThanOrEqual(4);
    expect(source.match(/partition_findings\.py/g)?.length ?? 0).toBeGreaterThanOrEqual(3);
    expect(source).toContain("both `vigolium-results/findings/` and `vigolium-results/findings-theoretical/`");
    expect(source).toContain("### 0: Intent Cartography");
    expect(source).toContain("vigolium-audit:intent-mapper");
    expect(source).toContain("### V1.5: Intent Cross-Check");
    expect(source).not.toContain("Collect `Verdict: VALID` drafts, assign severity IDs");
    expect(source).not.toContain("rm -rf vigolium-results/findings-draft/");

    const harness = parseYaml(
      readFileSync(join(CONTENT, "harnesses", "codex", "frontmatter.yaml"), "utf8"),
    ) as { exclude?: string[] };
    const excluded = new Set(harness.exclude ?? []);
    const referenced = new Set(
      [...source.matchAll(/vigolium-audit:([a-z][a-z0-9-]+)/g)]
        .map((match) => match[1]!)
        .filter((name) => name !== "deep"),
    );
    for (const agent of referenced) {
      expect(readFileSync(join(AGENTS, `${agent}.md`), "utf8").length).toBeGreaterThan(0);
      expect(excluded.has(agent), `Codex excludes dispatch role ${agent}`).toBe(false);
    }
  });
});
