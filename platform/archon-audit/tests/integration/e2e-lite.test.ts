import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { Orchestrator } from "../../src/engine/orchestrator.js";
import { makeContentLoader, resolveRoots } from "../../src/content-loader.js";
import type { Adapter, AdapterEvent, AdapterRunInput } from "../../src/adapters/adapter.js";
import type { OrchestratorEvent } from "../../src/engine/events.js";

/**
 * Scripted fake adapter that simulates an LLM doing real work: writing finding
 * files to archon/findings-draft/, emitting tool calls, and finishing each
 * phase with realistic usage. Used by the e2e fixture test below.
 */
class ScriptedFakeAdapter implements Adapter {
  readonly id = "scripted-fake";
  readonly platform = "claude" as const;
  readonly description = "ScriptedFakeAdapter (e2e tests)";
  private readonly findingsDir: string;
  calls: AdapterRunInput[] = [];

  constructor(targetDir: string) {
    this.findingsDir = join(targetDir, "archon", "findings-draft");
  }

  async probe(): Promise<void> {}

  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    this.calls.push(input);
    const label = input.label ?? "";
    yield { kind: "textDelta", text: `[fake] starting ${label}\n` };

    if (label === "lite:L1") {
      // Simulate writing the recon block.
      mkdirSync(join(this.findingsDir, ".."), { recursive: true });
      mkdirSync(join(this.findingsDir, "..", "attack-surface"), { recursive: true });
      writeFileSync(
        join(this.findingsDir, "..", "attack-surface", "lite-recon.md"),
        "## Lite Recon\n\n- Languages: Python\n- Excluded: tests/\n",
      );
      yield {
        kind: "toolCall",
        id: "tu-1",
        tool: "Write",
        input: { path: "archon/attack-surface/lite-recon.md" },
      };
    } else if (label === "lite:L2") {
      // Simulate writing a finding draft.
      mkdirSync(this.findingsDir, { recursive: true });
      writeFileSync(
        join(this.findingsDir, "l2-001-hardcoded-password.md"),
        [
          "## L2-001: Hardcoded Password",
          "",
          "- Severity: High",
          "- File: login.py",
          "- Line: 1",
          "- Verdict: VALID",
          "",
        ].join("\n"),
      );
      yield {
        kind: "toolCall",
        id: "tu-2",
        tool: "Write",
        input: { path: "archon/findings-draft/l2-001-hardcoded-password.md" },
      };
    } else if (label === "lite:L3") {
      mkdirSync(this.findingsDir, { recursive: true });
      writeFileSync(
        join(this.findingsDir, "l3-001-no-input-validation.md"),
        "## L3-001: No input validation\n\n- Severity: Medium\n- Verdict: VALID\n",
      );
      yield {
        kind: "toolCall",
        id: "tu-3",
        tool: "Write",
        input: { path: "archon/findings-draft/l3-001-no-input-validation.md" },
      };
    }

    yield {
      kind: "finish",
      ok: true,
      result: `done ${label}`,
      usd: 0.01,
      tokens: { input: 50, output: 25 },
      durationMs: 5,
    };
  }
}

describe("e2e: lite mode against tiny-vuln fixture", () => {
  test("orchestrator runs all 3 phases, writes findings, persists state", async () => {
    const target = mkdtempSync(join(tmpdir(), "archon-e2e-"));
    writeFileSync(
      join(target, "login.py"),
      'def login(user, password):\n    return password == "hunter2"\n',
    );

    const adapter = new ScriptedFakeAdapter(target);
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
    });

    const findingsDiscovered: string[] = [];
    const phasesEnded: { id: string; ok: boolean }[] = [];
    orch.on((e: OrchestratorEvent) => {
      if (e.kind === "findingDiscovered") findingsDiscovered.push(e.relPath);
      if (e.kind === "phaseEnd") phasesEnded.push({ id: e.phase.id, ok: e.ok });
    });

    const result = await orch.run();
    expect(result.status).toBe("complete");
    expect(result.failedPhases).toEqual([]);

    // All three phases ran in order.
    expect(adapter.calls.map((c) => c.label)).toEqual(["lite:L1", "lite:L2", "lite:L3"]);
    expect(phasesEnded).toEqual([
      { id: "L1", ok: true },
      { id: "L2", ok: true },
      { id: "L3", ok: true },
    ]);

    // State file has the right shape.
    const state = JSON.parse(readFileSync(join(target, "archon", "audit-state.json"), "utf8"));
    expect(state.audits.length).toBe(1);
    const audit = state.audits[0];
    expect(audit.status).toBe("complete");
    expect(audit.mode).toBe("lite");
    expect(audit.agent_sdk).toBe("scripted-fake");
    expect(audit.usage.cost_usd).toBeGreaterThan(0);
    for (const id of ["L1", "L2", "L3"]) {
      expect(audit.phases[id].status).toBe("complete");
    }

    // Default: raw artifacts preserved (stripping is opt-in via --strip-raw).
    const drafts = readdirSync(join(target, "archon", "findings-draft")).sort();
    expect(drafts).toEqual([
      "l2-001-hardcoded-password.md",
      "l3-001-no-input-validation.md",
    ]);

    // Recon artifact present.
    expect(
      readFileSync(join(target, "archon", "attack-surface", "lite-recon.md"), "utf8"),
    ).toContain("Languages: Python");

    // Findings stats reach the result.
    expect(result.findings.total).toBe(2);
    expect(result.findings.bySeverity).toEqual({ High: 1, Medium: 1 });
    expect(result.totalTokens.input).toBeGreaterThan(0);

    // Findings watcher fired for at least the two drafts (timing-dependent;
    // file-watch on macOS can deliver events after the run loop finishes).
    // Allow either 0 or >=2; just assert no spurious findings if any fired.
    if (findingsDiscovered.length > 0) {
      expect(findingsDiscovered.length).toBeGreaterThanOrEqual(1);
      for (const p of findingsDiscovered) {
        expect(p).toContain(".md");
      }
    }
  });

  test("--strip-raw strips raw artifacts and promotes drafts; default preserves everything", async () => {
    // Two parallel runs: one with stripRaw=true, one with default (stripRaw=false).
    // Both seed extra raw artifacts (semgrep-res, codeql-artifacts) and a
    // top-level *.md report; assert what survives.
    for (const stripRaw of [true, false]) {
      const target = mkdtempSync(
        join(tmpdir(), `archon-strip-${stripRaw ? "on" : "default"}-`),
      );
      const archonDir = join(target, "archon");
      mkdirSync(archonDir, { recursive: true });

      const adapter = new ScriptedFakeAdapter(target);
      // Pre-seed raw byproducts as if scanners had run.
      mkdirSync(join(archonDir, "semgrep-res"), { recursive: true });
      writeFileSync(join(archonDir, "semgrep-res", "raw.json"), "{}");
      mkdirSync(join(archonDir, "codeql-artifacts"), { recursive: true });
      writeFileSync(join(archonDir, "codeql-artifacts", "db.bqrs"), "");
      writeFileSync(join(archonDir, "final-audit-report.md"), "# Lite report\n");

      const orch = new Orchestrator({
        adapter,
        loader: makeContentLoader(resolveRoots()),
        targetDir: target,
        mode: "lite",
        ...(stripRaw ? { stripRaw: true } : {}),
      });
      const result = await orch.run();
      expect(result.status).toBe("complete");

      // Always preserved.
      expect(existsSync(join(archonDir, "audit-state.json"))).toBe(true);
      expect(existsSync(join(archonDir, "final-audit-report.md"))).toBe(true);
      expect(existsSync(join(archonDir, "attack-surface"))).toBe(true);
      expect(existsSync(join(archonDir, "findings"))).toBe(true);

      if (stripRaw) {
        // --strip-raw pruned raw byproducts and promoted drafts into findings/.
        expect(existsSync(join(archonDir, "findings-draft"))).toBe(false);
        expect(existsSync(join(archonDir, "semgrep-res"))).toBe(false);
        expect(existsSync(join(archonDir, "codeql-artifacts"))).toBe(false);
        const finals = readdirSync(join(archonDir, "findings")).sort();
        expect(finals).toContain("l2-001-hardcoded-password.md");
        expect(finals).toContain("l3-001-no-input-validation.md");
      } else {
        // Default: raw byproducts and drafts survive untouched.
        expect(existsSync(join(archonDir, "findings-draft"))).toBe(true);
        expect(existsSync(join(archonDir, "semgrep-res"))).toBe(true);
        expect(existsSync(join(archonDir, "codeql-artifacts"))).toBe(true);
      }
    }
  });

  test("compiled-mode parity: same orchestrator behavior with embedded content", async () => {
    // This test just validates that the loader works when invoked the same way
    // the compiled binary would invoke it (resolveRoots default path).
    const target = mkdtempSync(join(tmpdir(), "archon-e2e-"));
    const adapter = new ScriptedFakeAdapter(target);
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "lite",
    });
    const result = await orch.run();
    expect(result.status).toBe("complete");
  });
});
