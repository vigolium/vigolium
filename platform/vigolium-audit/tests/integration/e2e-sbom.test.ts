import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { Orchestrator } from "../../src/engine/orchestrator.js";
import { makeContentLoader, resolveRoots } from "../../src/content-loader.js";
import type { Adapter, AdapterEvent, AdapterRunInput } from "../../src/adapters/adapter.js";

/**
 * The 9 component categories the general-SBOM inventory enumerates. Must stay in
 * sync with cve-scout.md §4a and knowledge-base-template.md "## Component Inventory".
 */
const SBOM_CATEGORIES = new Set([
  "runtime",
  "package",
  "framework",
  "datastore",
  "external-service",
  "container-os",
  "build-ci",
  "binary",
  "vendored",
]);

/**
 * Validate that an object matches the sbom.json contract documented in
 * cve-scout.md §4c. Used both for the doc's own example and for the artifact a
 * balanced run writes, so the two can never silently diverge.
 */
function assertValidSbom(sbom: unknown): void {
  expect(sbom).toBeObject();
  const s = sbom as Record<string, unknown>;

  expect(typeof s.target).toBe("string");
  expect(typeof s.generated_at).toBe("string");
  expect(Array.isArray(s.components)).toBe(true);
  expect(Array.isArray(s.categories_covered)).toBe(true);
  expect(Array.isArray(s.coverage_gaps)).toBe(true);

  for (const cat of s.categories_covered as unknown[]) {
    expect(SBOM_CATEGORIES.has(cat as string)).toBe(true);
  }

  for (const raw of s.components as unknown[]) {
    expect(raw).toBeObject();
    const c = raw as Record<string, unknown>;
    expect(typeof c.name).toBe("string");
    expect((c.name as string).length).toBeGreaterThan(0);
    expect(SBOM_CATEGORIES.has(c.category as string)).toBe(true);
    // ecosystem is null for non-package categories, a string otherwise.
    expect(c.ecosystem === null || typeof c.ecosystem === "string").toBe(true);
    expect(typeof c.version).toBe("string");
    expect(c.relationship).toBe("direct");
    expect(typeof c.purpose).toBe("string");
    expect(Array.isArray(c.evidence)).toBe(true);
    expect((c.evidence as unknown[]).length).toBeGreaterThanOrEqual(1);
    for (const ev of c.evidence as unknown[]) expect(typeof ev).toBe("string");
    expect(typeof c.security_relevant).toBe("boolean");
  }
}

/** Pull the fenced ```json block that holds the sbom.json schema out of a doc. */
function extractSbomExample(markdown: string): unknown {
  const blocks = markdown.match(/```json\n([\s\S]*?)```/g) ?? [];
  for (const block of blocks) {
    const body = block.replace(/```json\n/, "").replace(/```$/, "");
    if (body.includes('"categories_covered"')) return JSON.parse(body);
  }
  throw new Error("no sbom.json example block found in document");
}

const CONTENT_DIR = join(import.meta.dir, "..", "..", "src", "content");

/**
 * Scripted adapter for a balanced run. Mirrors what cve-scout (phase B1) does:
 * writes the general component inventory to attack-surface/sbom.json plus the
 * KB Component Inventory section. Every other balanced phase is a no-op finish.
 */
class SbomFakeAdapter implements Adapter {
  readonly id = "scripted-fake-sbom";
  readonly platform = "claude" as const;
  readonly description = "SbomFakeAdapter (e2e tests)";
  private readonly attackSurfaceDir: string;
  calls: AdapterRunInput[] = [];

  constructor(targetDir: string) {
    this.attackSurfaceDir = join(targetDir, "vigolium-results", "attack-surface");
  }

  async probe(): Promise<void> {}

  async *run(input: AdapterRunInput): AsyncIterable<AdapterEvent> {
    this.calls.push(input);
    const label = input.label ?? "";
    yield { kind: "textDelta", text: `[fake] starting ${label}\n` };

    if (label === "balanced:B1") {
      mkdirSync(this.attackSurfaceDir, { recursive: true });
      const sbom = {
        target: "acme/widget",
        generated_at: "2026-06-04T00:00:00Z",
        components: [
          {
            name: "express",
            category: "framework",
            ecosystem: "npm",
            version: "4.18.2",
            relationship: "direct",
            purpose: "HTTP server framework",
            evidence: ["package.json", "src/app.ts:3 import"],
            security_relevant: true,
          },
          {
            name: "node",
            category: "runtime",
            ecosystem: null,
            version: "20.11.0",
            relationship: "direct",
            purpose: "JavaScript runtime",
            evidence: [".nvmrc", "Dockerfile:1 FROM node:20"],
            security_relevant: false,
          },
          {
            name: "ffmpeg",
            category: "binary",
            ecosystem: null,
            version: "unknown",
            relationship: "direct",
            purpose: "Invoked to transcode user uploads",
            evidence: ["src/media/transcode.ts:42 spawn('ffmpeg', ...)"],
            security_relevant: true,
          },
          {
            name: "postgres",
            category: "datastore",
            ecosystem: null,
            version: "16",
            relationship: "direct",
            purpose: "Primary relational store",
            evidence: ["docker-compose.yml services.db", "DATABASE_URL env"],
            security_relevant: false,
          },
        ],
        categories_covered: [
          "runtime",
          "package",
          "framework",
          "datastore",
          "external-service",
          "container-os",
          "build-ci",
          "binary",
          "vendored",
        ],
        coverage_gaps: ["no lockfile present — package versions inferred from manifest ranges"],
      };
      writeFileSync(join(this.attackSurfaceDir, "sbom.json"), JSON.stringify(sbom, null, 2));
      writeFileSync(
        join(this.attackSurfaceDir, "knowledge-base-report.md"),
        "## Advisory Intelligence\n\n(none)\n\n## Component Inventory\n\nTotal 4 — runtime: 1, framework: 1, datastore: 1, binary: 1\n",
      );
      yield {
        kind: "toolCall",
        id: "tu-sbom",
        tool: "Write",
        input: { path: "vigolium-results/attack-surface/sbom.json" },
      };
    } else if (label === "balanced:B2") {
      const kbPath = join(this.attackSurfaceDir, "knowledge-base-report.md");
      writeFileSync(
        kbPath,
        readFileSync(kbPath, "utf8") +
          "\n## Architecture Model\n\nSingle-service fixture with one HTTP boundary.\n" +
          "\n## Attack Surface\n\nFixture entry point inventory completed.\n",
      );
      writeFileSync(
        join(this.attackSurfaceDir, "unauthenticated-surface.md"),
        "# Unauthenticated Attack Surface\n\nNo anonymous fixture routes.\n",
      );
    } else if (label === "balanced:B3") {
      const kbPath = join(this.attackSurfaceDir, "knowledge-base-report.md");
      writeFileSync(
        kbPath,
        readFileSync(kbPath, "utf8") +
          "\n## Static Analysis Summary\n\nBuilt-in fixture analysis completed with no retained alerts.\n",
      );
    } else if (label === "balanced:B4") {
      const probeDir = join(this.attackSurfaceDir, "..", "probe-workspace", "balanced-probe");
      mkdirSync(probeDir, { recursive: true });
      writeFileSync(join(probeDir, "probe-summary.md"), "## Probe Summary\n\nNo validated fixture hypotheses.\n");
    } else if (label === "balanced:B5") {
      const chamberDir = join(this.attackSurfaceDir, "..", "chamber-workspace", "balanced-chamber");
      mkdirSync(chamberDir, { recursive: true });
      writeFileSync(join(chamberDir, "debate.md"), "## Chamber Debate\n\nClosed with no valid fixture findings.\n");
    } else if (label === "balanced:B7") {
      const draftDir = join(this.attackSurfaceDir, "..", "findings-draft");
      mkdirSync(draftDir, { recursive: true });
      writeFileSync(join(draftDir, "consolidation-manifest.json"), '{"findings":[],"theoretical":[],"dropped":[]}\n');
    } else if (label === "balanced:B9") {
      writeFileSync(
        join(this.attackSurfaceDir, "..", "final-audit-report.md"),
        "# Final Audit Report\n\n" + "Balanced fixture report content. ".repeat(10) + "\n",
      );
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

describe("e2e: SBOM component inventory (balanced mode)", () => {
  test("B1/cve-scout writes a schema-valid sbom.json to attack-surface/", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-sbom-"));
    writeFileSync(join(target, "package.json"), '{"name":"widget","dependencies":{"express":"^4"}}\n');

    const adapter = new SbomFakeAdapter(target);
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "balanced",
    });

    const result = await orch.run();
    expect(result.status).toBe("complete");
    expect(result.failedPhases).toEqual([]);

    // The cve-scout phase ran first under the balanced:B1 label.
    expect(adapter.calls[0]?.label).toBe("balanced:B1");

    // The artifact exists at the canonical retained path and validates.
    const sbomPath = join(target, "vigolium-results", "attack-surface", "sbom.json");
    expect(existsSync(sbomPath)).toBe(true);
    const sbom = JSON.parse(readFileSync(sbomPath, "utf8"));
    assertValidSbom(sbom);

    // Spot-check the "general, not just lockfile" categories are representable:
    // a shelled-out binary and a runtime made it into the inventory.
    const cats = new Set((sbom.components as { category: string }[]).map((c) => c.category));
    expect(cats.has("binary")).toBe(true);
    expect(cats.has("runtime")).toBe(true);

    // State records all balanced phases as complete.
    const state = JSON.parse(
      readFileSync(join(target, "vigolium-results", "audit-state.json"), "utf8"),
    );
    const audit = state.audits[0];
    expect(audit.mode).toBe("balanced");
    for (const id of ["B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9"]) {
      expect(audit.phases[id].status).toBe("complete");
    }
  });

  test("--strip-raw retains sbom.json (it lives under the durable attack-surface/ dir)", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-sbom-strip-"));
    const adapter = new SbomFakeAdapter(target);
    const orch = new Orchestrator({
      adapter,
      loader: makeContentLoader(resolveRoots()),
      targetDir: target,
      mode: "balanced",
      stripRaw: true,
    });

    const result = await orch.run();
    expect(result.status).toBe("complete");

    const sbomPath = join(target, "vigolium-results", "attack-surface", "sbom.json");
    expect(existsSync(sbomPath)).toBe(true);
    assertValidSbom(JSON.parse(readFileSync(sbomPath, "utf8")));
  });

  test("the documented sbom.json example in cve-scout.md is itself schema-valid", () => {
    const cveScout = readFileSync(join(CONTENT_DIR, "agent-defs", "cve-scout.md"), "utf8");

    // The agent must document the canonical artifact path and the inventory categories.
    expect(cveScout).toContain("vigolium-results/attack-surface/sbom.json");

    // The embedded example must parse and conform to the same contract the engine
    // preserves — guards the doc against drifting into invalid JSON or a missing field.
    assertValidSbom(extractSbomExample(cveScout));

    // The KB template carries the matching human-readable section.
    const kbTemplate = readFileSync(
      join(CONTENT_DIR, "skills", "audit", "references", "knowledge-base-template.md"),
      "utf8",
    );
    expect(kbTemplate).toContain("## Component Inventory");
  });
});
