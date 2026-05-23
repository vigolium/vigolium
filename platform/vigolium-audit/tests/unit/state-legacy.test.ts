import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { StateStore } from "../../src/engine/state.js";

describe("StateStore legacy audit-state compatibility", () => {
  test("defaults missing branch/completed_at from Codex handoff-written state", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-state-legacy-"));
    const results = join(target, "vigolium-results");
    await Bun.$`mkdir -p ${results}`;
    writeFileSync(
      join(results, "audit-state.json"),
      JSON.stringify({
        audits: [
          {
            audit_id: "2026-05-22T05:37:02Z",
            mode: "full",
            repository: "google/site-kit-wp",
            model: "codex",
            agent_sdk: "codex",
            commit: "abc123",
            started_at: "2026-05-22T05:37:02Z",
            status: "in_progress",
            phases: { P1: { status: "complete" } },
          },
        ],
      }),
    );

    const state = await new StateStore(results).load();
    expect(state.schema_version).toBe(1);
    expect(state.audits[0]?.branch).toBeNull();
    expect(state.audits[0]?.completed_at).toBeNull();
    expect(state.audits[0]?.mode).toBe("deep");
  });

  test("preserves one-shot/mode-specific metadata entries without phases", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-state-legacy-"));
    const results = join(target, "vigolium-results");
    await Bun.$`mkdir -p ${results}`;
    writeFileSync(
      join(results, "audit-state.json"),
      JSON.stringify({
        schema_version: 1,
        merge_metadata: { sources: ["run-a", "run-b"] },
        audits: [
          {
            audit_id: "2026-05-22T06:00:00Z",
            parent_audit_id: "parent-1",
            mode: "reinvest",
            repository: "google/site-kit-wp",
            model: "codex",
            agent_sdk: "codex",
            commit: "abc123",
            started_at: "2026-05-22T06:00:00Z",
            completed_at: null,
            status: "in_progress",
            wave_scope: ["C1", "H1"],
          },
        ],
      }),
    );

    const store = new StateStore(results);
    const state = await store.load();
    expect(state.audits[0]?.phases).toEqual({});
    expect((state as unknown as { merge_metadata?: unknown }).merge_metadata).toEqual({ sources: ["run-a", "run-b"] });
    expect((state.audits[0] as unknown as { parent_audit_id?: string }).parent_audit_id).toBe("parent-1");
    expect((state.audits[0] as unknown as { wave_scope?: string[] }).wave_scope).toEqual(["C1", "H1"]);

    await store.updateAudit("2026-05-22T06:00:00Z", { status: "aborted" });
    const reloaded = await store.load();
    expect((reloaded as unknown as { merge_metadata?: unknown }).merge_metadata).toEqual({ sources: ["run-a", "run-b"] });
    expect((reloaded.audits[0] as unknown as { wave_scope?: string[] }).wave_scope).toEqual(["C1", "H1"]);
  });

  test("rejects a state file written by a newer schema version with an actionable message", async () => {
    const target = mkdtempSync(join(tmpdir(), "vigolium-audit-state-future-"));
    const results = join(target, "vigolium-results");
    await Bun.$`mkdir -p ${results}`;
    writeFileSync(
      join(results, "audit-state.json"),
      JSON.stringify({ schema_version: 2, audits: [] }),
    );
    await expect(new StateStore(results).load()).rejects.toThrow(/newer than this build/);
  });
});
