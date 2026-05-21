import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  REFRESH_FRESH_EXCLUDED_PHASES,
  TRIGGERED_VIA_REFRESH,
  detectRefreshRoute,
  findInProgressRefreshAudit,
} from "../../src/cli/refresh-detect.js";

function makeTarget(): string {
  return mkdtempSync(join(tmpdir(), "vigolium-audit-refresh-detect-"));
}

function writeState(target: string, state: object): void {
  const resultsDir = join(target, "vigolium-results");
  mkdirSync(resultsDir, { recursive: true });
  writeFileSync(join(resultsDir, "audit-state.json"), JSON.stringify(state));
}

function writeKb(target: string, body = "# KB\nstuff\n"): void {
  const dir = join(target, "vigolium-results", "attack-surface");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "knowledge-base-report.md"), body);
}

function writeFindingDir(target: string, name: string): void {
  const dir = join(target, "vigolium-results", "findings", name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "draft.md"), "## stub\n- Severity: High\n");
}

const COMPLETE_AUDIT = {
  audit_id: "2026-05-10T00:00:00.000Z",
  commit: null,
  branch: null,
  repository: null,
  mode: "deep",
  model: null,
  agent_sdk: "claude-code",
  started_at: "2026-05-10T00:00:00.000Z",
  completed_at: "2026-05-10T01:00:00.000Z",
  status: "complete",
  phases: {},
};

describe("detectRefreshRoute", () => {
  test("no vigolium-results/ dir → fresh-deep", async () => {
    const target = makeTarget();
    const r = await detectRefreshRoute(target);
    expect(r.route).toBe("fresh-deep");
    if (r.route === "fresh-deep") {
      expect(r.excludePhases).toEqual([...REFRESH_FRESH_EXCLUDED_PHASES]);
      expect(r.reason).toContain("no completed prior audit");
    }
  });

  test("state present but no findings + no KB → fresh-deep", async () => {
    const target = makeTarget();
    writeState(target, { schema_version: 1, audits: [COMPLETE_AUDIT] });
    const r = await detectRefreshRoute(target);
    expect(r.route).toBe("fresh-deep");
    if (r.route === "fresh-deep") {
      expect(r.reason).toContain("no prior findings");
      expect(r.reason).toContain("no knowledge-base-report.md");
    }
  });

  test("only in_progress audit → fresh-deep", async () => {
    const target = makeTarget();
    writeState(target, {
      schema_version: 1,
      audits: [{ ...COMPLETE_AUDIT, status: "in_progress", completed_at: null }],
    });
    writeFindingDir(target, "C1-something");
    writeKb(target);
    const r = await detectRefreshRoute(target);
    expect(r.route).toBe("fresh-deep");
  });

  test("complete audit + findings + KB → revisit", async () => {
    const target = makeTarget();
    writeState(target, { schema_version: 1, audits: [COMPLETE_AUDIT] });
    writeFindingDir(target, "C1-something");
    writeFindingDir(target, "H2-other");
    writeKb(target);
    const r = await detectRefreshRoute(target);
    expect(r.route).toBe("revisit");
    if (r.route === "revisit") {
      expect(r.reason).toContain("2 findings");
      expect(r.reason).toContain("KB");
    }
  });

  test("complete audit + KB but empty findings/ → fresh-deep", async () => {
    const target = makeTarget();
    writeState(target, { schema_version: 1, audits: [COMPLETE_AUDIT] });
    mkdirSync(join(target, "vigolium-results", "findings"), { recursive: true });
    writeKb(target);
    const r = await detectRefreshRoute(target);
    expect(r.route).toBe("fresh-deep");
    if (r.route === "fresh-deep") {
      expect(r.reason).toContain("no prior findings");
    }
  });

  test("malformed audit-state.json → fresh-deep, no throw", async () => {
    const target = makeTarget();
    const resultsDir = join(target, "vigolium-results");
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(join(resultsDir, "audit-state.json"), "{not json");
    const r = await detectRefreshRoute(target);
    expect(r.route).toBe("fresh-deep");
  });
});

describe("findInProgressRefreshAudit", () => {
  test("no state → null", async () => {
    const target = makeTarget();
    expect(await findInProgressRefreshAudit(target)).toBeNull();
  });

  test("in_progress without triggered_via → null", async () => {
    const target = makeTarget();
    writeState(target, {
      schema_version: 1,
      audits: [{ ...COMPLETE_AUDIT, status: "in_progress", completed_at: null }],
    });
    expect(await findInProgressRefreshAudit(target)).toBeNull();
  });

  test("in_progress with triggered_via=refresh → returns it", async () => {
    const target = makeTarget();
    writeState(target, {
      schema_version: 1,
      audits: [
        {
          ...COMPLETE_AUDIT,
          audit_id: "audit-A",
          status: "in_progress",
          completed_at: null,
          mode: "revisit",
          triggered_via: TRIGGERED_VIA_REFRESH,
        },
      ],
    });
    const r = await findInProgressRefreshAudit(target);
    expect(r).toEqual({ mode: "revisit", auditId: "audit-A" });
  });

  test("prefers latest in-progress refresh", async () => {
    const target = makeTarget();
    writeState(target, {
      schema_version: 1,
      audits: [
        {
          ...COMPLETE_AUDIT,
          audit_id: "audit-old",
          status: "in_progress",
          completed_at: null,
          mode: "deep",
          triggered_via: TRIGGERED_VIA_REFRESH,
        },
        { ...COMPLETE_AUDIT, audit_id: "audit-mid", status: "complete" },
        {
          ...COMPLETE_AUDIT,
          audit_id: "audit-new",
          status: "in_progress",
          completed_at: null,
          mode: "revisit",
          triggered_via: TRIGGERED_VIA_REFRESH,
        },
      ],
    });
    const r = await findInProgressRefreshAudit(target);
    expect(r?.auditId).toBe("audit-new");
    expect(r?.mode).toBe("revisit");
  });

  test("completed refresh audit ignored (not in_progress)", async () => {
    const target = makeTarget();
    writeState(target, {
      schema_version: 1,
      audits: [{ ...COMPLETE_AUDIT, triggered_via: "refresh" }],
    });
    expect(await findInProgressRefreshAudit(target)).toBeNull();
  });
});
