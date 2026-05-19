import { readdir, stat } from "fs/promises";
import { join } from "path";
import { StateStore } from "../engine/state.js";
import type { AuditMode } from "../engine/types.js";

export type RefreshRoute =
  | { route: "revisit"; reason: string }
  | { route: "fresh-deep"; reason: string; excludePhases: string[] };

/**
 * Marker stored on `AuditRecord.triggered_via` when the user invoked
 * `--mode refresh`. Lets future `refresh` runs identify their own prior
 * audits regardless of which underlying mode (revisit / deep) was chosen.
 */
export const TRIGGERED_VIA_REFRESH = "refresh";

/**
 * Phases skipped when `--mode refresh` falls back to a fresh deep audit:
 *   D1 — Intelligence Pass (CVE) (CVE intelligence; anchors on known issues)
 *   D2 — Intelligence Pass (History) (requires git; commit archaeology / history mining)
 *   D3 — Patch Audit (requires git; CVE-bypass focus)
 *
 * Skipping all three keeps the fresh-perspective spirit: the audit reasons
 * about the code without anchoring on prior CVEs or git archaeology. Phases
 * D2 and D3 are also `requires_git: true` and would be dropped anyway on a
 * no-git target — listing them explicitly here makes the policy obvious in
 * the audit-state.json skip records.
 */
export const REFRESH_FRESH_EXCLUDED_PHASES: readonly string[] = ["D1", "D2", "D3"];

/**
 * Decide what `--mode refresh` should resolve to for `targetDir`.
 *
 * Routes to `revisit` only when the prior audit is a useful seed for an
 * anti-anchored second pass: a completed audit, a non-empty findings/ dir
 * (the negative list), and a non-empty KB (revisit refuses to run without).
 * Anything else falls back to a fresh deep audit with the exclude set.
 */
export async function detectRefreshRoute(targetDir: string): Promise<RefreshRoute> {
  const archonDir = join(targetDir, "archon");
  const findingsDir = join(archonDir, "findings");
  const theoreticalDir = join(archonDir, "findings-theoretical");
  const kbPath = join(archonDir, "attack-surface", "knowledge-base-report.md");

  const [stateLoaded, confirmedCount, theoreticalCount, kbBytes] = await Promise.all([
    new StateStore(archonDir).load().catch(() => null),
    countFindingDirs(findingsDir),
    countFindingDirs(theoreticalDir),
    fileSizeOrZero(kbPath),
  ]);
  // Either bucket is a useful revisit seed — a prior audit that produced only
  // theoretical findings is still worth an anti-anchored second pass.
  const findingsCount = confirmedCount + theoreticalCount;
  const hasComplete = stateLoaded?.audits.some((a) => a.status === "complete") ?? false;

  if (hasComplete && findingsCount > 0 && kbBytes > 0) {
    return {
      route: "revisit",
      reason: `prior audit detected: ${findingsCount} findings, KB ${kbBytes}b`,
    };
  }
  const reasons: string[] = [];
  if (!hasComplete) reasons.push("no completed prior audit");
  if (findingsCount === 0) reasons.push("no prior findings to seed against");
  if (kbBytes === 0) reasons.push("no knowledge-base-report.md");
  return {
    route: "fresh-deep",
    reason: reasons.join("; "),
    excludePhases: [...REFRESH_FRESH_EXCLUDED_PHASES],
  };
}

/**
 * If a prior `--mode refresh` invocation was interrupted, prefer to resume
 * its in-progress audit (whichever underlying mode it resolved to) rather
 * than re-detecting from scratch. Re-detection would pick a different lane
 * if the partial run had already produced findings.
 */
export async function findInProgressRefreshAudit(
  targetDir: string,
): Promise<{ mode: AuditMode; auditId: string } | null> {
  const archonDir = join(targetDir, "archon");
  try {
    const state = await new StateStore(archonDir).load();
    for (let i = state.audits.length - 1; i >= 0; i--) {
      const a = state.audits[i]!;
      if (a.status === "in_progress" && a.triggered_via === TRIGGERED_VIA_REFRESH) {
        return { mode: a.mode, auditId: a.audit_id };
      }
    }
  } catch {
    return null;
  }
  return null;
}

async function countFindingDirs(dir: string): Promise<number> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return 0;
  }
  const candidates = entries.filter((name) => !name.startsWith("."));
  const stats = await Promise.all(
    candidates.map(async (name) => {
      try {
        return { name, s: await stat(join(dir, name)) };
      } catch {
        return null;
      }
    }),
  );
  let count = 0;
  for (const e of stats) {
    if (e === null) continue;
    if (e.s.isDirectory() || e.name.toLowerCase().endsWith(".md")) count++;
  }
  return count;
}

async function fileSizeOrZero(path: string): Promise<number> {
  try {
    const s = await stat(path);
    return s.isFile() ? s.size : 0;
  } catch {
    return 0;
  }
}
