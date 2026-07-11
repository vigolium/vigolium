import { lstat, mkdir, rename } from "fs/promises";
import { join } from "path";
import type { AuditMode } from "./types.js";

const CORE_MODES = new Set<AuditMode>(["lite", "balanced", "deep"]);

/**
 * Phase-owned outputs that must not leak into a fresh core audit. State,
 * file-state, operator INFO, confirmation/revisit metadata, and unrelated
 * mode reports intentionally remain at the results root.
 */
const CORE_ARTIFACT_ENTRIES = [
  "attack-surface",
  "bypass-analysis",
  "findings",
  "findings-theoretical",
  "findings-draft",
  "probe-workspace",
  "chamber-workspace",
  "adversarial-reviews",
  "codeql-artifacts",
  "codeql-queries",
  "semgrep-res",
  "semgrep-rules",
  "real-env-evidence",
  "tmp",
  "attack-pattern-registry.json",
  "final-audit-report.md",
  "audit-report.md",
] as const;

export function isCoreAuditMode(mode: AuditMode): boolean {
  return CORE_MODES.has(mode);
}

/**
 * Move prior phase-owned artifacts out of the live paths before a fresh run.
 * Renames stay within vigolium-results, so the operation is fast and remains
 * reversible on a failed/aborted audit. Explicit strip/auto-prune may remove
 * the archive after a successful delivery.
 */
export async function archivePriorCoreArtifacts(
  resultsDir: string,
  auditId: string,
): Promise<string[]> {
  const destination = join(
    resultsDir,
    ".archive",
    "pre-run",
    auditId.replace(/[^A-Za-z0-9._-]/g, "_"),
  );
  const moved: string[] = [];

  for (const entry of CORE_ARTIFACT_ENTRIES) {
    const source = join(resultsDir, entry);
    try {
      await lstat(source);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw err;
    }
    await mkdir(destination, { recursive: true });
    await rename(source, join(destination, entry));
    moved.push(entry);
  }
  return moved;
}
