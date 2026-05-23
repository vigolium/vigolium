import { mkdir, readdir, rename, rm, stat } from "fs/promises";
import { join } from "path";

/**
 * Strip raw audit byproducts so the user is left with just the artifacts they
 * care about. Always preserved at the top level of `vigolium-results/`:
 *   - durable state files (`audit-state.json`, `file-state.json`, revisit state)
 *   - `findings/` (finalized confirmed findings)
 *   - `findings-theoretical/` (finalized theoretical / unconfirmed findings)
 *   - `attack-surface/` (recon outputs)
 *   - `confirm-workspace/` when requested (confirmation evidence + staging)
 *   - `quarantine/` (merge/manual-review output)
 *   - `*.md` (mode reports: final-audit-report.md, confirmation-report.md, …)
 *
 * Legacy lite runs can opt into promoting leftover markdown drafts into
 * `findings/` before deleting `findings-draft/`. Deep/balanced/confirm output
 * must not promote drafts: raw drafts are intermediate workspace state, while
 * finalized findings live in bucket directories with `draft.md` + `report.md`.
 */
export interface StripRawArtifactsOptions {
  /** Promote leftover top-level markdown drafts into findings/ before pruning. */
  promoteDrafts?: boolean;
  /** Preserve confirm-workspace/ evidence and verdict staging. */
  keepConfirmWorkspace?: boolean;
}

export async function stripRawArtifacts(
  resultsDir: string,
  options: StripRawArtifactsOptions = {},
): Promise<void> {
  const promoteDrafts = options.promoteDrafts ?? true;
  const keepConfirmWorkspace = options.keepConfirmWorkspace ?? true;
  const findingsDraft = join(resultsDir, "findings-draft");
  const findingsFinal = join(resultsDir, "findings");

  // Promote any leftover drafts only for modes where drafts are the final-ish
  // output shape (historically lite). Deep/balanced/chamber drafts should be
  // discarded after their canonical finding directories have been written.
  if (promoteDrafts) {
    try {
      const drafts = await readdir(findingsDraft);
      if (drafts.length > 0) {
        await mkdir(findingsFinal, { recursive: true });
        for (const name of drafts) {
          if (!name.toLowerCase().endsWith(".md")) continue;
          const src = join(findingsDraft, name);
          const dst = join(findingsFinal, name);
          try {
            await stat(dst);
            // Final already exists — leave it; don't clobber.
          } catch {
            await rename(src, dst).catch(() => {});
          }
        }
      }
    } catch {
      // findings-draft may not exist; nothing to promote.
    }
  }

  let entries: string[];
  try {
    entries = await readdir(resultsDir);
  } catch {
    return;
  }

  for (const name of entries) {
    if (shouldKeep(name, { keepConfirmWorkspace })) continue;
    await rm(join(resultsDir, name), { recursive: true, force: true }).catch(() => {});
  }
}

const DURABLE_STATE_FILES = new Set([
  "audit-state.json",
  "file-state.json",
  "revisit-audit-state.json",
]);

const DURABLE_DIRS = new Set([
  "attack-surface",
  "findings",
  "findings-theoretical",
  "quarantine",
]);

function shouldKeep(
  name: string,
  options: { keepConfirmWorkspace: boolean },
): boolean {
  if (DURABLE_STATE_FILES.has(name)) return true;
  if (DURABLE_DIRS.has(name)) return true;
  if (options.keepConfirmWorkspace && name === "confirm-workspace") return true;
  if (name.toLowerCase().endsWith(".md")) return true;
  return false;
}
