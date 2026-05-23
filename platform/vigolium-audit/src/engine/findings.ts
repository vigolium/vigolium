import { existsSync, readdirSync, statSync, watch as fsWatch } from "fs";
import { mkdir, readFile, readdir, stat } from "fs/promises";
import { join, relative } from "path";
import type { OrchestratorBus } from "./events.js";

/**
 * Watch `vigolium-results/findings-draft/` and `vigolium-results/findings/` for new `.md` files
 * and emit `findingDiscovered` events on the bus. Used by both the per-phase
 * orchestrator and the slash-command / dispatch handoff drivers.
 *
 * Uses `fs.watch(dir, { recursive: true })`. macOS supports this natively;
 * Linux requires Node ≥ 20.0.0 (the recursive flag was finalized then and is
 * implemented via inotify). On older Node or unusual filesystems the watch may
 * silently stop reporting nested events — drafts written to subdirs won't show
 * up as `+ finding:` lines, but quarantine and final reporting are unaffected
 * because they read the directory directly.
 */
export function startFindingsWatcher(args: {
  resultsDir: string;
  auditId: string;
  targetDir: string;
  bus: OrchestratorBus;
}): () => void {
  const { resultsDir, auditId, targetDir, bus } = args;
  const findingsDraft = join(resultsDir, "findings-draft");
  const findingsFinal = join(resultsDir, "findings");
  const findingsTheoretical = join(resultsDir, "findings-theoretical");
  const seen = new Set<string>();
  const watchers: Array<{ close: () => void }> = [];
  for (const dir of [findingsDraft, findingsFinal, findingsTheoretical]) {
    mkdir(dir, { recursive: true }).catch(() => {});
    try {
      const w = fsWatch(dir, { recursive: true }, (_eventType, filename) => {
        if (!filename) return;
        if (typeof filename !== "string") return;
        if (!filename.endsWith(".md")) return;
        const full = join(dir, filename);
        // macOS FSEvents prefix-matches paths, so a watcher on `findings/`
        // also fires for sibling `findings-draft/` writes with a filename
        // like `-draft/foo.md` — producing a phantom `findings/-draft/foo.md`
        // that doesn't exist on disk. Drop events whose resolved path isn't
        // a real file inside the watched dir.
        if (!existsSync(full)) return;
        if (seen.has(full)) return;
        seen.add(full);
        // Fire-and-forget from a fs.watch callback (can't be async). Swallow
        // listener failures so a slow/throwing renderer can't crash the watcher.
        void bus
          .emit({
            kind: "findingDiscovered",
            auditId,
            phaseId: null,
            path: full,
            relPath: relative(targetDir, full),
          })
          .catch(() => {});
      });
      watchers.push({ close: () => w.close() });
    } catch {
      /* dir may not exist yet on this platform; ignore */
    }
  }
  return () => watchers.forEach((w) => w.close());
}

/**
 * Decide which phase produced a draft entry. Reads frontmatter from the entry
 * (or its primary `.md` file if it's a directory) and, failing that, falls back
 * to longest-prefix match against the known phase IDs. Returns null when no
 * signal is available so the entry isn't quarantined by mistake.
 */
export async function detectDraftOwner(args: {
  draftsDir: string;
  entry: string;
  allPhaseIds: string[];
}): Promise<string | null> {
  const { draftsDir, entry, allPhaseIds } = args;
  const full = join(draftsDir, entry);

  // 1. Frontmatter signal: scan a representative .md inside the entry.
  const mdPaths: string[] = [];
  try {
    const s = statSync(full);
    if (s.isFile() && entry.toLowerCase().endsWith(".md")) {
      mdPaths.push(full);
    } else if (s.isDirectory()) {
      for (const child of readdirSync(full)) {
        if (child.toLowerCase().endsWith(".md")) mdPaths.push(join(full, child));
      }
    }
  } catch {
    return null;
  }
  for (const p of mdPaths) {
    try {
      const head = (await readFile(p, "utf8")).slice(0, 2048);
      const m = head.match(/^[ \t]*(?:phase[_-]?id|phase)\s*:\s*["']?([\w.-]+)["']?\s*$/im);
      if (m && m[1] && allPhaseIds.includes(m[1])) return m[1];
    } catch {
      /* keep trying */
    }
  }

  // 2. Filename-prefix signal: longest matching phase id wins. Case-insensitive
  // because draft naming conventions drift across agents (V1 vs v1, etc.).
  const lower = entry.toLowerCase();
  let best: string | null = null;
  for (const id of allPhaseIds) {
    const pfx = `${id.toLowerCase()}-`;
    if (lower.startsWith(pfx) && (best === null || id.length > best.length)) {
      best = id;
    }
  }
  return best;
}

/** Finalized finding buckets: confirmed (`findings/`) + theoretical (`findings-theoretical`). */
const FINALIZED_FINDING_DIRS: readonly string[] = ["findings", "findings-theoretical"];

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];

export async function summarizeFindings(
  resultsDir: string,
): Promise<{ total: number; bySeverity: Record<string, number> }> {
  const bySeverity: Record<string, number> = {};
  let total = 0;
  for (const sub of FINALIZED_FINDING_DIRS) {
    const dir = join(resultsDir, sub);
    let entries: import("fs").Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const mdPath = await representativeFindingMarkdown(join(dir, entry.name), entry.isDirectory());
      if (mdPath === null) continue;
      total++;
      const sev = parseSeverity(await readFile(mdPath, "utf8").catch(() => "")) ?? "Unknown";
      bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    }
  }

  // Draft findings are historically flat markdown files. Keep counting them
  // separately so in-progress audits still surface candidate volume, but do
  // not recurse and double-count directory-shaped finalized findings.
  const draftsDir = join(resultsDir, "findings-draft");
  try {
    for (const entry of await readdir(draftsDir, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.toLowerCase().endsWith(".md")) continue;
      total++;
      const body = await readFile(join(draftsDir, entry.name), "utf8").catch(() => "");
      const sev = parseSeverity(body) ?? "Unknown";
      bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    }
  } catch {
    /* no drafts */
  }
  return { total, bySeverity: sortSeverity(bySeverity) };
}

async function representativeFindingMarkdown(path: string, isDirectory: boolean): Promise<string | null> {
  if (!isDirectory) return path.toLowerCase().endsWith(".md") ? path : null;
  for (const candidate of ["report.md", "draft.md"]) {
    const full = join(path, candidate);
    try {
      const s = await stat(full);
      if (s.isFile()) return full;
    } catch {
      /* try next */
    }
  }
  return null;
}

function parseSeverity(body: string): string | null {
  // Matches both "**Severity**: High" and "- Severity: High" / "Severity: High".
  const m = body.match(/severity\s*\*?\*?\s*:\s*\*?\*?\s*([A-Za-z]+)/i);
  if (!m || !m[1]) return null;
  const raw = m[1].toLowerCase();
  for (const canonical of SEVERITY_ORDER) {
    if (canonical.toLowerCase() === raw) return canonical;
  }
  return m[1].charAt(0).toUpperCase() + m[1].slice(1).toLowerCase();
}

function sortSeverity(counts: Record<string, number>): Record<string, number> {
  const ordered: Record<string, number> = {};
  for (const k of SEVERITY_ORDER) {
    if (counts[k] !== undefined) ordered[k] = counts[k];
  }
  for (const k of Object.keys(counts)) {
    if (!SEVERITY_ORDER.includes(k)) ordered[k] = counts[k]!;
  }
  return ordered;
}
