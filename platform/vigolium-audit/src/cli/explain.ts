import { existsSync } from "fs";
import { readdir, readFile, stat } from "fs/promises";
import { resolve, join, basename } from "path";
import chalk from "chalk";
import { StateStore } from "../engine/state.js";
import { failCli, severityColor, statusArrow } from "./util.js";
import type { AuditRecord } from "../engine/types.js";

interface ExplainOptions {
  targetDir?: string;
  json?: boolean;
}

/**
 * Locate and print a finding by id/slug. Read-only. Reports:
 *   - finding directory and primary report.md content
 *   - audit + phase that produced it (from frontmatter, falling back to
 *     filename prefix and the latest audit's phase records)
 *   - any preserved raw artifacts under .archive/<audit>/<phase>/
 *
 * Useful for triaging false positives without spelunking through vigolium-results/.
 */
export async function explainCommand(findingId: string, opts: ExplainOptions = {}): Promise<void> {
  const targetDir = resolve(opts.targetDir ?? ".");
  const resultsDir = join(targetDir, "vigolium-results");
  if (!existsSync(resultsDir)) return fail(opts, `no vigolium-results/ directory at ${targetDir}`);

  const located = await locateFinding(resultsDir, findingId);
  if (!located) return fail(opts, `no finding matching "${findingId}" under ${resultsDir}/findings* — try a partial id or slug`);

  const body = await readFirstReport(located.path);
  const phaseId = body ? extractField(body, /^[ \t]*(?:phase[_-]?id|phase)\s*:\s*["']?([\w.-]+)["']?\s*$/im) : null;
  const auditId = body ? extractField(body, /^[ \t]*(?:audit[_-]?id|audit)\s*:\s*["']?([\w.:-]+)["']?\s*$/im) : null;
  const severity = body ? extractField(body, /severity\s*\*?\*?\s*:\s*\*?\*?\s*([A-Za-z]+)/i) : null;

  let producingAudit: AuditRecord | null = null;
  let producingPhaseId: string | null = phaseId;
  try {
    const store = new StateStore(resultsDir);
    const state = await store.load();
    if (auditId) {
      producingAudit = state.audits.find((a) => a.audit_id === auditId) ?? null;
    }
    if (!producingAudit) producingAudit = state.audits[state.audits.length - 1] ?? null;
    if (!producingPhaseId && producingAudit) {
      // Fall back: longest matching phase id prefix in the directory name.
      const dirName = basename(located.path).toLowerCase();
      let best: string | null = null;
      for (const id of Object.keys(producingAudit.phases)) {
        const pfx = `${id.toLowerCase()}-`;
        if (dirName.startsWith(pfx) && (best === null || id.length > best.length)) best = id;
      }
      producingPhaseId = best;
    }
  } catch {
    /* state may not exist — that's fine */
  }

  const archiveDir = producingAudit && producingPhaseId
    ? join(resultsDir, ".archive", producingAudit.audit_id, producingPhaseId)
    : null;
  const archiveEntries = archiveDir && existsSync(archiveDir) ? await readdir(archiveDir) : [];

  if (opts.json) {
    process.stdout.write(
      JSON.stringify({
        kind: "explain",
        finding: {
          id: findingId,
          path: located.path,
          stage: located.stage,
          severity,
          phaseId: producingPhaseId,
          auditId: producingAudit?.audit_id ?? null,
          auditMode: producingAudit?.mode ?? null,
          archive: archiveDir,
          archiveEntries,
          body,
        },
      }) + "\n",
    );
    return;
  }

  console.log(chalk.bold(`\nvigolium-audit — explain ${chalk.cyan(findingId)}`));
  console.log(`${statusArrow("Path")} Path:      ${chalk.cyan(located.path)}`);
  console.log(`${statusArrow("Stage")} Stage:     ${located.stage}`);
  if (severity) console.log(`${statusArrow("Severity")} Severity:  ${severityColor(severity)(severity)}`);
  if (producingPhaseId) console.log(`${statusArrow("Phase")} Phase:     ${chalk.cyan(producingPhaseId)}`);
  if (producingAudit) {
    console.log(`${statusArrow("Audit")} Audit:     ${chalk.cyan(producingAudit.audit_id)} ${chalk.dim(`(${producingAudit.mode})`)}`);
  }
  if (archiveEntries.length > 0) {
    console.log(`${statusArrow("Archive")} Archive:   ${chalk.dim(archiveDir)} ${chalk.dim(`(${archiveEntries.length} files)`)}`);
  }
  if (body) {
    console.log(chalk.dim(`\n--- ${basename(located.path)} ---`));
    console.log(body.trimEnd());
  }
}

interface LocatedFinding {
  /** Absolute path: file (when finding is a flat .md) or directory. */
  path: string;
  stage: "final" | "draft" | "archived";
}

/**
 * Search findings/ then findings-theoretical/ then findings-draft/ then
 * .archive/ for an entry whose name matches the id case-insensitively.
 * Allows partial / slug-only inputs.
 */
async function locateFinding(resultsDir: string, id: string): Promise<LocatedFinding | null> {
  const needle = id.toLowerCase();
  const stages: Array<[string, "final" | "draft"]> = [
    ["findings", "final"],
    ["findings-theoretical", "final"],
    ["findings-draft", "draft"],
  ];
  for (const [sub, stage] of stages) {
    const dir = join(resultsDir, sub);
    if (!existsSync(dir)) continue;
    const entries = await readdir(dir);
    const exact = entries.find((e) => e.toLowerCase() === needle);
    if (exact) return { path: join(dir, exact), stage };
    const partial = entries.find((e) => e.toLowerCase().includes(needle));
    if (partial) return { path: join(dir, partial), stage };
  }
  // Walk .archive/<audit>/<phase>/ for quarantined drafts.
  const archiveRoot = join(resultsDir, ".archive");
  if (existsSync(archiveRoot)) {
    // Fresh core runs preserve the prior finalized buckets under
    // .archive/pre-run/<new-audit-id>/{findings,findings-theoretical}/.
    const preRun = join(archiveRoot, "pre-run");
    if (existsSync(preRun)) {
      for (const snapshot of await readdir(preRun)) {
        for (const bucket of ["findings", "findings-theoretical"]) {
          const bucketDir = join(preRun, snapshot, bucket);
          if (!existsSync(bucketDir) || !(await stat(bucketDir)).isDirectory()) continue;
          const entries = await readdir(bucketDir);
          const exact = entries.find((entry) => entry.toLowerCase() === needle);
          const partial = exact ?? entries.find((entry) => entry.toLowerCase().includes(needle));
          if (partial) return { path: join(bucketDir, partial), stage: "archived" };
        }
      }
    }
    for (const audit of await readdir(archiveRoot)) {
      if (audit === "pre-run") continue;
      const auditDir = join(archiveRoot, audit);
      if (!(await stat(auditDir)).isDirectory()) continue;
      for (const phase of await readdir(auditDir)) {
        const phaseDir = join(auditDir, phase);
        if (!(await stat(phaseDir)).isDirectory()) continue;
        const entries = await readdir(phaseDir);
        const match = entries.find((e) => e.toLowerCase().includes(needle));
        if (match) return { path: join(phaseDir, match), stage: "archived" };
      }
    }
  }
  return null;
}

async function readFirstReport(p: string): Promise<string | null> {
  let s;
  try {
    s = await stat(p);
  } catch {
    return null;
  }
  if (s.isFile()) {
    try {
      return await readFile(p, "utf8");
    } catch {
      return null;
    }
  }
  if (s.isDirectory()) {
    const children = await readdir(p);
    const preferred = children.find((c) => c.toLowerCase() === "report.md");
    const first = preferred ?? children.find((c) => c.toLowerCase().endsWith(".md"));
    if (!first) return null;
    try {
      return await readFile(join(p, first), "utf8");
    } catch {
      return null;
    }
  }
  return null;
}

function extractField(body: string, re: RegExp): string | null {
  const m = body.match(re);
  return m && m[1] ? m[1] : null;
}

function fail(opts: ExplainOptions, msg: string): never {
  return failCli(opts, "explain", msg);
}
