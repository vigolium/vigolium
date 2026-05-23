import chalk from "chalk";
import { resolve, join } from "path";
import { getContentLoader } from "../content-loader.js";
import { StateStore } from "../engine/state.js";
import { formatDuration } from "./run-render.js";
import type { AuditRecord, CommandDef } from "../engine/types.js";

interface ListOptions {
  target?: string;
  json?: boolean;
}

interface ModeRow {
  mode: string;
  description: string;
  /** Phase count; -1 marks a synthetic routing mode (refresh) that resolves at runtime. */
  phases: number;
  /** Median duration of prior `complete` runs of this mode, in ms. */
  observedMedianMs: number | null;
  /** Sample size behind the median. */
  observedRuns: number;
  /** Heuristic estimate when no observed data is available, in ms. */
  estimateMs: number;
  /** True when the time figure is the heuristic, false when it's the observed median. */
  estimateFromBaseline: boolean;
}

/**
 * Per-phase wall-clock baseline used when no historical state exists. Tuned
 * conservatively from typical L1/L2-style scans — a phase that calls Bash,
 * Read, Grep, and writes 0–2 findings usually lands in this range.
 */
const BASELINE_MINUTES_PER_PHASE = 4;

export async function listCommand(opts: ListOptions = {}): Promise<void> {
  const targetDir = resolve(opts.target ?? ".");
  const loader = getContentLoader();
  const modeNames = (await loader.listCommands()).sort();

  const observed = await collectObservedDurations(targetDir);

  const rows: ModeRow[] = [];
  for (const mode of modeNames) {
    let command: CommandDef;
    try {
      command = await loader.loadCommand(mode);
    } catch {
      continue;
    }
    const phases = command.phases.length;
    // 0-phase command-defs (e.g. status.md) are slash-command UI templates,
    // not invokable audit modes. Surface them via their own CLI commands.
    if (phases === 0) continue;
    const stats = observed.get(mode);
    rows.push({
      mode,
      description: command.description,
      phases,
      observedMedianMs: stats?.median ?? null,
      observedRuns: stats?.runs ?? 0,
      estimateMs: stats?.median ?? phases * BASELINE_MINUTES_PER_PHASE * 60_000,
      estimateFromBaseline: stats === undefined,
    });
  }

  // `refresh` is a routing mode resolved at runtime (revisit | deep) — no
  // command-def of its own, but users invoke it via --mode refresh.
  rows.push({
    mode: "refresh",
    description: "Routing mode: re-audit a target by dispatching to `revisit` when a prior complete audit + KB exists, otherwise a fresh `deep` skipping advisory/archaeology/patch-bypass phases.",
    phases: -1,
    observedMedianMs: null,
    observedRuns: 0,
    estimateMs: 0,
    estimateFromBaseline: true,
  });
  rows.sort((a, b) => a.mode.localeCompare(b.mode));

  if (opts.json) {
    process.stdout.write(JSON.stringify({ kind: "list", targetDir, modes: rows }) + "\n");
    return;
  }

  console.log(chalk.bold(`\nvigolium-audit — available modes ${chalk.dim(`(${rows.length} total)`)}\n`));

  // Width-aware: cap description column so a narrow terminal doesn't wrap
  // mid-row. Hard floor at 40 cols of description so it stays useful.
  const termWidth = process.stdout.columns || 100;
  const phasesStr = (r: ModeRow): string => (r.phases === -1 ? "—" : String(r.phases));
  const timeStr = (r: ModeRow): string => (r.phases === -1 ? "varies" : `~${formatDuration(r.estimateMs)}`);

  const modeCol = Math.max(...rows.map((r) => r.mode.length), 4);
  const phasesCol = Math.max(...rows.map((r) => phasesStr(r).length), 6);
  const timeCol = Math.max(...rows.map((r) => timeStr(r).length), 6);
  const descCol = Math.max(40, termWidth - modeCol - phasesCol - timeCol - 8);

  const header = chalk.dim(
    "mode".padEnd(modeCol) +
      "  " +
      "phases".padStart(phasesCol) +
      "  " +
      "time".padStart(timeCol) +
      "  " +
      "description",
  );
  console.log(header);
  console.log(chalk.dim("─".repeat(Math.min(termWidth, modeCol + phasesCol + timeCol + descCol + 6))));

  // Wrap descriptions across up to 2 lines at word boundaries. Line 2 is
  // indented under the description column so the table stays aligned; longer
  // descriptions ellipsis at the end of line 2.
  const descIndent = " ".repeat(modeCol + 2 + phasesCol + 2 + timeCol + 2);
  for (const r of rows) {
    const [line1, line2] = wrapTwo(r.description, descCol);
    const timeColor = r.phases === -1 ? chalk.yellow : r.estimateFromBaseline ? chalk.dim : chalk.cyan;
    console.log(
      chalk.cyan(r.mode.padEnd(modeCol)) +
        "  " +
        chalk.magenta(phasesStr(r).padStart(phasesCol)) +
        "  " +
        timeColor(timeStr(r).padStart(timeCol)) +
        "  " +
        line1,
    );
    if (line2.length > 0) console.log(descIndent + line2);
  }
  console.log("");
  console.log(
    chalk.dim(
      `time: ${chalk.cyan("observed median")} from prior complete runs; ${chalk.dim("baseline")} = phases × ${BASELINE_MINUTES_PER_PHASE} min`,
    ),
  );
  console.log(chalk.dim(`pass --json for full descriptions and per-mode sample counts\n`));

  printChoiceGuide();
}

function printChoiceGuide(): void {
  const h = (s: string): string => chalk.bold(s);
  const m = (s: string): string => chalk.cyan(s);
  console.log(h("Choosing between modes:"));
  console.log(
    `  ${m("revisit")}    second offensive pass on the same code. Reuses prior KB; anti-anchored\n` +
      `             reasoning surfaces findings round 1 missed. Use after a complete deep run\n` +
      `             when you want to make sure nothing was missed.`,
  );
  console.log(
    `  ${m("reinvest")}   cross-agent re-verification of CRIT/HIGH findings using a DIFFERENT\n` +
      `             agent platform (claude ↔ codex). Confirms / refutes existing findings;\n` +
      `             does NOT surface new ones. Cheap; pair after revisit.`,
  );
  console.log(
    `  ${m("refresh")}    routing convenience: resolves to ${m("revisit")} when prior KB + findings exist,\n` +
      `             otherwise a fresh ${m("deep")} skipping advisory/archaeology/patch-bypass phases.`,
  );
  console.log(
    `  ${m("diff")}       re-run only the deep phases affected by files changed since the last\n` +
      `             audited commit. Use for incremental re-audit after a small change.`,
  );
  console.log(
    `  ${m("longshot")}   bottom-up file-by-file hail-mary. Surfaces findings that architecture-\n` +
      `             anchored audits miss; complementary to deep, not a replacement.`,
  );
  console.log("");
  console.log(
    chalk.dim(
      `  recipe: have a deep result? run ` +
        chalk.cyan("`vigolium-audit run --modes revisit,reinvest --agent codex`") +
        ` (or vice-versa) for a second pass with anti-anchored reasoning followed by cross-agent FP elimination.`,
    ),
  );
  console.log("");
  console.log(h("Resuming an interrupted audit:"));
  console.log(
    `  If a run was killed mid-way (quota limit, SIGINT, crash, --max-cost cap), the\n` +
      `  audit stays non-complete in ${chalk.cyan("vigolium-results/audit-state.json")}. Pick it up where it left off:\n` +
      `    ${chalk.cyan("vigolium-audit resume [path]")}                   # auto-detect mode + audit, continue\n` +
      `    ${chalk.cyan("vigolium-audit run --mode <mode> --resume")}      # explicit form, when you want to pick the mode yourself`,
  );
  console.log(
    chalk.dim(
      `  Completed phases are skipped; stale in-progress phases are quarantined and retried.\n` +
        `  Preference order when picking the audit: ${chalk.cyan("in_progress")} → ${chalk.cyan("aborted")} → ${chalk.cyan("failed")}.`,
    ),
  );
  console.log("");
}

/**
 * Split `text` into at most two lines, each no wider than `width`, breaking at
 * word boundaries. Anything that wouldn't fit on line 2 is ellipsised.
 */
function wrapTwo(text: string, width: number): [string, string] {
  if (text.length <= width) return [text, ""];
  const breakAt = findBreak(text, width);
  const first = text.slice(0, breakAt).trimEnd();
  const rest = text.slice(breakAt).trimStart();
  if (rest.length <= width) return [first, rest];
  const secondBreak = findBreak(rest, width - 1);
  return [first, rest.slice(0, secondBreak).trimEnd() + "…"];
}

/** Find the last whitespace at or before `width`, or `width` itself if none. */
function findBreak(s: string, width: number): number {
  if (s.length <= width) return s.length;
  const slice = s.slice(0, width + 1);
  const lastSpace = slice.lastIndexOf(" ");
  return lastSpace > 0 ? lastSpace : width;
}

interface ModeStats {
  median: number;
  runs: number;
}

async function collectObservedDurations(targetDir: string): Promise<Map<string, ModeStats>> {
  const out = new Map<string, ModeStats>();
  let audits: AuditRecord[];
  try {
    audits = (await new StateStore(join(targetDir, "vigolium-results")).load()).audits;
  } catch {
    return out;
  }

  const byMode = new Map<string, number[]>();
  for (const a of audits) {
    if (a.status !== "complete" || !a.completed_at) continue;
    const start = Date.parse(a.started_at);
    const end = Date.parse(a.completed_at);
    if (Number.isNaN(start) || Number.isNaN(end) || end <= start) continue;
    const list = byMode.get(a.mode) ?? [];
    list.push(end - start);
    byMode.set(a.mode, list);
  }

  for (const [mode, durations] of byMode) {
    durations.sort((a, b) => a - b);
    const mid = Math.floor(durations.length / 2);
    const median = durations.length % 2 === 0
      ? Math.round((durations[mid - 1]! + durations[mid]!) / 2)
      : durations[mid]!;
    out.set(mode, { median, runs: durations.length });
  }
  return out;
}
