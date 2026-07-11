import chalk from "chalk";
import { DURABLE_DIRS, DURABLE_STATE_FILES } from "../engine/strip-artifacts.js";
import { JUNK_DIR_NAMES, JUNK_FILE_EXTENSIONS } from "../engine/redact-artifacts.js";

export interface OutputStructureOptions {
  json?: boolean;
}

interface KeepEntry {
  /** Path under `vigolium-results/`. A trailing `/` marks a directory. */
  path: string;
  note: string;
}

interface RemoveEntry {
  path: string;
  note: string;
}

interface StructureSpec {
  keep: KeepEntry[];
  remove: RemoveEntry[];
  /** Recursive junk patterns swept out of surviving directories. */
  sweep: string[];
  redact: {
    /** Files dropped wholesale (can't be safely scrubbed). */
    drop: string[];
    scope: string;
    note: string;
  };
  naming: { pattern: string; note: string }[];
  instructions: string[];
}

// Human descriptions for the canonical keep set. Names are sourced from the
// strip pass's own constants (DURABLE_STATE_FILES / DURABLE_DIRS) so this stays
// in sync; the notes here are the only thing maintained by hand.
const KEEP_NOTES: Record<string, string> = {
  "audit-state.json": "canonical phase-graph + run history (resume/status read this; never rewrite)",
  "file-state.json": "per-file scan record used by diff mode for incremental scope (never rewrite)",
  "revisit-audit-state.json": "round-N revisit state, kept separate from the round-1 audit-state.json",
  "attack-surface": "durable knowledge base: recon, KB report, SAST, authz matrix, intent reconciliation",
  findings: "finalized confirmed findings — one dir per finding (report.md, poc.*, evidence/)",
  "findings-theoretical": "finalized theoretical / unconfirmed findings, same per-dir shape",
  quarantine: "findings excluded by a merge, with the reason in QUARANTINE.md",
};

// Raw workspaces and scratch the strip pass removes. These are everything that
// is NOT in the keep set — `shouldKeep()` keeps durable state, durable dirs,
// confirm-workspace/, and *.md, and drops the rest. Listed explicitly here so
// the downstream agent knows what to expect (illustrative, not exhaustive).
const COMMON_RAW_DIRS: RemoveEntry[] = [
  { path: ".archive/", note: "reversible pre-run snapshots and failed-phase quarantine; keep while resuming, remove only after successful delivery" },
  { path: "findings-draft/", note: "in-progress candidate drafts; promote any VALID draft into findings/ FIRST, then delete" },
  { path: "codeql-artifacts/", note: "built CodeQL DB + SARIF — large, raw" },
  { path: "codeql-queries/", note: "generated per-variant .ql queries" },
  { path: "chamber-workspace/", note: "review-chamber debate transcripts" },
  { path: "probe-workspace/", note: "per-component probe scratch" },
  { path: "adversarial-reviews/", note: "independent-verifier scratch reviews" },
  { path: "bypass-analysis/", note: "per-advisory bypass notes (merged into the KB already)" },
  { path: "real-env-evidence/", note: "live-env capture scratch" },
  { path: "merge-workspace/", note: "merge index / dedup / rename scratch" },
  { path: "*-prior-round/", note: "previous-round snapshots from revisit/reinvest" },
  { path: "scripts/", note: "agent-generated helper scripts" },
  { path: "semgrep-res/", note: "raw Semgrep output" },
];

export function buildSpec(): StructureSpec {
  const keep: KeepEntry[] = [];
  for (const name of DURABLE_STATE_FILES) {
    keep.push({ path: name, note: KEEP_NOTES[name] ?? "durable state file" });
  }
  for (const name of DURABLE_DIRS) {
    keep.push({ path: `${name}/`, note: KEEP_NOTES[name] ?? "durable output directory" });
  }
  keep.push({
    path: "confirm-workspace/",
    note: "confirmation evidence, verdict-grouped report-ready/ + needs-review/ staging, env logs",
  });
  keep.push({
    path: "*.md",
    note: "mode reports: final-audit-report.md, confirmation-report.md, merge-report.md, reinvest-report.md",
  });

  const sweep = [
    ...JUNK_FILE_EXTENSIONS.map((ext) => `*${ext}`),
    ...[...JUNK_DIR_NAMES].map((d) => `${d}/`),
  ];

  return {
    keep,
    remove: COMMON_RAW_DIRS,
    sweep,
    redact: {
      drop: ["db-snapshot.*"],
      scope: "confirm-workspace/ only",
      note:
        "drop db-snapshot.* wholesale; mask secret-keyed JSON values (password/token/api_key/…) to ***; " +
        "mask KEY=VALUE secrets, inline-credential URLs, and JWT/sk-/ghp_/AKIA/xox token shapes in *.log. " +
        "Never touch audit-state.json / file-state.json — downstream tooling parses them.",
    },
    naming: [
      { pattern: "findings/<Severity><N>-<slug>/", note: "uppercase severity initial + 1-indexed within severity, e.g. C1-sql-injection, H2-idor, M3-open-redirect" },
      { pattern: "FP-<ID>-<slug>/", note: "false positive confirmed during confirm mode; excluded from severity counts but retained" },
    ],
    instructions: [
      "Promote every VALID draft in findings-draft/ into findings/<Severity><N>-<slug>/ (1-index N within each severity), then delete findings-draft/.",
      "Delete the raw workspaces listed under REMOVE — they are intermediate scratch, not deliverables.",
      "Recursively sweep junk (" + sweep.join(", ") + ") out of every surviving directory.",
      "In confirm-workspace/ only: delete db-snapshot.* and mask secret values in JSON + *.log files.",
      "Leave audit-state.json and file-state.json byte-for-byte unchanged — they are machine-parsed.",
      "Keep every top-level *.md report and the durable directories as-is.",
      "Do not invent or move findings between findings/ and findings-theoretical/ — preserve each finding's bucket.",
    ],
  };
}

export function renderMarkdown(spec: StructureSpec): string {
  const lines: string[] = [];
  lines.push("# Ideal vigolium-results/ layout (post-cleanup)");
  lines.push("");
  lines.push(
    "Hand this spec to a coding agent together with a `vigolium-results/` folder to normalize it " +
      "to the canonical, delivery-oriented layout below. This is the same shape `vigolium-audit strip` " +
      "produces. KEEP entries are the durable deliverables; everything else is raw scratch to remove.",
  );
  lines.push("");

  lines.push("## Canonical tree");
  lines.push("");
  lines.push("```text");
  lines.push("vigolium-results/");
  for (const k of spec.keep) {
    lines.push(`  ${k.path.padEnd(26)}KEEP    # ${k.note}`);
  }
  lines.push("  ─────");
  for (const r of spec.remove) {
    lines.push(`  ${r.path.padEnd(26)}REMOVE  # ${r.note}`);
  }
  lines.push("```");
  lines.push("");

  lines.push("## Keep (durable deliverables)");
  lines.push("");
  for (const k of spec.keep) {
    lines.push(`- \`${k.path}\` — ${k.note}`);
  }
  lines.push("");

  lines.push("## Remove (raw scratch / intermediate workspaces)");
  lines.push("");
  lines.push("Anything not in the keep set is raw scratch. Common offenders:");
  lines.push("");
  for (const r of spec.remove) {
    lines.push(`- \`${r.path}\` — ${r.note}`);
  }
  lines.push("");

  lines.push("## Sweep (recursive, inside kept dirs)");
  lines.push("");
  lines.push(`Remove scanner scratch left inside surviving directories: ${spec.sweep.map((s) => `\`${s}\``).join(", ")}.`);
  lines.push("");

  lines.push("## Redact secrets");
  lines.push("");
  lines.push(`Scope: **${spec.redact.scope}**. ${spec.redact.note}`);
  lines.push("");

  lines.push("## Naming conventions");
  lines.push("");
  for (const n of spec.naming) {
    lines.push(`- \`${n.pattern}\` — ${n.note}`);
  }
  lines.push("");

  lines.push("## Instructions for the cleanup agent");
  lines.push("");
  spec.instructions.forEach((step, i) => lines.push(`${i + 1}. ${step}`));
  lines.push("");

  return lines.join("\n");
}

function renderHuman(spec: StructureSpec): string {
  // Terminal-friendly colored rendering of the same spec.
  const lines: string[] = [];
  lines.push(chalk.bold("\nIdeal vigolium-results/ layout (post-cleanup)\n"));
  lines.push(
    chalk.dim(
      "Pipe this into a coding agent (or `> spec.md`) to normalize a results folder to the\n" +
        "canonical layout — the same shape `vigolium-audit strip` produces.\n",
    ),
  );
  lines.push(chalk.bold("vigolium-results/"));
  for (const k of spec.keep) {
    lines.push(`  ${chalk.cyan(k.path.padEnd(26))}${chalk.green("KEEP")}    ${chalk.dim("# " + k.note)}`);
  }
  lines.push(chalk.dim("  ─────"));
  for (const r of spec.remove) {
    lines.push(`  ${chalk.yellow(r.path.padEnd(26))}${chalk.red("REMOVE")}  ${chalk.dim("# " + r.note)}`);
  }
  lines.push("");
  lines.push(chalk.bold("Sweep (recursive): ") + spec.sweep.map((s) => chalk.magenta(s)).join(", "));
  lines.push(chalk.bold("Redact: ") + chalk.dim(`${spec.redact.scope} — drop db-snapshot.*, mask secrets in JSON + *.log`));
  lines.push("");
  lines.push(chalk.bold("Naming:"));
  for (const n of spec.naming) lines.push(`  ${chalk.cyan(n.pattern)} ${chalk.dim("— " + n.note)}`);
  lines.push("");
  lines.push(chalk.bold("Instructions for the cleanup agent:"));
  spec.instructions.forEach((step, i) => lines.push(`  ${chalk.dim(`${i + 1}.`)} ${step}`));
  lines.push("");
  lines.push(
    chalk.dim("Tip: `vigolium-audit output-structure --markdown` emits the raw markdown for piping into another agent."),
  );
  lines.push("");
  return lines.join("\n");
}

/**
 * `vigolium-audit output-structure` — print the canonical "ideal" layout of a
 * finished `vigolium-results/` folder as a prompt-ready spec. Designed to be
 * handed to another coding agent (along with a real results folder) so it can
 * clean up / normalize the output to the delivery-oriented shape that
 * `vigolium-audit strip` produces.
 *
 * Three output flavors:
 *   - default       human-readable, colorized summary for the terminal
 *   - --markdown    raw markdown (pipe into an agent or `> spec.md`)
 *   - --json        structured spec for tooling
 */
export async function outputStructureCommand(
  opts: OutputStructureOptions & { markdown?: boolean } = {},
): Promise<void> {
  const spec = buildSpec();

  if (opts.json) {
    process.stdout.write(JSON.stringify({ kind: "output-structure", ...spec }, null, 2) + "\n");
    return;
  }
  if (opts.markdown) {
    process.stdout.write(renderMarkdown(spec) + "\n");
    return;
  }
  process.stdout.write(renderHuman(spec) + "\n");
}
