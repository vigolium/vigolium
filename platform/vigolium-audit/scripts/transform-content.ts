#!/usr/bin/env bun
/**
 * Build-time markdown transform that emits SDK-safe variants of vendored
 * agent-defs and command-defs. Source files keep their Claude-Code-flavored
 * prose; this script writes neutralized copies under src/content/sdk-variants/
 * for use by adapters that don't speak Claude Code's slash-command / subagent
 * dispatch model (currently: codex-sdk, codex-cli).
 *
 * Rules are pure and deterministic — no LLM in the loop. Diff between source
 * and variant is printed at the end of the run for review.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "fs";
import { dirname, join, relative } from "path";
import { fileURLToPath } from "url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "src", "content");
const OUT = join(SRC, "sdk-variants");

interface Rule {
  name: string;
  apply(text: string): string;
}

const RULES: Rule[] = [
  {
    name: "strip-vigolium-audit-prefix",
    // `vigolium-audit:advisory-hunter` → `advisory-hunter` (preserve backticks).
    apply: (t) => t.replace(/\bvigolium-audit:([a-zA-Z][\w-]*)/g, "$1"),
  },
  {
    name: "strip-run-in-background",
    // ` with \`run_in_background: true\`` → ``
    apply: (t) =>
      t
        .replace(/\s*with\s+`run_in_background:\s*true`/g, "")
        .replace(/`run_in_background:\s*true`/g, ""),
  },
  {
    name: "neutralize-spawn-language",
    // `spawn \`<name>\`` → `(orchestrator dispatches \`<name>\`)`. The original
    // rule had a trailing `\b` after the closing backtick, which only matches
    // before a word character — so any "spawn `name`" followed by a space,
    // period, or end-of-string slipped through. Drop the trailing boundary.
    apply: (t) => t.replace(/\b(?:spawn|Spawn)\s+`([a-z][\w-]+)`/g, "(orchestrator dispatches `$1`)"),
  },
  {
    name: "drop-parallel-message-cue",
    // "In a single message, ..." → just ...
    apply: (t) =>
      t.replace(/\bIn a \*\*single message\*\*,?\s*/gi, "").replace(/\bin a single message,?\s*/gi, ""),
  },
  {
    name: "drop-claude-code-tool-mentions",
    apply: (t) =>
      t
        .replace(/\bAskUserQuestion\b/g, "(prompt user — interactive only)")
        .replace(/\bTaskCreate\b|\bTaskUpdate\b|\bTaskGet\b|\bTaskList\b/g, "(plan-tool — n/a)"),
  },
];

function transform(text: string): string {
  let out = text;
  for (const rule of RULES) out = rule.apply(out);
  return out;
}

/**
 * Post-transform validators. Each one inspects the *output* of `transform()`
 * and returns a problem string (or null when clean). If any validator
 * complains for any file, the build fails loudly — silently shipping a
 * variant that still contains Claude-Code-shaped markup is the exact bug
 * SDK variants exist to prevent.
 *
 * Validators ignore code fences and the description: frontmatter line
 * because those legitimately quote claude-shaped tokens in documentation.
 */
type ValidatorIssue = { rule: string; sample: string };
const VALIDATORS: Array<{ name: string; check: RegExp }> = [
  { name: "no-vigolium-audit-prefix", check: /\bvigolium-audit:[a-zA-Z][\w-]*/ },
  { name: "no-run-in-background-flag", check: /run_in_background:\s*true/ },
  { name: "no-spawn-backtick", check: /\bspawn\s+`[a-z][\w-]+`/i },
];

function validate(text: string): ValidatorIssue[] {
  const stripped = stripCodeFencesAndQuotes(text);
  const issues: ValidatorIssue[] = [];
  for (const v of VALIDATORS) {
    const m = stripped.match(v.check);
    if (m) issues.push({ rule: v.name, sample: m[0] });
  }
  return issues;
}

function stripCodeFencesAndQuotes(text: string): string {
  // Drop fenced code blocks and the description: line (which can legitimately
  // quote the claude-shaped tokens these validators are looking for).
  return text
    .replace(/```[\s\S]*?```/g, "")
    .replace(/^description:[^\n]*\n/m, "");
}

function copyTree(
  srcDir: string,
  outDir: string,
  kindLabel: string,
  problems: Array<{ file: string; issues: ValidatorIssue[] }>,
): { changed: number; total: number } {
  let total = 0;
  let changed = 0;
  if (!existsSync(srcDir)) return { changed, total };
  for (const entry of readdirSync(srcDir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      const sub = copyTree(join(srcDir, entry.name), join(outDir, entry.name), kindLabel, problems);
      total += sub.total;
      changed += sub.changed;
      continue;
    }
    if (!entry.name.endsWith(".md")) continue;
    total++;
    const srcPath = join(srcDir, entry.name);
    const outPath = join(outDir, entry.name);
    const original = readFileSync(srcPath, "utf8");
    const transformed = transform(original);
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    writeFileSync(outPath, transformed);
    if (transformed !== original) changed++;
    const issues = validate(transformed);
    if (issues.length > 0) problems.push({ file: relative(ROOT, outPath), issues });
  }
  return { changed, total };
}

function main(): void {
  if (existsSync(OUT)) rmSync(OUT, { recursive: true, force: true });
  mkdirSync(OUT, { recursive: true });

  const problems: Array<{ file: string; issues: ValidatorIssue[] }> = [];
  const agents = copyTree(join(SRC, "agent-defs"), join(OUT, "agent-defs"), "agent", problems);
  const commands = copyTree(join(SRC, "command-defs"), join(OUT, "command-defs"), "command", problems);

  console.log(
    `[transform] sdk-variants → ${relative(ROOT, OUT)} ` +
      `(agents ${agents.changed}/${agents.total}, commands ${commands.changed}/${commands.total})`,
  );

  if (problems.length > 0) {
    console.error(`[transform] FAIL: ${problems.length} files still contain claude-shaped markup after transform:`);
    for (const p of problems) {
      for (const i of p.issues) {
        console.error(`  ${p.file}  [${i.rule}]  ${JSON.stringify(i.sample)}`);
      }
    }
    console.error(
      `\nUpdate the RULES table in scripts/transform-content.ts to handle this token, ` +
        `or rephrase the source so the codex variant doesn't need to neutralize it.`,
    );
    process.exit(2);
  }
}

main();
