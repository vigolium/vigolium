import { existsSync } from "fs";
import { resolve, join } from "path";
import chalk from "chalk";
import { StateStore } from "../engine/state.js";
import { summarizeFindings } from "../engine/orchestrator.js";
import { formatDuration } from "./run.js";
import { failCli, severityColor, statusArrow } from "./util.js";
import type { AuditRecord } from "../engine/types.js";

interface StatusOptions {
  json?: boolean;
}

/**
 * Print a compact summary of the latest audit in a target's `archon/` folder.
 * Read-only: never modifies state. Falls back to a friendly hint when no
 * archon state exists in the target.
 */
export async function statusCommand(targetPath: string, opts: StatusOptions = {}): Promise<void> {
  const targetDir = resolve(targetPath ?? ".");
  const archonDir = join(targetDir, "archon");

  if (!existsSync(archonDir)) {
    return fail(opts, `no archon/ directory at ${targetDir} — run an audit first`);
  }

  const store = new StateStore(archonDir);
  let latest: AuditRecord | null;
  try {
    latest = await store.latestAudit("any");
  } catch (err) {
    return fail(opts, `cannot read audit-state.json: ${(err as Error).message}`);
  }
  if (!latest) {
    return fail(opts, `no audits recorded in ${archonDir}/audit-state.json yet`);
  }

  const findings = await summarizeFindings(archonDir);
  const phaseSummary = summarizePhases(latest);
  const durationMs = durationOf(latest);

  if (opts.json) {
    process.stdout.write(
      JSON.stringify({
        kind: "status",
        targetDir,
        audit: {
          id: latest.audit_id,
          mode: latest.mode,
          status: latest.status,
          startedAt: latest.started_at,
          completedAt: latest.completed_at,
          durationMs,
          commit: latest.commit,
          branch: latest.branch,
          repository: latest.repository,
          model: latest.model,
          agentSdk: latest.agent_sdk,
          triggeredVia: latest.triggered_via ?? null,
          usage: latest.usage ?? null,
          phases: phaseSummary,
        },
        findings,
      }) + "\n",
    );
    return;
  }

  const statusColor =
    latest.status === "complete"
      ? chalk.green
      : latest.status === "failed"
        ? chalk.red
        : latest.status === "aborted"
          ? chalk.yellow
          : chalk.blue;
  const line = (k: string, v: string): void => console.log(`${statusArrow(k)} ${k.padEnd(10)} ${v}`);

  console.log(chalk.bold(`\narchon — status for ${chalk.cyan(targetDir)}`));
  line("Audit:", chalk.cyan(latest.audit_id));
  line("Mode:", chalk.cyan(latest.mode) + (latest.triggered_via ? chalk.dim(` (via ${latest.triggered_via})`) : ""));
  line("Status:", statusColor(latest.status));
  line("Started:", latest.started_at);
  if (latest.completed_at) line("Ended:", latest.completed_at);
  if (durationMs !== null) line("Duration:", formatDuration(durationMs));
  if (latest.commit) line("Commit:", `${(latest.branch ?? "(detached)")} @ ${latest.commit.slice(0, 7)}`);
  if (latest.agent_sdk) line("Adapter:", latest.agent_sdk + (latest.model ? chalk.dim(` (${latest.model})`) : ""));
  if (latest.usage) {
    line(
      "Usage:",
      `${chalk.magenta(`$${latest.usage.cost_usd.toFixed(2)}`)} — ` +
        chalk.magenta(`${latest.usage.input_tokens}/${latest.usage.output_tokens}`) +
        " tok",
    );
  }
  line("Phases:", formatPhaseSummary(phaseSummary));
  line("Findings:", formatFindingsLine(findings));
}

function summarizePhases(audit: AuditRecord): Record<string, number> {
  const counts: Record<string, number> = { pending: 0, in_progress: 0, complete: 0, failed: 0, skipped: 0 };
  for (const phase of Object.values(audit.phases)) {
    counts[phase.status] = (counts[phase.status] ?? 0) + 1;
  }
  return counts;
}

function formatPhaseSummary(counts: Record<string, number>): string {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const parts: string[] = [];
  if (counts.complete) parts.push(chalk.green(`${counts.complete} complete`));
  if (counts.failed) parts.push(chalk.red(`${counts.failed} failed`));
  if (counts.skipped) parts.push(chalk.dim(`${counts.skipped} skipped`));
  if (counts.in_progress) parts.push(chalk.yellow(`${counts.in_progress} in-progress`));
  if (counts.pending) parts.push(chalk.dim(`${counts.pending} pending`));
  return `${total} total — ${parts.join(", ")}`;
}

function formatFindingsLine(findings: { total: number; bySeverity: Record<string, number> }): string {
  if (findings.total === 0) return chalk.dim("0");
  const parts = Object.entries(findings.bySeverity).map(
    ([sev, n]) => severityColor(sev)(`${sev}: ${n}`),
  );
  return `${chalk.magenta(findings.total)} total — ${parts.join(", ")}`;
}

function durationOf(audit: AuditRecord): number | null {
  if (!audit.completed_at) return null;
  const start = Date.parse(audit.started_at);
  const end = Date.parse(audit.completed_at);
  if (Number.isNaN(start) || Number.isNaN(end)) return null;
  return end - start;
}

function fail(opts: StatusOptions, msg: string): never {
  return failCli(opts, "status", msg);
}
