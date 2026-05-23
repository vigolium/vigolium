import { mkdir, writeFile } from "fs/promises";
import { join } from "path";

/**
 * Always-present directive injected into `vigolium-results/audit-context.md` by every
 * CLI entry point that launches a mode (claude/codex handoff, interactive
 * `-i` exec). Each command-def's Context section inlines this file via
 * `!cat`, so the agents see it on their first turn.
 *
 * Policy: the user's invocation of `vigolium-audit run --mode <m>` IS the
 * authorization. Agents must not freelance text-based confirmation prompts,
 * regardless of whether `AskUserQuestion` is available. When the mode spec's
 * Pre-Flight Check would normally ask via `AskUserQuestion`, the default is
 * "Start fresh" — re-invocation signals the user wants a fresh run, not a
 * resume. Resume is opt-in via the explicit `--resume` flag; when that flag is
 * present, writeAuditContext uses RESUME_CONFIRM_SECTION instead.
 */
export const AUTO_CONFIRM_SECTION =
  `## Auto-Confirm Default — Invocation Is Authorization\n\n` +
  `The user invoked this mode deliberately by running \`vigolium-audit run --mode <m>\`. ` +
  `That invocation IS the authorization for the entire run. Do not seek further ` +
  `confirmation under any guise — whether or not \`AskUserQuestion\` is available, ` +
  `whether or not a human appears to be watching the stream.\n\n` +
  `**Forbidden behaviors (zero tolerance):**\n` +
  `- Do NOT emit a freelance text-based confirmation prompt — no "Two options: 1. ... 2. ...", ` +
  `no "Before I kick off … I need your confirmation", no "Should I proceed? (yes/no)", ` +
  `no "Which would you like?" with numbered choices. If the spec doesn't explicitly require ` +
  `a stop, you MUST proceed.\n` +
  `- Do NOT stop to surface concerns about cost, duration, scope size, code drift, ` +
  `model attribution, stale working artifacts, or whether the user "really wants" the mode ` +
  `they invoked. The orchestrator already accepted those trade-offs by launching this run.\n` +
  `- Do NOT propose alternative modes ("Downshift to balanced / lite?"). The user picked this ` +
  `mode; honor it.\n` +
  `- Do NOT invent side effects the spec forbids — in particular, do NOT create or check out ` +
  `an "audit" branch, do NOT \`git checkout\`/\`git switch\`/\`git commit\`/\`git push\`. ` +
  `The mode spec is explicit: stay on the current branch and write everything under \`vigolium-results/\`.\n\n` +
  `**Required defaults when the spec's Pre-Flight Check would normally ask via \`AskUserQuestion\`:**\n` +
  `- Existing \`vigolium-results/audit-state.json\` (in-progress or complete): pick **"Start fresh"** — ` +
  `delete the existing \`vigolium-results/audit-state.json\` and proceed with Pre-Audit Setup. ` +
  `Re-invocation of the same mode signals the user wants a fresh run, not a resume. ` +
  `(Resume is only entered via the explicit \`--resume\` flag, which the CLI handles before ` +
  `this prompt ever runs.)\n` +
  `- Any other resume-vs-fresh / scope-confirmation / model-attribution choice: pick the option ` +
  `marked "(Recommended)" if any, else pick the option that **continues the audit**.\n\n` +
  `- Clean up stale working state per the mode spec (e.g. \`findings-draft/\`, ` +
  `\`probe-workspace/\`, \`chamber-workspace/\` from prior rounds) and continue.\n` +
  `- Only stop if a hard precondition genuinely cannot be satisfied (e.g. target directory ` +
  `unreadable) — in that case fail loudly with an explicit error rather than waiting for input.`;

export const RESUME_CONFIRM_SECTION =
  `## Auto-Confirm Default — Explicit Resume Requested\n\n` +
  `The user invoked this run through \`vigolium-audit resume\` or \`vigolium-audit run --resume\`. ` +
  `That invocation IS the authorization to continue the existing non-complete audit. Do not seek further ` +
  `confirmation under any guise — whether or not \`AskUserQuestion\` is available.\n\n` +
  `**Required defaults when the spec's Pre-Flight Check would normally ask via \`AskUserQuestion\`:**\n` +
  `- Existing \`vigolium-results/audit-state.json\` (in-progress, failed, or aborted): pick **"Resume from last checkpoint"**. ` +
  `Do NOT start fresh, do NOT delete \`audit-state.json\`, and do NOT wipe durable findings or attack-surface outputs.\n` +
  `- Reset only stale \`in_progress\` phase markers that need to be retried, preserving completed phase outputs.\n` +
  `- Any other resume-vs-fresh / scope-confirmation / model-attribution choice: pick the option that **continues the existing audit**.\n\n` +
  `**Forbidden behaviors (zero tolerance):**\n` +
  `- Do NOT emit a freelance text-based confirmation prompt — no "Should I proceed?", no numbered choices, no pause for confirmation.\n` +
  `- Do NOT propose alternative modes or downshift.\n` +
  `- Do NOT create or check out branches, commit, push, or mutate git state. Stay on the current branch and write under \`vigolium-results/\`.\n\n` +
  `Only stop if a hard precondition genuinely cannot be satisfied; fail loudly with an explicit error rather than waiting for input.`;

export interface AuditContextPayload {
  /** True when launched by `vigolium-audit resume` / `run --resume`. */
  resume?: boolean;
  /** Records `triggered_via` on the audit record (e.g. "refresh→deep"). */
  triggeredVia?: string;
  /** Phase IDs the orchestrator wants the agents to skip. */
  excludePhases?: string[];
  /** Free-form user-supplied prose narrowing the audit. */
  focus?: string;
  /** Free-form user-supplied prose flagging intentional behaviors. */
  expectedBehaviors?: string;
}

/**
 * Write `<resultsDir>/audit-context.md` containing the auto-confirm directive
 * plus any orchestrator/user-supplied context. Always called before the
 * agents start work so every code path (handoff + interactive) injects the
 * same policy. Creates `resultsDir` if it doesn't already exist.
 */
export async function writeAuditContext(
  resultsDir: string,
  payload: AuditContextPayload,
): Promise<void> {
  await mkdir(resultsDir, { recursive: true });
  const sections: string[] = [payload.resume ? RESUME_CONFIRM_SECTION : AUTO_CONFIRM_SECTION];
  if (payload.resume) {
    sections.push(`## Resume Requested\n\nContinue the latest non-complete audit for this mode. Preserve the existing audit ID and completed phase state.`);
  }
  if (payload.triggeredVia) {
    sections.push(`## Triggered Via\n\n${payload.triggeredVia}`);
  }
  if (payload.excludePhases && payload.excludePhases.length > 0) {
    const list = payload.excludePhases.map((p) => `- ${p}`).join("\n");
    sections.push(
      `## Skip Phases (orchestrator directive)\n\n` +
        `Skip these phase IDs without spawning their agents. Record them as ` +
        `\`skipped\` in \`vigolium-results/audit-state.json\`.\n\n${list}`,
    );
  }
  if (payload.focus) {
    sections.push(`## Audit Focus (user-supplied)\n\n${payload.focus.trim()}`);
  }
  if (payload.expectedBehaviors) {
    sections.push(
      `## Expected Behaviors (user-supplied)\n\n` +
        `The behaviors below are intentional design decisions. Do not file findings ` +
        `for issues that match these descriptions; if a candidate finding overlaps, ` +
        `note the overlap and exclude it.\n\n${payload.expectedBehaviors.trim()}`,
    );
  }

  const contextPath = join(resultsDir, "audit-context.md");
  const body =
    `# Audit Context\n\n` +
    `Auto-generated by the vigolium-audit CLI before the mode starts. Read this for ` +
    `run-time directives and user-supplied context before starting work.\n\n` +
    `${sections.join("\n\n")}\n`;
  await writeFile(contextPath, body, "utf8");
}
