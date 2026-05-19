import { mkdir, writeFile } from "fs/promises";
import { join } from "path";

/**
 * Always-present directive injected into `archon/audit-context.md` by every
 * CLI entry point that launches a mode (claude/codex handoff, interactive
 * `-i` exec). Each command-def's Context section inlines this file via
 * `!cat`, so the agents see it on their first turn.
 *
 * Policy: the user's invocation of `archon run --mode <m>` IS the
 * authorization. Agents must not freelance text-based confirmation prompts,
 * regardless of whether `AskUserQuestion` is available. When the mode spec's
 * Pre-Flight Check would normally ask via `AskUserQuestion`, the default is
 * "Start fresh" — re-invocation signals the user wants a fresh run, not a
 * resume. Resume is opt-in via the explicit `--resume` flag.
 */
export const AUTO_CONFIRM_SECTION =
  `## Auto-Confirm Default — Invocation Is Authorization\n\n` +
  `The user invoked this mode deliberately by running \`archon run --mode <m>\`. ` +
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
  `The mode spec is explicit: stay on the current branch and write everything under \`archon/\`.\n\n` +
  `**Required defaults when the spec's Pre-Flight Check would normally ask via \`AskUserQuestion\`:**\n` +
  `- Existing \`archon/audit-state.json\` (in-progress or complete): pick **"Start fresh"** — ` +
  `delete the existing \`archon/audit-state.json\` and proceed with Pre-Audit Setup. ` +
  `Re-invocation of the same mode signals the user wants a fresh run, not a resume. ` +
  `(Resume is only entered via the explicit \`--resume\` flag, which the CLI handles before ` +
  `this prompt ever runs.)\n` +
  `- Any other resume-vs-fresh / scope-confirmation / model-attribution choice: pick the option ` +
  `marked "(Recommended)" if any, else pick the option that **continues the audit**.\n\n` +
  `- Clean up stale working state per the mode spec (e.g. \`findings-draft/\`, ` +
  `\`probe-workspace/\`, \`chamber-workspace/\` from prior rounds) and continue.\n` +
  `- Only stop if a hard precondition genuinely cannot be satisfied (e.g. target directory ` +
  `unreadable) — in that case fail loudly with an explicit error rather than waiting for input.`;

export interface AuditContextPayload {
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
 * Write `<archonDir>/audit-context.md` containing the auto-confirm directive
 * plus any orchestrator/user-supplied context. Always called before the
 * agents start work so every code path (handoff + interactive) injects the
 * same policy. Creates `archonDir` if it doesn't already exist.
 */
export async function writeAuditContext(
  archonDir: string,
  payload: AuditContextPayload,
): Promise<void> {
  await mkdir(archonDir, { recursive: true });
  const sections: string[] = [AUTO_CONFIRM_SECTION];
  if (payload.triggeredVia) {
    sections.push(`## Triggered Via\n\n${payload.triggeredVia}`);
  }
  if (payload.excludePhases && payload.excludePhases.length > 0) {
    const list = payload.excludePhases.map((p) => `- ${p}`).join("\n");
    sections.push(
      `## Skip Phases (orchestrator directive)\n\n` +
        `Skip these phase IDs without spawning their agents. Record them as ` +
        `\`skipped\` in \`archon/audit-state.json\`.\n\n${list}`,
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

  const contextPath = join(archonDir, "audit-context.md");
  const body =
    `# Audit Context\n\n` +
    `Auto-generated by the archon CLI before the mode starts. Read this for ` +
    `run-time directives and user-supplied context before starting work.\n\n` +
    `${sections.join("\n\n")}\n`;
  await writeFile(contextPath, body, "utf8");
}
