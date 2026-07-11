import type { CommandDef, PhaseDef } from "./types.js";
import { describeArtifactRule } from "./artifact-gates.js";

export function parseToolsField(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function composeUserPrompt(
  phase: PhaseDef,
  command: CommandDef,
  auditId: string,
  targetDir: string,
  context: { focus?: string; expectedBehaviors?: string; liveTarget?: string } = {},
): string {
  // The command body uses $ARGUMENTS as a placeholder for trailing slash-command
  // args. In headless mode there's no slash command, so we substitute the live
  // target (or empty string) before truncating — leaving the literal token
  // would mislead the agent.
  const argSubstitution = context.liveTarget ?? "";
  const bodyWithArgs = command.body.replace(/\$ARGUMENTS\b/g, argSubstitution);
  const lines = [
    `Audit ID: ${auditId}`,
    `Mode: ${command.mode}`,
    `Phase: ${phase.id} — ${phase.title}`,
    `Target directory: ${targetDir}`,
    `State file: vigolium-results/audit-state.json`,
  ];
  if (typeof context.liveTarget === "string" && context.liveTarget.length > 0) {
    lines.push(`Live target: ${context.liveTarget}`);
  }
  lines.push(
    ``,
    `Execute this phase as defined in the command-def's prose body.`,
    `The engine exclusively owns vigolium-results/audit-state.json. Do not edit it or mark phase state yourself.`,
  );
  if (phase.completion) {
    const gateKind = phase.completion.enforcement === "required" ? "required" : "best-effort advisory";
    lines.push(
      `The engine will evaluate these ${gateKind} artifact checks after the phase:`,
      ...phase.completion.artifacts.map((rule) => `- ${describeArtifactRule(rule)}`),
    );
  }
  lines.push(
    ``,
    `--- COMMAND-DEF BODY (for reference) ---`,
    bodyWithArgs,
  );
  if (typeof context.focus === "string" && context.focus.length > 0) {
    lines.push(
      ``,
      `--- AUDIT FOCUS (user-supplied) ---`,
      `Prioritize the following areas. This is a hint, not a hard restriction —`,
      `if you discover a high-severity issue outside these areas, still report it.`,
      ``,
      context.focus,
    );
  }
  if (typeof context.expectedBehaviors === "string" && context.expectedBehaviors.length > 0) {
    lines.push(
      ``,
      `--- EXPECTED BEHAVIORS (user-supplied) ---`,
      `The behaviors described below are intentional design decisions, NOT`,
      `vulnerabilities. Do not file findings for issues that match these`,
      `descriptions. If a finding overlaps, note the overlap and exclude it.`,
      ``,
      context.expectedBehaviors,
    );
  }
  return lines.join("\n");
}
