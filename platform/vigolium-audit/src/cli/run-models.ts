import type { AgentPlatform } from "../engine/types.js";

/**
 * Per-platform default model. Overridable via `--model`. The `[1m]` suffix on
 * the Claude default selects the 1M-context Opus 4.7 variant. The codex default
 * also gets `xhigh` reasoning effort applied to the adapter; both pieces are
 * dropped when `--model` is set so a custom model isn't silently paired with a
 * default reasoning policy.
 */
export const DEFAULT_CLAUDE_MODEL = "claude-opus-4-7[1m]";
export const DEFAULT_CODEX_MODEL = "gpt-5.5";
export const DEFAULT_CODEX_REASONING_EFFORT = "xhigh" as const;

export function resolveDefaultModel(platform: AgentPlatform, override?: string): string {
  if (override !== undefined && override.length > 0) return override;
  return platform === "claude" ? DEFAULT_CLAUDE_MODEL : DEFAULT_CODEX_MODEL;
}
