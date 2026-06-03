/**
 * Model selection.
 *
 * By default vigolium-audit does NOT force a model — it lets the underlying agent
 * runtime (the `claude` / `codex` CLI or SDK) use its own configured default
 * (subscription default, `~/.claude` settings, etc.). A model is forwarded only
 * when the user opts in explicitly. Precedence:
 *
 *   1. `--model <name>` flag (highest priority)
 *   2. `VIGOLIUM_AUDIT_MODEL` env var
 *   3. unset → inherit the runtime default (no `--model` passed)
 *
 * Reasoning effort is likewise left to the runtime default; it is no longer
 * coupled to a hardcoded model choice.
 */
export const MODEL_ENV_VAR = "VIGOLIUM_AUDIT_MODEL";

/**
 * Resolve the model to forward to the agent runtime, or `undefined` to inherit
 * the runtime's own default. `override` is the value of the `--model` flag.
 */
export function resolveModel(override?: string): string | undefined {
  if (override !== undefined && override.length > 0) return override;
  const env = process.env[MODEL_ENV_VAR];
  if (env !== undefined && env.length > 0) return env;
  return undefined;
}
