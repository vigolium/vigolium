import type { AgentPlatform } from "../engine/types.js";

/**
 * Normalized event stream emitted by every Adapter, regardless of underlying
 * runtime (Claude SDK, Claude CLI, Codex SDK, Codex CLI). The orchestrator
 * and the TUI both subscribe to this stream.
 */
export type AdapterEvent =
  | { kind: "textDelta"; text: string }
  | { kind: "toolCall"; id: string; tool: string; input: unknown }
  | { kind: "toolResult"; id: string; output: unknown; isError: boolean; partial?: boolean }
  | { kind: "thinking"; text: string }
  | {
      kind: "session";
      sessionId: string;
      /**
       * Init-time inventory of what the session has access to. Populated from
       * Claude Code's `system: init` message. Lets the user verify the plugin
       * actually loaded inside claude's view of the world (mismatch with the
       * `[setup]` install count is a smoking gun for plugin-resolution bugs).
       */
      agents?: string[];
      commands?: string[];
      skills?: string[];
      plugins?: { name: string; path: string }[];
      model?: string;
      permissionMode?: string;
    }
  | {
      kind: "finish";
      ok: true;
      result: string;
      usd: number;
      tokens: { input: number; output: number };
      durationMs: number;
    }
  | {
      kind: "finish";
      ok: false;
      reason: string;
      usd: number;
      tokens: { input: number; output: number };
      durationMs: number;
    }
  | { kind: "error"; cause: Error; transient?: boolean }
  | {
      /**
       * Anthropic API subscription rate-limit snapshot. Returned inside API
       * response bodies for Claude.ai subscribers only; absent for API-key
       * users. We harvest it from Claude Code's stream-json output and surface
       * it so callers can show a `/usage`-style quota line without making a
       * dedicated probe call.
       */
      kind: "rateLimits";
      data: RateLimitsSnapshot;
    };

export interface RateLimitsWindow {
  /** 0–100; percentage of the window already used. */
  used_percentage: number;
  /** Unix epoch seconds when the window resets. */
  resets_at: number;
}

export interface RateLimitsSnapshot {
  five_hour?: RateLimitsWindow;
  seven_day?: RateLimitsWindow;
  seven_day_opus?: RateLimitsWindow;
  seven_day_sonnet?: RateLimitsWindow;
}

export interface AdapterRunInput {
  /**
   * Custom system prompt. When undefined, the adapter uses the runtime's
   * default — for claude that means the Claude Code preset, which is required
   * for slash-command resolution and plugin-loaded skills/agents to work.
   */
  systemPrompt?: string;
  userPrompt: string;
  /**
   * Tool whitelist for the model. Adapter implementations decide how to map
   * names to their runtime's tool registry. When undefined, no restriction
   * is applied (runtime defaults). An empty array explicitly denies all tools.
   */
  tools?: string[];
  /**
   * Tools that must NOT be available to the model. Used in headless mode to
   * block AskUserQuestion (which would deadlock). Composed with `tools` —
   * a name in `disallowedTools` overrides any allow-list match.
   */
  disallowedTools?: string[];
  /** Working directory to run tool calls in. Defaults to process.cwd(). */
  cwd?: string;
  /** Per-call model override (e.g. "sonnet" / "opus" / "claude-sonnet-4-6"). */
  model?: string;
  /** Hard cap on conversation turns; adapter terminates with a finish event. */
  maxTurns?: number;
  /** Externally-driven abort. Adapter should propagate to its runtime. */
  abortSignal?: AbortSignal;
  /**
   * Resume a prior conversation by session id (from a previous run's `session`
   * event). Loads that session's history so a follow-up prompt continues it —
   * e.g. triage → exploit on the same finding without re-establishing context.
   * Claude SDK maps this to `query`'s `resume` option; codex has no equivalent
   * and ignores it.
   */
  resume?: string;
  /** Hint label for logs / TUI; usually the phase id. */
  label?: string;
  /**
   * Verbose mode: CLI adapters pass through `-d/--debug` to their child
   * binary and forward child stderr live to the parent stderr.
   */
  debug?: boolean;
  /**
   * Absolute path to a Claude Code plugin directory to load for this run.
   * Surfaces commands, agents, skills, hooks. Required for slash-command
   * dispatch in handoff-mode headless runs. Ignored by codex adapters.
   */
  pluginDir?: string;
  /**
   * Bypass all tool-permission prompts for this run. Required when
   * `pluginDir` is set so the agent can call the plugin's tools without
   * blocking on confirmation. Maps to `--dangerously-skip-permissions` (CLI)
   * or `permissionMode: 'bypassPermissions'` + `allowDangerouslySkipPermissions`
   * (SDK).
   */
  bypassPermissions?: boolean;
}

export interface Adapter {
  /** Stable id, e.g. "claude-sdk", "claude-cli", "codex-sdk", "codex-cli". */
  readonly id: string;
  readonly platform: AgentPlatform;
  /** Human-readable description shown by `vigolium-audit verify`. */
  readonly description: string;
  /**
   * One-shot adapter probe: round-trip a trivial prompt to confirm auth +
   * connectivity. Throws on failure with a useful message.
   */
  probe(): Promise<void>;
  /** Drive a single phase / agent invocation. */
  run(input: AdapterRunInput): AsyncIterable<AdapterEvent>;
}
