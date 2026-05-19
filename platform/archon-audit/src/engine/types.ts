export type AuditMode =
  | "lite"
  | "balanced"
  | "deep"
  | "diff"
  | "confirm"
  | "merge"
  | "revisit"
  | "reinvest"
  | "longshot"
  | "refresh";

export type AgentPlatform = "claude" | "codex";

export interface RunOptions {
  mode?: AuditMode;
  /**
   * Comma-separated list of modes to run sequentially in one invocation
   * (e.g. "deep,refresh,confirm"). Mutually exclusive with --mode. The chain
   * stops as soon as a mode finishes with status other than `complete`, and
   * --max-cost is enforced as an aggregate cap across the whole chain.
   */
  modes?: string;
  agent?: AgentPlatform;
  /**
   * Model name forwarded to the agent runtime. Defaults: claude →
   * `claude-opus-4-7[1m]`, codex → `gpt-5.5` (with `xhigh` reasoning effort).
   * Forwarded to the underlying CLI / SDK as `--model` (or equivalent).
   */
  model?: string;
  target: string;
  /** Alias of `target` (mirrors `vigolium agent audit --source`); folded into `target` at the CLI boundary. */
  source?: string;
  interactive?: boolean;
  fromAudit?: string;
  baseline?: string;
  maxCost?: number;
  strict?: boolean;
  output?: string;
  /** Sets CLAUDE_CODE_OAUTH_TOKEN for the subprocess / SDK. */
  oauthToken?: string;
  /** Override the platform's creds file for the lifetime of the run. */
  oauthCredFile?: string;
  /** Set the platform's API key env var (ANTHROPIC_API_KEY / OPENAI_API_KEY). */
  apiKey?: string;
  /** Global flag: emit machine-readable NDJSON on stdout. */
  json?: boolean;
  /** Global flag: verbose event surface (tool inputs/results, thinking, stacks). */
  debug?: boolean;
  /** Global flag: animate agent message text as a typewriter. On by default; `--no-streaming` disables. */
  streaming?: boolean;
  /**
   * Opt into post-audit stripping of raw scanner output, draft findings,
   * codeql/semgrep workspaces, etc. from `archon/`. Defaults to off
   * (everything is preserved). Runs only on `complete` status;
   * `failed`/`aborted` always preserve everything.
   */
  stripRaw?: boolean;
  /**
   * Path to a file describing areas the audit should prioritize. Free-form
   * prose; injected as a soft hint into every phase's user prompt. Hard cap
   * 32 KB. Auto-inherits from the most recent prior audit when unset.
   */
  focusFile?: string;
  /**
   * Path to a file describing intentional design decisions that should NOT
   * be flagged as vulnerabilities. Free-form prose; injected as a hard
   * exclusion into every phase's user prompt. Hard cap 32 KB. Auto-inherits
   * from the most recent prior audit when unset.
   */
  expectedBehaviorsFile?: string;
  /**
   * Live HTTP(S) endpoint to verify findings against in `confirm` mode.
   * When set, the URL is injected into the prompt and substituted for
   * `$ARGUMENTS` in the command-def body so confirm.md skips V2/V3 (env
   * discovery + provisioning) and runs PoCs against the remote target.
   * Confirm-only; rejected for other modes.
   */
  liveTarget?: string;
  /**
   * Resolve and render the phase plan, prompts, allowed-tools, and content
   * provenance without invoking any adapter. Useful for verifying mode edits
   * or per-user overrides before burning tokens. No state file is written.
   */
  dryRun?: boolean;
  /**
   * Force serial phase execution even when the mode declares parallel_with
   * siblings. Useful for cleaner logs or capped-bandwidth environments.
   * Default: parallel is on whenever phases mutually opt in.
   */
  serial?: boolean;
  /**
   * For --modes chains: run all listed modes concurrently instead of
   * sequentially. Each mode gets its own \`archon/parallel-<mode>/\` subdir
   * so audit-state.json doesn't collide. Ignored for --mode (single mode).
   */
  parallelModes?: boolean;
  /**
   * cac maps `--no-git` to `git: false`. When false, archon skips all git
   * probing: phases gated on `requires_git` are dropped (as if the target
   * had no .git), and the audit record's commit/branch/repository fields
   * are recorded as null. Undefined/true preserves existing behavior.
   */
  git?: boolean;
  /**
   * Seed the run from an existing archon/ output directory. archon reads its
   * audit-state.json, shallow-clones the recorded repository at the recorded
   * commit, copies this directory into the clone as `archon/`, runs the
   * requested mode against the clone, then syncs the whole archon/ tree back
   * to this path on exit. Headless-only; incompatible with --no-git.
   */
  fromArchonDir?: string;
  /**
   * Keep the temporary clone directory after the run finishes instead of
   * removing it. Only applies when --from-archon-dir is set and the clone
   * destination was an auto-generated temp dir (no --target override).
   */
  keepClone?: boolean;
  /**
   * Resume the latest non-complete audit in `<target>/archon/audit-state.json`
   * that matches the requested mode. Completed phases are skipped; stale
   * `in_progress` phases are quarantined and retried. The audit's `audit_id`,
   * `started_at`, and `context` are preserved. Mutually exclusive with
   * --modes, --from-archon-dir, --parallel-modes, and --mode refresh (which
   * has its own resume detection).
   */
  resume?: boolean;
}

export interface AuditContext {
  /** User-supplied focus prose (already loaded from --focus-file). */
  focus?: string;
  /** User-supplied expected-behaviors prose (already loaded from flag). */
  expected_behaviors?: string;
}

export type PhaseStatus = "pending" | "in_progress" | "complete" | "failed" | "skipped";

export interface PhaseRecord {
  status: PhaseStatus;
  started_at?: string;
  completed_at?: string;
  failed_at?: string;
  error?: string;
}

export interface AuditRecord {
  audit_id: string;
  commit: string | null;
  branch: string | null;
  repository: string | null;
  mode: AuditMode;
  model: string | null;
  agent_sdk: string;
  started_at: string;
  completed_at: string | null;
  status: "in_progress" | "complete" | "failed" | "aborted";
  phases: Record<string, PhaseRecord>;
  usage?: {
    input_tokens: number;
    output_tokens: number;
    cost_usd: number;
  };
  context?: AuditContext;
  /**
   * The mode the user originally invoked, when distinct from `mode`. Set by
   * the `refresh` router when it resolves to `revisit` or `deep` underneath.
   * Preserved across resume so reports can attribute the audit to the user's
   * actual intent.
   */
  triggered_via?: string;
}

export interface AuditState {
  schema_version: 1;
  audits: AuditRecord[];
}

export interface PhaseDef {
  id: string;
  title: string;
  agent: string | null;
  requires_git: boolean;
  parallel_with: string[];
  depends_on: string[];
}

export interface CommandDef {
  mode: AuditMode;
  description: string;
  phases: PhaseDef[];
  /** Frontmatter `allowed-tools` field (Claude-Code-shaped). */
  allowed_tools_raw?: string;
  /** Markdown body after the frontmatter block. */
  body: string;
  /** Source path the command-def was loaded from. */
  source_path: string;
}

export interface AgentDef {
  name: string;
  description: string;
  model?: string;
  tools?: string[];
  body: string;
  bodySdk?: string;
}
