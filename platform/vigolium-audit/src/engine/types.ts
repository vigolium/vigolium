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

/** Adapter transport used for headless agent execution. */
export type AgentTransport = "auto" | "sdk" | "cli";

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
   * Headless adapter transport. `auto` prefers the Codex Agent SDK (which can
   * reuse Codex CLI/ChatGPT login) while preserving Claude's existing
   * API-key-to-SDK / subscription-to-CLI selection. Interactive (`-i`) runs
   * always use the native CLI and reject an explicit `sdk` transport.
   */
  transport?: AgentTransport;
  /**
   * Model name forwarded to the agent runtime. When unset (and
   * `VIGOLIUM_AUDIT_MODEL` is also unset), no `--model` is passed and the
   * underlying CLI / SDK uses its own configured default. Set this (or the env
   * var) to forward an explicit model.
   */
  model?: string;
  /**
   * Audit target. Usually a local directory path; may also be a remote git
   * URL (https://github.com/owner/repo, https://gitlab.com/owner/repo,
   * git@host:owner/repo, git:// or ssh:// schemes). At the CLI boundary, a
   * URL is shallow-cloned into `./<owner-repo>/` under the current working
   * directory and this field is rewritten to that path before any phase runs.
   */
  target: string;
  /** Alias of `target` (mirrors `vigolium agent audit --source`); folded into `target` at the CLI boundary. Accepts the same path or remote git URL forms. */
  source?: string;
  interactive?: boolean;
  /**
   * Interactive runs (`-i`) only: launch the underlying agent handoff command
   * inside a detached tmux session and stream its pane output to stdout,
   * instead of exec'ing it attached to the current terminal. The session is
   * named so the user can `tmux attach` for full interaction. Requires `tmux`
   * on PATH. Ignored for headless runs.
   */
  tmux?: boolean;
  /**
   * Interactive runs (`-i`) only: path or command name of the agent binary to
   * exec (e.g. a wrapper like `cc`/`cw` that pre-loads env). Overrides the
   * auto-detected `claude`/`codex` binary and the `VIGOLIUM_AUDIT_*_PATH`
   * env overrides. A leading `~/` is expanded to the home directory; a bare
   * command name is resolved via PATH by the OS at spawn time.
   */
  agentBinary?: string;
  /**
   * Interactive claude runs (`-i`) only: value passed straight through to the
   * claude CLI as `--disallowedTools` (e.g. "AskUserQuestion" so the agent
   * can't block a headless-style handoff on an interactive question). No-op
   * for codex, which has no equivalent flag.
   */
  disallowedTools?: string;
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
   * codeql/semgrep workspaces, etc. from `vigolium-results/`. Defaults to off
   * (everything is preserved). Runs only on `complete` status;
   * `failed`/`aborted` always preserve everything.
   */
  stripRaw?: boolean;
  /**
   * Opt out of the post-audit auto-prune that `deep` and `confirm` apply on
   * successful completion. With --keep-raw, raw scanner output, draft
   * findings, and intermediate workspaces stay under `vigolium-results/` so
   * the user can manually review them. Mutually exclusive with --strip-raw.
   */
  keepRaw?: boolean;
  /**
   * When post-audit cleanup runs, retain DB snapshots and skip scrubbing
   * secrets (passwords, tokens, API keys, connection strings) from the
   * `confirm-workspace/` JSON + log files. The junk sweep (`*.sarif`,
   * `*.bqrs`, `tmp/`) still runs. Default: redact. `--keep-raw` is a
   * superset (it skips the whole prune, so secrets are retained too).
   */
  keepSecrets?: boolean;
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
   * sequentially. Each mode gets its own \`vigolium-results/parallel-<mode>/\` subdir
   * so audit-state.json doesn't collide. Ignored for --mode (single mode).
   */
  parallelModes?: boolean;
  /**
   * cac maps `--no-git` to `git: false`. When false, vigolium-audit skips all git
   * probing: phases gated on `requires_git` are dropped (as if the target
   * had no .git), and the audit record's commit/branch/repository fields
   * are recorded as null. Undefined/true preserves existing behavior.
   */
  git?: boolean;
  /**
   * Seed the run from an existing vigolium-results/ output directory. vigolium-audit reads its
   * audit-state.json, shallow-clones the recorded repository at the recorded
   * commit, copies this directory into the clone as `vigolium-results/`, runs the
   * requested mode against the clone, then syncs the whole vigolium-results/ tree back
   * to this path on exit. Headless-only; incompatible with --no-git.
   */
  fromResultsDir?: string;
  /**
   * Keep the temporary clone directory after the run finishes instead of
   * removing it. Only applies when --from-results-dir is set and the clone
   * destination was an auto-generated temp dir (no --target override).
   */
  keepClone?: boolean;
  /**
   * Resume the latest non-complete audit in `<target>/vigolium-results/audit-state.json`
   * that matches the requested mode. Completed phases are skipped; stale
   * `in_progress` phases are quarantined and retried. The audit's `audit_id`,
   * `started_at`, and `context` are preserved. Mutually exclusive with
   * --modes, --from-results-dir, --parallel-modes, and --mode refresh (which
   * has its own resume detection).
   */
  resume?: boolean;
  /**
   * `merge` mode only: two-or-more audit output folders (project dir or
   * `vigolium-results/` dir) to consolidate before the LLM normalization pass.
   * The deterministic pre-merge copies their findings (collision-safe) into the
   * first `--dir` folder in place and stamps `merge_metadata` into its
   * `audit-state.json`, then `run --mode merge` dedups/renumbers/reports.
   * cac hands a single `--dir` through as a string; normalize to an array.
   */
  dir?: string | string[];
  /** Allow a pre-merge / non-destructive op to write into a non-empty destination. */
  force?: boolean;
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
  /** Whether local Git history was available to history-dependent phases. */
  history_available?: boolean;
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

/** A concrete file that must exist under `vigolium-results/`. */
export interface FileArtifactRule {
  kind: "file";
  /** Path relative to the active results directory. */
  path: string;
  /** Minimum byte size. Defaults to 1. */
  min_bytes: number;
  /** Literal strings that must all occur in the file. */
  contains: string[];
  /** Parse the file as JSON after the size/content checks. */
  json: boolean;
}

/** A set of files matched below `vigolium-results/`. */
export interface GlobArtifactRule {
  kind: "glob";
  /** Bun glob pattern relative to the active results directory. */
  pattern: string;
  /** Minimum number of matching regular files. Defaults to 1. */
  min_matches: number;
  /** Minimum size for every matched file. Defaults to 1. */
  each_min_bytes: number;
  /** Optional literals used to select a subset of glob matches for validation. */
  select_contains?: string[] | undefined;
  /** Literals required in every selected match. */
  each_contains?: string[] | undefined;
}

/** At least one nested rule must pass. */
export interface AnyArtifactRule {
  kind: "any";
  rules: ArtifactRule[];
}

/** Require a report file in every immediate finding directory across buckets. */
export interface FindingReportsArtifactRule {
  kind: "finding_reports";
  /** Bucket paths relative to the results directory. */
  roots: string[];
  filename: string;
  min_bytes: number;
  /** A clean audit with no finding directories satisfies the rule. */
  allow_empty: boolean;
  /** Optional consolidation manifest whose finding IDs must all resolve to reports. */
  manifest_path?: string | undefined;
  /** Array fields read from the manifest. */
  manifest_lists: string[];
}

export type ArtifactRule =
  | FileArtifactRule
  | GlobArtifactRule
  | FindingReportsArtifactRule
  | AnyArtifactRule;

/**
 * Deterministic completion contract evaluated by the engine after an agent
 * returns. Agents do not decide whether a phase is complete.
 */
export interface PhaseCompletionContract {
  artifacts: ArtifactRule[];
  /** Narrow repair calls allowed after a successful agent return. */
  repair_attempts: number;
  /** Required gates fail the phase; advisory gates provide best-effort observability only. */
  enforcement: "required" | "advisory";
}

export interface PhaseDef {
  id: string;
  title: string;
  agent: string | null;
  requires_git: boolean;
  parallel_with: string[];
  depends_on: string[];
  completion?: PhaseCompletionContract;
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
