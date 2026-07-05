#!/usr/bin/env bun
import { cac } from "cac";
import chalk from "chalk";
import pkg from "../package.json" with { type: "json" };
import { AUTHOR, BUILD_DATE, COMMIT_HASH, DOCS, WEBSITE } from "./build-info.js";
import type { AgentPlatform } from "./engine/types.js";

const TAGLINE =
  "vigolium-audit is an autonomous source-code security audit agent. It drives Claude or Codex through a multi-agent pipeline — gathering advisories, surfacing candidates, proposing attack paths, debating exploitability, and killing false positives — to surface high-confidence, exploitable findings in your repository.";

// One-line blurb shown in the `version` / `--version` block. Intentionally
// short — the fuller pitch lives in TAGLINE (shown under `--help`).
const DESCRIPTION =
  "vigolium-audit is Vigolium's autonomous agent for thorough source-code security audits, surfacing high-confidence, exploitable vulnerabilities.";

const cli = cac("vigolium-audit");

// Global flags — propagate to every subcommand.
//   --json:  NDJSON / single-object JSON on stdout, logs on stderr.
//   --debug: verbose event surface (raw tool calls/results, thinking blocks,
//            full error stacks, child-process stderr passthrough).
//   --agent: agent platform; consumed by run/confirm/resume/merge, accepted
//            (and harmlessly ignored) by deterministic commands like strip.
cli.option("--json", "Output machine-readable NDJSON on stdout (replaces the human log)");
cli.option("--debug", "Verbose event surface for troubleshooting");
cli.option("--streaming", "Animate agent message text as a typewriter (default: on; pass --no-streaming to disable)", {
  default: true,
});
// No cac default here: the "claude" fallback is applied in code (run.ts /
// dry-run.ts via `opts.agent ?? "claude"`), which keeps the
// `opts.agent !== undefined` "did the user pass it?" sentinel meaningful for
// confirm/resume forwarding.
cli.option(
  "--agent <agent>",
  "Agent platform (claude|codex). Defaults to claude where it applies; ignored by deterministic commands (strip/status/list/...) and by `merge --premerge-only`.",
);

// --- examples (shown under `vigolium-audit --help`) -----------------------------------
// Each entry: cyan section header, then per-command pairs of (gray comment, command).
// Comments live on their own line above the command so help renders cleanly in narrow terminals.
const section = (s: string) => cli.example(chalk.blue(s));
const cmd = (comment: string, command: string) => {
  cli.example(`# ${comment}`);
  cli.example(`  ${command}`);
};
const blank = () => cli.example("");

section("# Quickstart");
cmd("preflight: binary + auth + ping", "vigolium-audit verify claude");
cmd("3-phase headless surface scan", "vigolium-audit run --mode lite --target ./repo");
cmd("full 15-phase audit, interactive (auto-installs harness, cleans up on exit)", "vigolium-audit run --mode deep --agent claude -i");
blank();

section("# Harness install (persistent; run -i also auto-installs ephemerally)");
cmd("install the claude harness into ~/.config/vigolium-audit/harness-claude", "vigolium-audit setup claude");
cmd("install both claude + codex harnesses", "vigolium-audit setup");
cmd("remove one platform's harness", "vigolium-audit uninstall --agent codex");
cmd("remove all installed harnesses", "vigolium-audit uninstall");
blank();

section("# Auth overrides (one-shot, restored on exit)");
cmd("ANTHROPIC_API_KEY for the run", "vigolium-audit run --mode deep --api-key sk-ant-...");
cmd("CLAUDE_CODE_OAUTH_TOKEN for the run", "vigolium-audit run --mode deep --oauth-token sk-ant-oat01-...");
cmd("override codex creds for one run", "vigolium-audit run --mode confirm --agent codex --oauth-cred-file ./codex-auth.json");
blank();

section("# Cost & resilience");
cmd("hard $20 cap", "vigolium-audit run --mode deep --max-cost 20");
cmd("abort on first phase failure", "vigolium-audit run --mode deep --strict");
cmd("remote target as a git URL (cloned into ./<owner-repo>/ under cwd)", "vigolium-audit run --mode deep --target https://github.com/Yoast/wordpress-seo");
cmd("remote target via SSH (same: clones into ./owner-repo/)", "vigolium-audit run --mode deep --target git@github.com:owner/repo.git");
blank();

section("# Audit context (per-run, persisted + auto-inherited by chained modes)");
cmd("narrow what the audit prioritizes (free-form prose, 32 KB cap)", "vigolium-audit run --mode deep --focus-file ./scope.md");
cmd("flag intentional behaviors so confirm doesn't re-flag them", "vigolium-audit run --mode confirm --expected-behaviors-file ./allowed.md");
cmd("both at once on the initial deep run", "vigolium-audit run --mode deep --focus-file ./scope.md --expected-behaviors-file ./allowed.md");
cmd("chained run auto-inherits context from prior audit (no flags needed)", "vigolium-audit run --mode reinvest --agent codex");
cmd("override one field on a chained run; the other still inherits", "vigolium-audit run --mode confirm --focus-file ./narrower.md");
cmd("clear inherited context for this run (pass an empty file)", "vigolium-audit run --mode longshot --focus-file /dev/null");
blank();

section("# Output cleanup");
cmd("deep/confirm auto-prune raw workspaces + redact secrets on success", "vigolium-audit run --mode deep");
cmd("keep raw workspaces for manual review (overrides the deep/confirm auto-prune)", "vigolium-audit run --mode deep --keep-raw");
cmd("prune + sweep junk but retain DB snapshots and confirm-workspace secrets", "vigolium-audit run --mode confirm --keep-secrets");
cmd("strip raw artifacts for modes that do not auto-prune", "vigolium-audit run --mode lite --strip-raw");
cmd("strip + redact an existing vigolium-results/ folder on demand", "vigolium-audit strip ./repo");
cmd("strip an existing folder but keep its secrets", "vigolium-audit strip ./repo --keep-secrets");
cmd("print the ideal output layout as a cleanup spec for another coding agent", "vigolium-audit output-structure --markdown");
blank();

section("# Inspect prior audits");
cmd("list available modes with rough time estimates", "vigolium-audit list");
cmd("one-screen summary of the latest audit", "vigolium-audit status ./repo");
cmd("machine-readable summary", "vigolium-audit status ./repo --json | jq .audit.status");
cmd("Claude Code token usage + estimated $ (24h / 7d / 30d / all)", "vigolium-audit usage");
cmd("usage scoped to the last 7 days", "vigolium-audit usage --since 7d");
cmd("send a tiny ping to refresh live quota (5h/7d/opus/sonnet %)", "vigolium-audit usage --refresh");
blank();

section("# Resume an interrupted audit");
cmd("auto-detect mode from audit-state.json and continue", "vigolium-audit resume ./repo");
cmd("same thing via run (--mode resume is an alias for `vigolium-audit resume`)", "vigolium-audit run --mode resume --target ./repo");
cmd("explicit form (you pick the mode)", "vigolium-audit run --mode deep --resume --target ./repo");
blank();

section("# Mode chaining (auto-detects the latest completed audit; --from-audit overrides)");
cmd("boot target + execute PoCs", "vigolium-audit run --mode confirm");
cmd("second pass with anti-anchoring", "vigolium-audit run --mode revisit");
cmd("cross-agent re-verification of CRIT/HIGH", "vigolium-audit run --mode reinvest --agent codex");
cmd("hail-mary file-by-file vulnerability hunt", "vigolium-audit run --mode longshot");
cmd("merge two audit folders + dedup/normalize in one go (e.g. different agents/models)", "vigolium-audit merge --dir ./auditA --dir ./auditB --agent codex");
cmd("same combined pass via run (--dir straight into the merge mode)", "vigolium-audit run --mode merge --dir ./auditA --dir ./auditB");
cmd("just the deterministic consolidation (no tokens; inspect before normalizing)", "vigolium-audit merge --dir ./auditA --dir ./auditB --premerge-only --output ./merged");
cmd("only re-run phases affected since baseline", "vigolium-audit run --mode diff --baseline HEAD~10");
cmd("auto-route: revisit if a prior audit exists, else fresh deep", "vigolium-audit run --mode refresh");
cmd("chain modes in one invocation (stops on non-complete; aggregate --max-cost)", "vigolium-audit run --modes deep,refresh,confirm");
blank();

section("# Machine-readable output");
cmd("check verify result", "vigolium-audit verify claude --json | jq .ok");
cmd("stream phase-end events", "vigolium-audit run --mode lite --json | jq -c 'select(.kind == \"phaseEnd\")'");
blank();

section("# Debugging");
cmd("tool inputs/results, thinking, child stderr", "vigolium-audit run --mode lite --debug");
cmd("capture verbose output to a file", "vigolium-audit run --mode lite --debug 2> vigolium-audit.log");

// Inject a description block above the auto-generated sections so the tagline
// shows on `vigolium-audit --help` and `vigolium-audit` (no subcommand). Strip the auto-injected
// `vigolium-audit/<version>` banner — `--version` still works for users who want it.
cli.help((sections) => {
  const filtered = sections.filter((s) => s.body !== `vigolium-audit/${pkg.version}`);
  filtered.unshift({ body: TAGLINE });
  return filtered;
});

const runCmd = cli
  .command("run", "Run a security audit")
  .option("--mode <mode>", "Audit mode (lite|balanced|deep|diff|confirm|merge|revisit|reinvest|longshot|refresh|resume). 'resume' is an alias for `vigolium-audit resume`: auto-detect the latest non-complete audit and continue it.")
  .option("--modes <list>", "Run multiple modes in sequence (comma-separated, e.g. deep,refresh,confirm). Mutually exclusive with --mode. Stops on first non-complete mode; --max-cost is an aggregate cap.")
  .option("--model <model>", "Model name forwarded to the agent runtime. Defaults to the agent's own configured model; set this flag or the VIGOLIUM_AUDIT_MODEL env var to override.")
  .option("--target <path-or-url>", "Target directory, or a remote git URL (https://github.com/..., https://gitlab.com/..., git@host:owner/repo, git://, ssh://). A URL is cloned with --depth=1 into ./<owner-repo>/ under the current working directory and used as the audit target; an existing same-remote checkout there is reused in place.", { default: "." })
  .option("--source <path-or-url>", "Alias of --target (parity with `vigolium agent audit --source`); accepts the same path or remote git URL forms.")
  .option("-i, --interactive", "Enable Ink TUI (auto-disabled when stdout is not a TTY)")
  .option("--tmux", "Interactive runs (-i): launch the agent handoff command inside a detached tmux session and stream its output to stdout (attach with `tmux attach -t <session>`). Requires tmux on PATH.")
  .option("--agent-binary <path>", "Interactive runs (-i): path or command name of the agent binary to exec (e.g. a wrapper like 'cc'/'cw' that pre-loads env). Overrides auto-detection. Leading ~/ is expanded; a bare name is resolved via PATH.")
  .option("--disallowed-tools <tools>", "Interactive claude runs (-i): pass through to the CLI as --disallowedTools (e.g. \"AskUserQuestion\" to stop the agent blocking on an interactive prompt).")
  .option("--from-audit <id>", "Source audit id for confirm/merge/diff modes")
  .option("--baseline <ref>", "Baseline git ref for diff mode")
  .option("--max-cost <usd>", "Hard cost cap in USD; abort when exceeded")
  .option("--strict", "Headless: abort on first phase failure instead of skip-and-continue")
  .option("--output <dir>", "Mirror <target>/vigolium-results/ to <dir> after each phase. On run completion, removes <target>/vigolium-results/ so only <dir> remains. Preserved on failure/abort for resume.")
  .option("--oauth-token <token>", "Set CLAUDE_CODE_OAUTH_TOKEN for the subprocess / SDK")
  .option("--oauth-cred-file <path>", "Override platform creds (claude: ~/.claude/.credentials.json, codex: ~/.codex/auth.json) for the run; original is backed up + restored on exit")
  .option("--api-key <key>", "Pass as platform API key env (claude → ANTHROPIC_API_KEY, codex → OPENAI_API_KEY)")
  .option("--strip-raw", "Strip raw scanner output and draft findings on success for modes that do not auto-prune")
  .option("--keep-raw", "Keep raw scanner output and intermediate workspaces for manual review; overrides the deep/confirm auto-prune. Mutually exclusive with --strip-raw.")
  .option("--keep-secrets", "When cleanup runs, retain DB snapshots and skip scrubbing secrets from confirm-workspace JSON/logs (default: redacted). The junk sweep still runs.")
  .option("--focus-file <path>", "Path to a free-form file describing areas to prioritize. Injected as a soft hint into every phase. Auto-inherited by chained modes.")
  .option("--expected-behaviors-file <path>", "Path to a free-form file describing intentional behaviors that should NOT be flagged. Auto-inherited by chained modes.")
  .option("--live-target <url>", "confirm mode only: HTTP(S) endpoint to verify findings against. Skips env discovery + provisioning and runs PoCs against this URL.")
  .option("--dry-run", "Resolve and print the phase plan, prompts, and content origin without invoking any adapter. No state file is written.")
  .option("--serial", "Force serial phase execution even when the mode declares parallel_with siblings. Default: parallel.")
  .option("--parallel-modes", "When used with --modes, run all listed modes concurrently in separate vigolium-results/parallel-<mode>/ subdirs instead of sequentially. --max-cost is split evenly. Incompatible with refresh.")
  .option("--no-git", "Skip all git-related checks: treat the target as a plain directory. Phases gated on requires_git are dropped, and commit/branch/repository are recorded as null.")
  .option("--from-results-dir <path>", "Seed the run from an existing vigolium-results/ output dir. vigolium-audit reads its audit-state.json, shallow-clones the recorded repo at the recorded commit, copies this dir into the clone as vigolium-results/, runs the mode, then syncs the result back. Headless-only; --target overrides the clone destination.")
  .option("--keep-clone", "With --from-results-dir: don't remove the temp clone on exit. Useful for inspecting or replaying the cloned working tree.")
  .option("--resume", "Resume the latest non-complete audit in <target>/vigolium-results/ that matches --mode. Completed phases skipped, stale in_progress phases retried. See `vigolium-audit resume` for an auto-detect entry point.")
  .option("--dir <path>", "merge mode only (repeatable): two-or-more audit output folders to consolidate before normalizing. Runs the deterministic pre-merge (collision-safe copy + merge_metadata) into the first --dir in place, then runs --mode merge over it. See also the standalone `vigolium-audit merge`.")
  .option("--force", "merge mode only: allow the pre-merge to write into a non-empty destination.")
  .action(async (opts) => {
    // `--source` is an alias of `--target` (parity with `vigolium agent audit`).
    // cac defaults --target to ".", so an unset/default --target with an
    // explicit --source means: use --source.
    if ((opts.target === undefined || opts.target === ".") && opts.source !== undefined) {
      opts.target = opts.source;
    }
    const { runCommand } = await import("./cli/run.js");
    await runCommand(opts);
  });

// --- per-command examples (shown under `vigolium-audit run -h`) ----------------------
// cac's global cli.example() does not propagate to subcommands, so we attach
// run-specific (especially mode-focused) examples here.
const runSection = (s: string) => runCmd.example(chalk.blue(s));
const runCmdEx = (comment: string, command: string) => {
  runCmd.example(`# ${comment}`);
  runCmd.example(`  ${command}`);
};
const runBlank = () => runCmd.example("");

runSection("# Quickstart");
runCmdEx("fast 3-phase headless surface scan", "vigolium-audit run --mode lite --target ./repo");
runCmdEx("full multi-phase audit (recon, candidates, attack paths, debate)", "vigolium-audit run --mode deep --target ./repo");
runCmdEx("interactive — drops you into the CLI with the vigolium-audit harness installed", "vigolium-audit run --mode deep -i");
runCmdEx("remote target as a git URL (clones into ./<owner-repo>/ under cwd)", "vigolium-audit run --mode deep --target https://github.com/Yoast/wordpress-seo");
runCmdEx("GitLab URL works the same way", "vigolium-audit run --mode deep --target https://gitlab.com/owner/repo");
runCmdEx("SSH form also accepted", "vigolium-audit run --mode deep --target git@github.com:owner/repo.git");
runCmdEx("--source is an alias of --target (accepts paths or git URLs)", "vigolium-audit run --mode deep --source ./repo");
runBlank();

runSection("# Interactive handoff tweaks (-i only)");
runCmdEx("run the handoff inside a detached tmux session and stream it (attach with `tmux attach`)", "vigolium-audit run --mode deep -i --tmux");
runCmdEx("use a custom claude wrapper that sets up env (e.g. 'cc'/'cw')", "vigolium-audit run --mode deep -i --agent-binary cc");
runCmdEx("point at an absolute binary path", "vigolium-audit run --mode deep -i --agent-binary ~/.local/bin/claude");
runCmdEx("stop the agent blocking on questions (claude)", "vigolium-audit run --mode deep -i --disallowed-tools AskUserQuestion");
runCmdEx("all three together", "vigolium-audit run --mode deep -i --tmux --agent-binary cw --disallowed-tools AskUserQuestion");
runBlank();

runSection("# Audit modes (each mode runs a different phase graph)");
runCmdEx("lite — ~3-phase surface scan, fast & cheap", "vigolium-audit run --mode lite");
runCmdEx("balanced — middle ground between lite and deep", "vigolium-audit run --mode balanced");
runCmdEx("deep — full audit pipeline, highest signal", "vigolium-audit run --mode deep");
runCmdEx("diff — re-audit only phases affected since a baseline ref", "vigolium-audit run --mode diff --baseline HEAD~10");
runCmdEx("confirm — boot the target and execute PoCs against prior findings", "vigolium-audit run --mode confirm");
runCmdEx("confirm against a live URL (skips env discovery + provisioning)", "vigolium-audit run --mode confirm --live-target https://staging.example.com");
runCmdEx("revisit — second pass with anti-anchoring on the latest audit", "vigolium-audit run --mode revisit");
runCmdEx("reinvest — cross-agent re-verification of CRIT/HIGH findings", "vigolium-audit run --mode reinvest --agent codex");
runCmdEx("longshot — hail-mary file-by-file vulnerability hunt", "vigolium-audit run --mode longshot");
runCmdEx("merge — consolidate two audit folders (e.g. different agents/models), then dedup + normalize", "vigolium-audit run --mode merge --dir ./auditA --dir ./auditB");
runCmdEx("refresh — auto-route: revisit if a prior audit exists, else fresh deep (skips advisory/git/cve-bypass)", "vigolium-audit run --mode refresh");
runCmdEx("resume — alias for `vigolium-audit resume`: auto-detect the latest non-complete audit and continue it", "vigolium-audit run --mode resume");
runBlank();

runSection("# Seed a run from an existing vigolium-results/ output dir (clones the recorded repo)");
runCmdEx("re-run confirm against an archived vigolium-results/ result; clone is in /tmp, synced back on exit", "vigolium-audit run --mode confirm --from-results-dir ./prior-audits/sentry");
runCmdEx("clone goes to a chosen dir instead of /tmp", "vigolium-audit run --mode confirm --from-results-dir ./prior-audits/sentry --target ./tmp-clones/sentry");
runCmdEx("retain the temp clone after the run for inspection", "vigolium-audit run --mode confirm --from-results-dir ./prior-audits/sentry --keep-clone");
runBlank();

runSection("# Mode chaining (auto-detects the latest completed audit; --from-audit overrides)");
runCmdEx("initial deep run", "vigolium-audit run --mode deep");
runCmdEx("then confirm exploitability of its findings", "vigolium-audit run --mode confirm");
runCmdEx("then anti-anchored revisit", "vigolium-audit run --mode revisit");
runCmdEx("then cross-agent re-verification on the other platform", "vigolium-audit run --mode reinvest --agent codex");
runCmdEx("explicitly point at a prior audit instead of the latest", "vigolium-audit run --mode confirm --from-audit a1b2c3d4");
runCmdEx("run multiple modes back-to-back in one invocation (stops on non-complete; aggregate --max-cost)", "vigolium-audit run --modes deep,refresh,confirm");
runBlank();

runSection("# Auth overrides (one-shot, restored on exit)");
runCmdEx("claude: ANTHROPIC_API_KEY for the run", "vigolium-audit run --mode deep --api-key sk-ant-...");
runCmdEx("claude: CLAUDE_CODE_OAUTH_TOKEN for the run", "vigolium-audit run --mode deep --oauth-token sk-ant-oat01-...");
runCmdEx("codex: override ~/.codex/auth.json for one run", "vigolium-audit run --mode confirm --agent codex --oauth-cred-file ./codex-auth.json");
runBlank();

runSection("# Cost & resilience");
runCmdEx("hard $20 cap (orchestrator aborts when exceeded)", "vigolium-audit run --mode deep --max-cost 20");
runCmdEx("abort on first phase failure (default: skip-and-continue)", "vigolium-audit run --mode deep --strict");
runCmdEx("treat target as a plain dir; skip git checks and requires_git phases", "vigolium-audit run --mode deep --no-git");
runBlank();

runSection("# Audit context (persisted + auto-inherited by chained modes)");
runCmdEx("narrow what the audit prioritizes (free-form prose, 32 KB cap)", "vigolium-audit run --mode deep --focus-file ./scope.md");
runCmdEx("flag intentional behaviors so confirm doesn't re-flag them", "vigolium-audit run --mode confirm --expected-behaviors-file ./allowed.md");
runCmdEx("both at once on the initial deep run", "vigolium-audit run --mode deep --focus-file ./scope.md --expected-behaviors-file ./allowed.md");
runCmdEx("override one field on a chained run; the other still inherits", "vigolium-audit run --mode confirm --focus-file ./narrower.md");
runCmdEx("clear inherited context for this run (pass an empty file)", "vigolium-audit run --mode longshot --focus-file /dev/null");
runBlank();

runSection("# Output & debugging");
runCmdEx("deep/confirm auto-prune raw workspaces + redact secrets on success", "vigolium-audit run --mode deep");
runCmdEx("keep raw workspaces for manual review (overrides the deep/confirm auto-prune)", "vigolium-audit run --mode deep --keep-raw");
runCmdEx("prune + sweep junk but retain DB snapshots and confirm-workspace secrets", "vigolium-audit run --mode confirm --keep-secrets");
runCmdEx("strip raw artifacts for modes that do not auto-prune", "vigolium-audit run --mode lite --strip-raw");
runCmdEx("stream NDJSON phase events", "vigolium-audit run --mode lite --json | jq -c 'select(.kind == \"phaseEnd\")'");
runCmdEx("verbose: tool inputs/results, thinking, child stderr", "vigolium-audit run --mode lite --debug");
runCmdEx("capture verbose output to a file", "vigolium-audit run --mode lite --debug 2> vigolium-audit.log");

const bridgeCmd = cli
  .command(
    "bridge <action>",
    "Sidecar: drive Claude/Codex via the Agent SDK for a single task. <action> is a task preset (triage|exploit|plan), `run` (raw prompt), `serve` (long-lived NDJSON daemon), or `list`. The vigolium-scanner skill is always loaded so the agent can operate the vigolium CLI. Built for the Go vigolium binary to call.",
  )
  .option("--model <model>", "Model forwarded to the agent runtime (e.g. sonnet|opus|a full model id). Defaults to the task preset or the runtime default; VIGOLIUM_AUDIT_MODEL also honored.")
  .option("--cwd <dir>", "Working directory the agent operates on (the target under assessment). Defaults to --target or the current directory.")
  .option("--target <dir>", "Alias of --cwd.")
  .option("--prompt <text>", "User instruction / task text.")
  .option("--prompt-file <path>", "Read the user prompt from a file (use '-' semantics by piping stdin instead).")
  .option("--input <text>", "Structured input context (e.g. a finding), inlined under a '# Task input' block.")
  .option("--input-file <path>", "Read structured input context (e.g. a finding JSON) from a file.")
  .option("--system-prompt <text>", "Override the system prompt (honored for the `run` action only).")
  .option("--system-prompt-file <path>", "Read the system-prompt override from a file.")
  .option("--skill <name>", "Load an extra skill on top of the task defaults (repeatable). vigolium-scanner is always loaded.")
  .option("--allow-tools <list>", "Comma-separated tool allow-list. Default: no restriction (all tools).")
  .option("--deny-tools <list>", "Comma-separated tools to deny. AskUserQuestion is always denied (headless).")
  .option("--max-turns <n>", "Hard cap on conversation turns.")
  .option("--resume <sessionId>", "Resume a prior session (from an earlier run's `session` event) so a follow-up continues the same conversation, e.g. triage → exploit.")
  .option("--output <mode>", "json|text — override the task's output mode. json extracts the final fenced JSON block into result.output.")
  .option("--no-bypass-permissions", "Do NOT bypass tool-permission prompts (default: bypass, required for autonomous tool use).")
  .option("--oauth-token <token>", "Set CLAUDE_CODE_OAUTH_TOKEN for the run/daemon")
  .option("--oauth-cred-file <path>", "Override platform creds for the run/daemon; original backed up + restored on exit")
  .option("--api-key <key>", "Pass as platform API key env (claude → ANTHROPIC_API_KEY, codex → OPENAI_API_KEY)")
  .action(async (action: string, opts) => {
    const { bridgeCommand } = await import("./cli/bridge.js");
    await bridgeCommand(action, opts);
  });

const bridgeEx = (comment: string, command: string) => {
  bridgeCmd.example(`# ${comment}`);
  bridgeCmd.example(`  ${command}`);
};
bridgeEx("triage a finding (JSON in, JSON verdict out), machine-readable", "vigolium-audit bridge triage --input-file finding.json --cwd ./repo --json");
bridgeEx("plan an attack against a target's code + attack surface", "vigolium-audit bridge plan --input-file vigolium-results/attack-surface/summary.md --cwd ./repo");
bridgeEx("develop a PoC for a confirmed finding against a live target", "vigolium-audit bridge exploit --input-file finding.json --prompt 'target: https://staging.example.com' --cwd ./repo");
bridgeEx("triage then exploit on the SAME conversation (chain via --resume)", "vigolium-audit bridge exploit --resume <sessionId-from-triage> --json");
bridgeEx("raw prompt, no preset, pick a skill and model", "vigolium-audit bridge run --prompt 'summarize the auth flow' --skill audit --model opus --cwd ./repo");
bridgeEx("pipe the prompt via stdin", "echo 'is the /admin route authenticated?' | vigolium-audit bridge run --cwd ./repo");
bridgeEx("long-lived daemon: Go sends NDJSON requests on stdin, reads events on stdout", "vigolium-audit bridge serve --cwd ./repo --json");
bridgeEx("list available task presets", "vigolium-audit bridge list");

cli
  .command("verify <platform>", "Verify install + adapter probe")
  .action(async (platform: string, opts: { json?: boolean }) => {
    const { verifyCommand } = await import("./cli/verify.js");
    await verifyCommand(platform, { json: !!opts.json });
  });

cli
  .command("incremental-scope", "Compute changed files since the last audit baseline. Use --since <ref> for an explicit git diff range, otherwise the hash baseline in file-state.json is used.")
  .option("--target <path>", "Project directory (default: current)", { default: "." })
  .option("--since <ref>", "Git ref to diff against (in addition to the hash baseline)")
  .action(async (opts: { target?: string; since?: string; json?: boolean }) => {
    const { incrementalScopeCommand } = await import("./cli/incremental-scope.js");
    await incrementalScopeCommand(opts);
  });

cli
  .command(
    "setup [platform]",
    "Install the vigolium-audit harness into the agent config dir (claude → ~/.config/vigolium-audit/harness-claude, codex → ~/.codex/agents). Pass a platform or --agent <platform>; omit to install both. Persistent — removed by `vigolium-audit uninstall`.",
  )
  .action(async (platform: string | undefined, opts: { json?: boolean; agent?: string }) => {
    const { setupCommand } = await import("./cli/setup.js");
    await setupCommand(platform ?? opts.agent, { json: !!opts.json });
  });

cli
  .command(
    "uninstall [platform]",
    "Remove installed vigolium-audit harness state. Pass a platform (claude|codex) or --agent <platform>; omit to remove all. (`vigolium-audit run -i` already auto-cleans its own ephemeral install.)",
  )
  .action(async (platform: string | undefined, opts: { json?: boolean; agent?: string }) => {
    const { uninstallCommand } = await import("./cli/uninstall.js");
    await uninstallCommand(platform ?? opts.agent, { json: !!opts.json });
  });

cli
  .command("strip <path>", "Strip raw byproducts from a vigolium-results/ folder; keeps audit-state.json, findings/, findings-theoretical/, attack-surface/, and *.md reports. Also sweeps scanner scratch (*.sarif/*.bqrs/tmp) and redacts confirm-workspace secrets (drops DB snapshots; masks passwords/tokens/keys in JSON+logs). Pass either the project dir or vigolium-results/ itself.")
  .option("--keep-secrets", "Retain DB snapshots and skip scrubbing secrets from confirm-workspace JSON/logs (default: redacted). The junk sweep still runs.")
  .action(async (path: string, opts: { json?: boolean; keepSecrets?: boolean }) => {
    const { stripCommand } = await import("./cli/strip.js");
    await stripCommand(path, { json: !!opts.json, ...(opts.keepSecrets ? { keepSecrets: true } : {}) });
  });

cli
  .command("merge", "Consolidate two-or-more vigolium-results/ folders into one and normalize the result in a single pass: a deterministic collision-safe copy (findings + attack-surface + merge_metadata stamp), then the `run --mode merge` LLM pass that dedups by root cause, renumbers, and regenerates reports. Pass --premerge-only to stop after the deterministic step (no tokens).")
  .option("--dir <path>", "An audit output folder to merge (repeatable; pass at least two). Accepts a project dir or a vigolium-results/ dir.")
  .option("--output <dir>", "Write the merged result to <dir>/vigolium-results/ instead of merging into the first --dir in place (non-destructive to the sources).")
  .option("--force", "Allow merging into a non-empty --output destination.")
  .option("--premerge-only", "Stop after the deterministic consolidation; skip the LLM normalization pass (no tokens spent). Prints the `run --mode merge` follow-up command.")
  .option("--model <model>", "Model name forwarded to the normalization pass.")
  .option("--max-cost <usd>", "Hard cost cap in USD for the normalization pass; abort when exceeded.")
  .option("--strict", "Abort the normalization pass on first phase failure instead of skip-and-continue.")
  .option("--oauth-token <token>", "Set CLAUDE_CODE_OAUTH_TOKEN for the normalization pass.")
  .option("--oauth-cred-file <path>", "Override platform creds for the normalization pass; original is backed up + restored on exit.")
  .option("--api-key <key>", "Pass as platform API key env (claude → ANTHROPIC_API_KEY, codex → OPENAI_API_KEY) for the normalization pass.")
  .action(
    async (opts: {
      dir?: string | string[];
      output?: string;
      force?: boolean;
      premergeOnly?: boolean;
      agent?: AgentPlatform;
      model?: string;
      maxCost?: number;
      strict?: boolean;
      oauthToken?: string;
      oauthCredFile?: string;
      apiKey?: string;
      json?: boolean;
      debug?: boolean;
      streaming?: boolean;
    }) => {
      const { mergeCommand } = await import("./cli/merge.js");
      await mergeCommand(opts);
    },
  );

cli
  .command("status [path]", "Print a one-screen summary of the latest audit in a project's vigolium-results/ folder. Read-only.")
  .action(async (path: string | undefined, opts: { json?: boolean }) => {
    const { statusCommand } = await import("./cli/status.js");
    await statusCommand(path ?? ".", { json: !!opts.json });
  });

cli
  .command(
    "output-structure",
    "Print the canonical 'ideal' vigolium-results/ layout as a prompt-ready cleanup spec (the same delivery-oriented shape `vigolium-audit strip` produces). Hand it to another coding agent — along with a results folder — to normalize/clean up the output. Static; reads nothing. Use --markdown to pipe into an agent, --json for tooling.",
  )
  .alias("structure")
  .option("--markdown", "Emit raw markdown (for piping into another agent or `> spec.md`) instead of the colorized terminal summary.")
  .action(async (opts: { json?: boolean; markdown?: boolean }) => {
    const { outputStructureCommand } = await import("./cli/output-structure.js");
    await outputStructureCommand({ json: !!opts.json, ...(opts.markdown ? { markdown: true } : {}) });
  });

cli
  .command(
    "resume [path]",
    "Resume the latest non-complete audit in <path>/vigolium-results/. Auto-detects the audit's mode from audit-state.json and continues where it left off (in_progress > aborted > failed). Headless.",
  )
  .option("--strict", "Abort on first phase failure instead of skip-and-continue.")
  .option("--max-cost <usd>", "Hard cost cap in USD for this resume invocation.")
  .option("--output <dir>", "Mirror <path>/vigolium-results/ to <dir> after each phase.")
  .option("--oauth-token <token>", "Set CLAUDE_CODE_OAUTH_TOKEN for the subprocess / SDK")
  .option("--oauth-cred-file <path>", "Override platform creds for the run")
  .option("--api-key <key>", "Pass as platform API key env")
  .option("--strip-raw", "Strip raw scanner output and draft findings on success")
  .option("--keep-raw", "Keep raw scanner output and intermediate workspaces for manual review; overrides the deep/confirm auto-prune. Mutually exclusive with --strip-raw.")
  .option("--keep-secrets", "When cleanup runs, retain DB snapshots and skip scrubbing secrets from confirm-workspace JSON/logs (default: redacted).")
  .option("--serial", "Force serial phase execution")
  .option("--no-git", "Skip all git-related checks")
  .action(
    async (
      path: string | undefined,
      opts: {
        agent?: string;
        strict?: boolean;
        maxCost?: string;
        output?: string;
        oauthToken?: string;
        oauthCredFile?: string;
        apiKey?: string;
        stripRaw?: boolean;
        keepRaw?: boolean;
        keepSecrets?: boolean;
        serial?: boolean;
        git?: boolean;
        json?: boolean;
        debug?: boolean;
        streaming?: boolean;
      },
    ) => {
      const { resumeCommand } = await import("./cli/resume.js");
      await resumeCommand(path ?? ".", opts);
    },
  );

const confirmCmd = cli
  .command(
    "confirm [path]",
    "Boot the target and execute PoCs against a prior audit's findings. Curated entry point for `--mode confirm`; --mode/--modes/--baseline/--parallel-modes don't apply here.",
  )
  .option("--model <model>", "Model name forwarded to the agent runtime.")
  .option("-i, --interactive", "Enable Ink TUI (auto-disabled when stdout is not a TTY)")
  .option("--from-audit <id>", "Source audit id to confirm. Defaults to the latest completed audit in <path>/vigolium-results/.")
  .option("--live-target <url>", "HTTP(S) endpoint to verify findings against. Skips env discovery + provisioning and runs PoCs against this URL.")
  .option("--focus-file <path>", "Path to a free-form file describing areas to prioritize. Auto-inherits from prior audit when unset.")
  .option("--expected-behaviors-file <path>", "Path to a free-form file describing intentional behaviors that should NOT be flagged.")
  .option("--max-cost <usd>", "Hard cost cap in USD; abort when exceeded")
  .option("--strict", "Abort on first phase failure instead of skip-and-continue")
  .option("--output <dir>", "Mirror <path>/vigolium-results/ to <dir> after each phase.")
  .option("--oauth-token <token>", "Set CLAUDE_CODE_OAUTH_TOKEN for the subprocess / SDK")
  .option("--oauth-cred-file <path>", "Override platform creds for the run")
  .option("--api-key <key>", "Pass as platform API key env")
  .option("--strip-raw", "Strip raw scanner output and draft findings on success")
  .option("--keep-raw", "Keep raw scanner output and intermediate workspaces for manual review; overrides the deep/confirm auto-prune. Mutually exclusive with --strip-raw.")
  .option("--keep-secrets", "When cleanup runs, retain DB snapshots and skip scrubbing secrets from confirm-workspace JSON/logs (default: redacted).")
  .option("--dry-run", "Resolve and print the phase plan without invoking any adapter. No state file is written.")
  .option("--serial", "Force serial phase execution")
  .option("--resume", "Resume the latest non-complete confirm audit in <path>/vigolium-results/ instead of starting fresh.")
  .option("--from-results-dir <path>", "Seed the run from an existing vigolium-results/ output dir (clones the recorded repo at the recorded commit).")
  .option("--keep-clone", "With --from-results-dir: don't remove the temp clone on exit.")
  .option("--no-git", "Skip all git-related checks: treat the target as a plain directory.")
  .action(
    async (
      path: string | undefined,
      opts: {
        agent?: string;
        model?: string;
        interactive?: boolean;
        fromAudit?: string;
        liveTarget?: string;
        focusFile?: string;
        expectedBehaviorsFile?: string;
        maxCost?: string;
        strict?: boolean;
        output?: string;
        oauthToken?: string;
        oauthCredFile?: string;
        apiKey?: string;
        stripRaw?: boolean;
        keepRaw?: boolean;
        keepSecrets?: boolean;
        dryRun?: boolean;
        serial?: boolean;
        resume?: boolean;
        fromResultsDir?: string;
        keepClone?: boolean;
        git?: boolean;
        json?: boolean;
        debug?: boolean;
        streaming?: boolean;
      },
    ) => {
      const { confirmCommand } = await import("./cli/confirm.js");
      await confirmCommand(path ?? ".", opts);
    },
  );

const confirmSection = (s: string) => confirmCmd.example(chalk.blue(s));
const confirmEx = (comment: string, command: string) => {
  confirmCmd.example(`# ${comment}`);
  confirmCmd.example(`  ${command}`);
};
const confirmBlank = () => confirmCmd.example("");

confirmSection("# Quickstart");
confirmEx("confirm the latest completed audit in ./repo", "vigolium-audit confirm ./repo");
confirmEx("confirm against a live URL (skips env discovery + provisioning)", "vigolium-audit confirm ./repo --live-target https://staging.example.com");
confirmEx("pick a specific prior audit", "vigolium-audit confirm ./repo --from-audit a1b2c3d4");
confirmEx("cross-agent confirmation on codex", "vigolium-audit confirm ./repo --agent codex");
confirmBlank();

confirmSection("# Output cleanup");
confirmEx("default: confirm auto-prunes raw workspaces + redacts secrets on success", "vigolium-audit confirm ./repo");
confirmEx("keep raw workspaces for manual review (no prune, no redaction)", "vigolium-audit confirm ./repo --keep-raw");
confirmEx("prune + sweep junk but retain DB snapshots and confirm-workspace secrets", "vigolium-audit confirm ./repo --keep-secrets");
confirmBlank();

confirmSection("# Replay an archived results dir");
confirmEx("re-run confirm against an archived vigolium-results/ result (clone in /tmp, synced back on exit)", "vigolium-audit confirm --from-results-dir ./prior-audits/sentry");
confirmEx("retain the temp clone for inspection", "vigolium-audit confirm --from-results-dir ./prior-audits/sentry --keep-clone");

cli
  .command("list", "List available audit modes with their descriptions, phase count, and rough time estimate (observed median when available, phase-count baseline otherwise).")
  .option("--target <path>", "Project directory to read prior-run timings from (default: current)", { default: "." })
  .action(async (opts: { target?: string; json?: boolean }) => {
    const { listCommand } = await import("./cli/list.js");
    await listCommand({ target: opts.target ?? ".", json: !!opts.json });
  });

cli
  .command("usage", "Show Claude Code token usage + estimated $ from ~/.claude/projects/*.jsonl logs. Aggregates 24h / 7d / 30d / all-time. Estimates use Anthropic public pricing — subscription users don't pay these rates, treat as a relative-intensity gauge.")
  .option("--since <spec>", "Time window: 24h, 7d, 30d, 4w, 3m, or 'all' (default: all)", { default: "all" })
  .option("--refresh", "Send a tiny ping to Claude (claude-haiku, ~$0.0001) to harvest live `rate_limits` and refresh the on-disk quota cache. Subscription users only — API-key responses don't include this block.")
  .action(async (opts: { since?: string; json?: boolean; refresh?: boolean }) => {
    const { usageCommand } = await import("./cli/usage.js");
    await usageCommand({
      ...(opts.since !== undefined ? { since: opts.since } : {}),
      json: !!opts.json,
      ...(opts.refresh ? { refresh: true } : {}),
    });
  });

cli
  .command("explain <finding>", "Show a finding's report, producing phase/audit, and any quarantined raw artifacts. Read-only.")
  .option("--target <path>", "Project directory (default: current)", { default: "." })
  .action(async (finding: string, opts: { target?: string; json?: boolean }) => {
    const { explainCommand } = await import("./cli/explain.js");
    await explainCommand(finding, { targetDir: opts.target ?? ".", json: !!opts.json });
  });

cli
  .command("version", "Print version, build, and project metadata (same as `vigolium-audit --version`)")
  .action(() => {
    printVersionBlock();
  });

cli.version(pkg.version);

// Unknown subcommand (e.g. `vigolium-audit something wrong`). cac emits
// `command:*` when there's a positional arg but no command matched; without a
// listener it would exit silently. Guide the user to `vigolium-audit run` and exit non-zero.
cli.on("command:*", () => {
  printUnknownCommand(String(cli.args[0] ?? ""));
  process.exit(1);
});

// `vigolium-audit` with no subcommand and no flags → show help. cac would otherwise
// silently exit. Detected on raw argv (cac's parsed.args is empty for any run
// that has no positional args after the matched command — including
// `vigolium-audit run --mode lite`, which we definitely want to dispatch).
const userArgs = process.argv.slice(2);
if (userArgs.includes("--version") || userArgs.includes("-v")) {
  printVersionBlock();
  process.exit(0);
}
if (userArgs.length === 0) {
  cli.outputHelp();
} else {
  cli.parse();
}

// Edit distance for a "did you mean" hint on typo'd subcommands.
function editDistance(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i]![j] = Math.min(dp[i - 1]![j]! + 1, dp[i]![j - 1]! + 1, dp[i - 1]![j - 1]! + cost);
    }
  }
  return dp[a.length]![b.length]!;
}

function printUnknownCommand(name: string): void {
  const commands = cli.commands.map((c) => c.name).filter(Boolean);
  console.error(chalk.red(`error: unknown command '${name}'`));

  const suggestion = commands
    .map((c) => ({ c, d: editDistance(name, c) }))
    .filter(({ d }) => d <= 2)
    .sort((x, y) => x.d - y.d)[0];
  if (suggestion) console.error(chalk.yellow(`did you mean '${suggestion.c}'?`));

  console.error(chalk.blue("\nRun a security audit with `vigolium-audit run`:"));
  console.error("  vigolium-audit run --mode lite --target ./repo   " + chalk.gray("# fast 3-phase surface scan"));
  console.error("  vigolium-audit run --mode deep --target ./repo   " + chalk.gray("# full audit pipeline"));
  console.error("  vigolium-audit run --mode deep -i                " + chalk.gray("# interactive (auto-installs harness)"));

  console.error(`\n${chalk.bold("Available commands:")} ${commands.join(", ")}`);
  console.error(
    chalk.gray("\nSee `vigolium-audit --help` for all commands and examples, or `vigolium-audit list` for audit modes."),
  );
}

function printVersionBlock(): void {
  const lines = [
    `vigolium-audit - ${DESCRIPTION}`,
    `Version: v${pkg.version}`,
    `Build: ${BUILD_DATE}`,
    `Commit: ${COMMIT_HASH}`,
    `Author: ${AUTHOR}`,
    `Website: ${WEBSITE}`,
    `Docs: ${DOCS}`,
  ];
  for (const line of lines) console.log(line);
}
