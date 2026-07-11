# Changelog

All notable changes to `vigolium-audit` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases before this file was introduced are recorded in the git history.

## [0.1.16-alpha]

### Added

- **Bridge protocol hardening (v1).** The `bridge serve` daemon now advertises a
  `protocolVersion` and validates every wire request against a schema before
  dispatch, so a malformed line (wrong field type, `null`, an array, an unknown
  method) becomes a structured `{ kind:"error", code:"invalid_request" }` instead
  of crashing. Terminal errors carry stable codes (`invalid_request`,
  `queue_full`, `deadline_exceeded`, `internal_error`) and a `retryable` flag.
- **Bounded daemon scheduler.** Concurrency is capped
  (`VIGOLIUM_AUDIT_BRIDGE_MAX_CONCURRENT`, default 4); excess runs queue up to
  `…_MAX_QUEUED` (default 64) and emit a `queued` event with position, beyond
  which new runs are rejected as `queue_full`. Per-run wall-clock deadlines are
  supported via `params.timeoutMs` / `…_BRIDGE_TIMEOUT_MS`.
- **Least-privilege task profiles.** Bridge tasks declare a `permission` profile
  (`read-only` / `workspace-write` / `full-access`) and `network` scope; `plan`
  and `triage` now run read-only (Codex OS sandbox + Claude write-tool deny-list)
  instead of full access, `exploit` runs workspace-write, and `run` stays
  full-access. Override per request/flag with `--permission` / `--network`.
- **Transient-failure retry in the bridge.** A cold 429/5xx/stream-idle failure
  or quota limit is now retried with the shared backoff policy (was a single
  attempt); usage is accumulated across attempts and surfaced as `attempts`.
  Retries are skipped once output has streamed so a half-run exploit/replay is
  never re-fired.

### Changed

- **Bridge result splits the overloaded `ok`.** `BridgeRunResult` now exposes
  `transportOk` (the run executed) and `contractOk` (`output:"json"` validated —
  `null` for text) alongside the compatibility `ok`, so a caller can tell a
  runtime failure apart from malformed output apart from a valid negative verdict.
- **Honest bridge skill inventory.** `ready`/`accepted` now announce the skill
  set that actually loads (including the always-on `vigolium-scanner`; empty on
  Codex) and a separate `requestedSkills`, rather than a set that excluded the
  scanner.
- **Bridge cancel is a single terminal.** Cancelling a run now emits exactly one
  `cancelled` message (no separate `cancelled` ack + later `result`); every
  accepted run produces exactly one terminal (`result` / `cancelled` / `error`).
  The daemon flushes `bye` before exit so a piped consumer isn't truncated.
- **Bridge system prompt marks inputs untrusted.** Task input, repo contents,
  HTTP traffic, and tool output are now explicitly framed as untrusted data that
  cannot override the task (prompt-injection guard).

### Fixed

- Clean audits with zero draft findings now still emit an empty consolidation
  manifest, allowing artifact-gated Lite, Balanced, and Deep runs to complete.
- Fresh core audits no longer satisfy completion gates with untouched artifacts
  left by an older run. Prior phase-owned outputs move to a reversible pre-run
  archive, while resume still accepts artifacts from its original start.

- Codex interactive runs now reject modes without an `AGENTS.md` dispatch
  (`diff`, `merge`, `reinvest`, and `longshot`) instead of silently falling
  through to a balanced audit; those modes remain available through the
  headless phase orchestrator.
- Managed audit helpers now mount at
  `~/.config/vigolium-audit/runtime-skills/`, leaving the documented
  `~/.config/vigolium-audit/skills/` override tree untouched. Legacy managed
  links are migrated conservatively, and ephemeral/uninstall cleanup removes
  the runtime link once no harness still uses it.
- Codex persisted-session tailing is strictly best effort: a missing,
  unreadable, or concurrently rotated JSONL file can no longer turn a
  successful SDK turn into an error or suppress its finish event.
- Codex `AGENTS.md` migration and uninstall preserve user-authored blank-line
  runs outside vigolium-audit's managed marker block.
- **`--max-cost` no longer silently disables the budget cap.** A non-numeric or
  non-positive value (e.g. `--max-cost abc`, `--max-cost 0`) now fails fast with
  a clear error instead of coercing to `NaN` and leaving the audit uncapped.
  Validation is shared across `run`, `confirm`, and `resume`.
- **CLI adapters always tear down their subprocess.** `claude-cli` and
  `codex-cli` now kill the child process (SIGTERM, escalating to SIGKILL),
  remove the abort listener, and stop the Codex session-tail poller even when
  the consumer abandons the event stream early or a phase throws mid-stream —
  closing a process/timer leak.
- **`audit-state.json` writes leave no orphaned staging files.** `atomicWrite`
  uses a unique staging suffix and cleans up on failure; a `StateStore` sweeps
  any staging files left by a previous crash before its first write.
- **Forward-incompatible state files fail with an actionable message.** A
  `audit-state.json` written by a newer schema version now reports "upgrade
  vigolium-audit" instead of a cryptic schema-mismatch error.
- Cost-warning and finding-discovered event emissions can no longer surface as
  unhandled promise rejections if a listener throws.
- The flaky harness install tests now have explicit timeouts, so they no longer
  intermittently fail under CI load.

### Changed

- Lite, Balanced, and Deep handoffs now use engine-owned audit state,
  deterministic finding consolidation, and confirmed/theoretical report gates.
- Codex deep dispatch now includes the full Deep Probe role set and follows the
  same consolidation, PoC partitioning, and two-bucket finalization contract as
  the canonical phase graph.

- Codex headless `--transport auto` now prefers the Codex Agent SDK, including
  ambient `codex login` / ChatGPT subscription auth. `--transport sdk|cli`
  selects a path explicitly, and `verify codex --transport both` probes both.
- Codex interactive audits now submit the canonical mode trigger (for example,
  `Full deep mode`) at TUI startup instead of requiring a second manual prompt.
- Upgraded `@openai/codex-sdk` and its bundled Codex CLI to `0.144.1`.
- The handoff status poller bounds each tick with a timeout, so a slow or stuck
  filesystem read can't freeze the live progress view for the whole audit.
- Per-failure draft quarantine reuses the phase IDs parsed at run start instead
  of re-reading and re-parsing the command YAML on every failed phase.
- On-disk state migrations now live behind a single `migrateAuditState` seam in
  `src/engine/state.ts`.
- **Internal decomposition (no behavior change).** Split the three largest files
  into focused modules:
  - The duplicated claude/codex handoff drivers now share a `BaseHandoff`
    skeleton (`src/engine/base-handoff.ts`); each subclass keeps only its
    trigger and retry policy.
  - `src/engine/orchestrator.ts` (1226 → 800 lines) extracted into
    `checkpoint.ts`, `findings.ts`, `strip-artifacts.ts`, and `prompts.ts`.
  - `src/cli/run.ts` (1868 → 1107 lines) extracted into `run-models.ts`,
    `run-interactive.ts`, and `run-render.ts` (the presentation layer).

### Added

- Executable per-phase completion contracts with safe path validation, bounded
  artifact-only repair, resume revalidation, advisory gates, and manifest-aware
  per-finding report checks.
- Trusted, label-based confirmation cleanup that ignores shell command strings
  and only terminates processes stamped for the active confirmation session.

- Codex SDK thread resume via `resumeThread()`, one-shot API-key forwarding,
  and persisted-session subagent lifecycle events matching the CLI adapter.
- Codex dry-run output now identifies the real single `codex-handoff` and its
  `AGENTS.md` dispatch source. Revisit's `assumption-breaker` and
  `independent-verifier` agents are included in the Codex harness roster.
- `SECURITY.md`, `CONTRIBUTING.md`, and this `CHANGELOG.md`.
- ESLint with `@typescript-eslint` rules targeting floating/misused promises
  (`bun run lint:eslint`), wired into CI.
- Test coverage reporting in CI.
