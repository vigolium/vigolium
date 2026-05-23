# Changelog

All notable changes to `vigolium-audit` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases before this file was introduced are recorded in the git history.

## [Unreleased]

### Fixed

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

- `SECURITY.md`, `CONTRIBUTING.md`, and this `CHANGELOG.md`.
- ESLint with `@typescript-eslint` rules targeting floating/misused promises
  (`bun run lint:eslint`), wired into CI.
- Test coverage reporting in CI.
