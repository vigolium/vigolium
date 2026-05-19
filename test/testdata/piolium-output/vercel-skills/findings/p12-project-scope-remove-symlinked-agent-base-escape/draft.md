---
id: p12
slug: project-scope-remove-symlinked-agent-base-escape
severity: info
---

Phase: 12
Sequence: 003
Slug: project-scope-remove-symlinked-agent-base-escape
Verdict: VALID
Rationale: The project/global symlink-base escape found in install writes also exists in project-scoped removal, where computed project paths are recursively deleted after following symlinked agent base directories.
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
Origin-Finding: piolium/findings-draft/p10-009-project-scope-symlinked-agent-base-escape.md
Origin-Pattern: AP-003

## Summary

`skills remove` uses the same project-relative agent base paths as install but does not resolve those bases with `realpath()` before scanning and deleting. If a project checkout contains `.agents` or another agent skills parent as a symlink to an outside directory, a project-scoped remove can delete skills outside the project while the command is operating in project scope.

## Location

- `src/remove.ts:42-51` scans project-scope canonical and agent-specific directories under `cwd`.
- `src/remove.ts:157-180` computes cleanup paths using `getInstallPath()`/agent directories and calls `rm(pathToCleanup, { recursive: true, force: true })`.
- `src/remove.ts:196-207` removes the canonical path with `rm(canonicalPath, { recursive: true, force: true })`.
- `src/installer.ts:63-67`, `src/installer.ts:82-86`, and `src/installer.ts:423-437` perform only lexical containment/sanitization for these project paths.

## Attacker Control

A malicious project repository can contain a symlinked agent base such as `.agents -> ../outside` or `.agents -> ~/.agents`. The victim then runs `skills remove`, especially `skills remove --all -y`, from that checkout.

## Trust Boundary Crossed

A project-scoped destructive operation crosses out of the current project and operates on the symlink target's skill directories.

## Impact

The command can delete global or shared agent skills outside the repository, disrupting other projects and removing persistent agent instructions or guardrail skills the user did not intend to touch.

## Evidence

- `piolium/tmp/p12-variant-proofs-output.txt` includes `project-remove-follows-symlinked-agents-base`; after creating `project/.agents` as a symlink to `outside`, running `removeCommand(['victim-skill'], { yes: true, global: false })` left `outsideStillExists: false`.
- P12 grep results (`piolium/tmp/p12-registry-grep.txt`) show the shared lexical `isPathSafe()` helper in `src/installer.ts`; `piolium/codeql-artifacts/sinks.json` lists recursive remove sinks in `src/remove.ts`, and `removeCommand()` performs no realpath containment check before those `rm()` calls.

## Reproduction Steps

1. Create `outside/skills/victim-skill/SKILL.md` and a project directory with `.agents` symlinked to `outside`.
2. Run the CLI's project-scoped remove path from the project, selecting `victim-skill` with `--yes` (or `--all -y`).
3. Observe that `outside/skills/victim-skill` is removed even though the operation was project-scoped.
