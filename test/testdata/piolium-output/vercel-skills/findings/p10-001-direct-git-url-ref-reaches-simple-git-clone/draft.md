---
id: p10-001
phase: P10
source-draft: p4-001
slug: direct-git-url-ref-reaches-simple-git-clone
severity: high
verdict: VALID
debate: piolium/chamber-workspace/c01-git-and-lock-command/debate.md
---
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous


# Direct git URL/ref reaches vulnerable simple-git clone boundary

## Summary

CLI-controlled git sources and refs reach `simpleGit().clone()` without a first-party scheme/ref allowlist. The bundled lockfile resolves `simple-git` to `3.30.0`, which Stage 01 identified as affected by active 2026 command/protocol bypass advisories fixed in `>=3.32.3`.

## Location

- Source: `src/add.ts:895-942` (`runAdd(args)` parses the user `source`).
- Parser: `src/source-parser.ts:220-386` accepts GitHub/GitLab/direct-git inputs and falls back to `{ type: 'git', url: input }`.
- Sink: `src/git.ts:25-62` passes `url` and optional `['--branch', ref]` to `git.clone(url, tempDir, cloneOptions)`.
- Dependency: `pnpm-lock.yaml` resolves `simple-git@3.30.0`.

## Attacker Control

A malicious skill publisher controls the copied `skills add <source>#<ref>` command, or can influence a lock-derived source that later re-enters the same add path.

## Trust Boundary Crossed

Untrusted CLI/lock input crosses into a native git subprocess running with the developer/CI user's credentials and environment.

## Impact

A successful simple-git/git argument or protocol bypass can execute commands on the developer workstation or CI runner and expose repository credentials, environment tokens, and project files.

## Evidence

- Stage 04 CodeQL paths P4-001/P4-002 show `process.argv`/`runAdd` source and ref reaching `git.clone`.
- `src/git.ts` inherits `process.env` and only disables terminal prompts/LFS; it does not allowlist URL schemes, block dangerous git protocols, or validate refs before `simple-git`.
- Stage 01 advisory inventory records `simple-git@3.30.0` as affected by GHSA-r275-fr43-pm7q / CVE-2026-28292 and GHSA-jcxm-m3jx-f287 / CVE-2026-28291.

## Stage 10 Notes

Devil's Advocate found no blocking protection beyond timeout/prompt disabling. Severity is HIGH, not CRITICAL, because exploitation requires a victim/automation to invoke the local CLI.

## Recommended Fix

Upgrade `simple-git` to a fixed version and add first-party URL/ref validation before `cloneRepo()`: allowlist safe schemes/hosts, reject `ext::`, `file://`, config/protocol override syntax, control characters, and refs beginning with `-`.
