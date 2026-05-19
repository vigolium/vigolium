---
id: p10-009
phase: P10
source-draft: p8-001
slug: project-scope-symlinked-agent-base-escape
severity: high
verdict: VALID
debate: piolium/chamber-workspace/c02-filesystem-symlink-boundaries/debate.md
---

PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous

# Project-scoped installs follow symlinked agent bases outside the project

## Summary

Project-scoped installs are presented as writing into the current project, but target containment is checked lexically. If a project checkout contains `.agents` or another agent skill-base parent as a symlink, the installer follows it and writes/deletes outside the project while `global: false`.

## Location

- Lexical safety check: `src/installer.ts:63-67`.
- Project canonical base: `src/installer.ts:84-86` returns `join(cwd, '.agents', 'skills')`.
- Destructive/write operations: `src/installer.ts:125-130`, `src/installer.ts:281-292`, `src/installer.ts:617-652`, `src/installer.ts:754-785`.

## Attacker Control

A malicious project repository or checkout can contain a symlinked `.agents` parent (for example `.agents -> ../.agents`). The victim then runs a project-scoped install or lock restore from that checkout.

## Trust Boundary Crossed

Project-local install scope crosses into external/global/shared agent skill directories via symlinked parents.

## Impact

A malicious project can persist or overwrite agent skills outside the project, including global `~/.agents/skills` when the symlink target is predictable. Later agent sessions in other projects may load the malicious instructions.

## Evidence

Stage 08 proof `piolium/tmp/p8-proofs.test.ts:35-58` passed: it symlinked `project/.agents` to an outside directory, called `installBlobSkillForAgent(..., global:false)`, and observed `outside/skills/shadow-scope/SKILL.md` was written.

## Stage 10 Notes

OS permissions still apply, but the project/global security boundary is bypassed. Severity normalized to HIGH.

## Recommended Fix

Resolve and validate real paths of install bases and targets before `rm()`, `mkdir()`, `writeFile()`, or `cp()`. Reject symlinked project agent bases that escape `realpath(cwd)` unless explicitly opted in.
