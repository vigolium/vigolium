---
id: p10-002
phase: P10
source-draft: p4-002
slug: symlink-dereference-copies-out-of-tree-files
severity: high
verdict: VALID
debate: piolium/chamber-workspace/c02-filesystem-symlink-boundaries/debate.md
---
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous


# Recursive install copy dereferences untrusted skill symlinks

## Summary

When installing a skill from a cloned/local tree, `copyDirectory()` follows symlinks with `dereference: true`. A malicious repository can include symlinks to files outside the skill tree, causing local readable files to be copied into `.agents/skills/<skill>` or global agent skill directories.

## Location

- Install path: `src/add.ts` selected skills -> `installSkillForAgent()`.
- Copy sink: `src/installer.ts:349-369` calls `cp(srcPath, destPath, { dereference: true, recursive: true })` for non-directory entries.

## Attacker Control

A malicious remote git/local skill source controls filesystem entries inside the skill directory, including symlinks committed to the repository.

## Trust Boundary Crossed

Untrusted repository contents cause the installer to read from local filesystem paths outside the repository/skill boundary and materialize those bytes into agent-consumed skill directories.

## Impact

Sensitive local files at predictable paths can be copied into project/global skill directories where downstream agents, accidental commits, backups, or later tooling may expose them. This can bypass agents that would otherwise only read project/skill directories.

## Evidence

- Stage 02 proof `piolium/tmp/stage02-symlink-copy.test.ts` passed and demonstrated live source symlinks are dereferenced and copied.
- `copyDirectory()` has no `realpath(srcPath)` containment check against the original skill root before copying.
- Broken symlink handling only skips `ENOENT`; valid external symlink targets are copied.

## Stage 10 Notes

Devil's Advocate noted the CLI itself does not upload the file, but no blocking protection prevents local file disclosure into agent/project-controlled directories. Severity normalized to HIGH.

## Recommended Fix

Reject symlinks in untrusted skill trees, or copy only after verifying `realpath(srcPath)` remains under `realpath(skillRoot)`. Consider preserving safe in-tree symlinks rather than dereferencing external targets.
