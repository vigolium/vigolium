---
id: p10-008
phase: P10
source-draft: p7-002
slug: agent-skill-name-constraints-not-enforced
severity: medium
verdict: VALID
debate: piolium/chamber-workspace/c04-skill-identity-and-snapshot/debate.md
---

## PoC Metadata

PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous

# Agent Skill `name` constraints are not enforced before deriving install directories

## Summary

The Agent Skills specification requires constrained lowercase names and parent-directory equality. The parser accepts any string `name`/`description` and the installer uses the frontmatter-controlled name after lossy sanitization to choose the install directory.

## Location

- `src/skills.ts:29-59` only type-checks and terminal-sanitizes `data.name`.
- `src/installer.ts:40-54` sanitizes arbitrary names rather than rejecting invalid ones.
- `src/installer.ts:245-247` derives the install directory from `skill.name || basename(skill.path)`.
- Well-known `src/providers/wellknown.ts:185-189` attempts a name regex but invalid multi-character names still pass.

## Attacker Control

A malicious skill author controls `SKILL.md` frontmatter, and for well-known sources also controls `index.json` entry names.

## Trust Boundary Crossed

Untrusted metadata controls the persistent skill namespace used by downstream agents and by future overwrite/update decisions.

## Impact

A malicious source can install under a trusted or colliding sanitized name that does not match its source directory, shadowing or overwriting existing skills and misleading users/agents about provenance.

## Evidence

Stage 07 compared the implementation with the Agent Skills reference validator and found missing length, character, consecutive-hyphen, leading/trailing-hyphen, and parent-directory equality checks. Stage 08 also noted the well-known regex fail-open bug.

## Stage 10 Notes

Path traversal is sanitized, but namespace/provenance confusion remains. Severity normalized to MEDIUM.

## Recommended Fix

Reject invalid skill names using the Agent Skills rules and require equality with `basename(dirname(SKILL.md))`. For well-known entries, fail closed on any regex mismatch.
