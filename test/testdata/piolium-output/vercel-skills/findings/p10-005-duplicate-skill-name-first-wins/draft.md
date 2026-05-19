---
id: p10-005
phase: P10
source-draft: p4-005
slug: duplicate-skill-name-first-wins
severity: medium
verdict: VALID
debate: piolium/chamber-workspace/c04-skill-identity-and-snapshot/debate.md
---

PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous

# Duplicate skill names are silently first-wins

## Summary

Skill discovery deduplicates by untrusted frontmatter `name` and silently keeps the first discovered path. Duplicate names are not rejected or shown to the user, enabling namespace shadowing in multi-skill catalogs.

## Location

- Discovery state: `src/skills.ts:108-109` initializes `seenNames`.
- Priority-directory dedupe: `src/skills.ts:192-199` only pushes when `!seenNames.has(skill.name)`.
- Recursive dedupe: `src/skills.ts:213-219` applies the same first-wins behavior.

## Attacker Control

A malicious skill author or PR contributor controls `SKILL.md` frontmatter names in a repository or catalog consumed by `skills add`.

## Trust Boundary Crossed

Untrusted metadata controls which skill implementation is offered/installed under a trusted name.

## Impact

A malicious skill can shadow a legitimate skill with the same name, weakening review and provenance for agent instructions that may later access secrets or modify code.

## Evidence

Stage 01 found an open first-party namespace-squatting issue (#353). Stage 04 Semgrep matched the first-wins dedupe sites. No later chamber evidence found a duplicate-name rejection path.

## Stage 10 Notes

This is not a path traversal bug; it is an identity/provenance bug. Severity normalized to MEDIUM.

## Recommended Fix

Reject duplicate names by default, or show every duplicate path and require an explicit path-scoped selection. Lock installed skills by name plus canonical source path/hash.
