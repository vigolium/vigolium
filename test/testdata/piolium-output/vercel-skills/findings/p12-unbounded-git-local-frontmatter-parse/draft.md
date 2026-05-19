---
id: p12
slug: unbounded-git-local-frontmatter-parse
severity: info
---

Phase: 12
Sequence: 002
Slug: unbounded-git-local-frontmatter-parse
Verdict: VALID
Rationale: The unbounded frontmatter parser used by well-known installs is also reached by attacker-controlled `SKILL.md` files from cloned git sources, local paths, and node_modules sync.
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
Origin-Finding: piolium/findings-draft/p10-004-unbounded-well-known-fetch-and-frontmatter-parse.md
Origin-Pattern: AP-005

## Summary

`parseSkillMd()` reads an entire `SKILL.md` file and passes it directly to `parseFrontmatter()` without byte, YAML-depth, or parser resource limits. Unlike the original well-known finding's HTTP transport, this variant is reached through remote git clones, local path installs, and `experimental_sync` over `node_modules` packages.

## Location

- `src/skills.ts:29-35` reads `SKILL.md` with `readFile(..., 'utf-8')` and calls `parseFrontmatter(content)`.
- `src/frontmatter.ts:8-15` applies an unbounded frontmatter regex and `parseYaml(match[1]!)`.
- `src/add.ts:1041-1056` clones remote git/GitHub/GitLab sources and calls `discoverSkills()`, which reaches `parseSkillMd()`.
- `src/sync.ts:45-77` discovers package skills from `node_modules` and also calls `parseSkillMd()`.

## Attacker Control

A malicious git repository, local project checkout, or npm dependency can supply a very large or deeply nested YAML frontmatter block in `SKILL.md`.

## Trust Boundary Crossed

Untrusted repository/package file contents are loaded into memory and parsed by the local CLI process during install, update, restore, or sync.

## Impact

An attacker can consume memory/CPU or crash/hang noninteractive developer setup and CI/bootstrap flows that install or sync skills from untrusted repositories or packages.

## Evidence

- CodeQL P12 structural output (`piolium/tmp/p12-codeql-variant-structures.json`) includes a `frontmatter-parse` match at `src/skills.ts:35` and the original well-known parse at `src/providers/wellknown.ts:278`.
- The P12 Semgrep scan (`piolium/tmp/p12-semgrep-registry.json`) matched `parseFrontmatter` in both `src/skills.ts:35` and `src/providers/wellknown.ts:278`, confirming the same parser sink across alternate transports.
- The Stage 03 knowledge base DFD-01 models malicious remote repositories as controlling `SKILL.md` metadata that reaches the YAML parser.

## Reproduction Steps

1. Create a repository or package with `SKILL.md` containing a large YAML frontmatter document between `---` delimiters.
2. Run `skills add <repo>` or `skills experimental_sync` for a project containing the package.
3. Observe `parseSkillMd()` read the full file and call `parseFrontmatter()` with no size/depth guard before any per-file rejection can occur.
