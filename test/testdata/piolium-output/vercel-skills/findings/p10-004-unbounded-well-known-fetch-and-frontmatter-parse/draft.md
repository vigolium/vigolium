---
id: p10-004
phase: P10
source-draft: p4-004
slug: unbounded-well-known-fetch-and-frontmatter-parse
severity: medium
verdict: VALID
debate: piolium/chamber-workspace/c03-well-known-discovery/debate.md
---
PoC-Status: executed
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous


# Well-known fetches and remote frontmatter parsing lack resource limits

## Summary

Well-known discovery performs attacker-controlled `fetch()` calls without explicit timeouts and reads/parses response bodies without byte, file-count, or YAML depth limits.

## Location

- Index fetch: `src/providers/wellknown.ts:134`.
- `SKILL.md` fetch/body read: `src/providers/wellknown.ts:271-278`.
- Auxiliary file fetch/body read: `src/providers/wellknown.ts:294-296`.
- YAML parse: `src/frontmatter.ts:12-15`.

## Attacker Control

A malicious well-known host controls response latency, response size, file count, and frontmatter content.

## Trust Boundary Crossed

Untrusted network content is loaded into memory and passed to the YAML parser in the local CLI/automation process.

## Impact

An attacker can hang installs or consume CPU/memory in noninteractive developer setup, CI bootstrap, or project restore flows.

## Evidence

Stage 04 CodeQL P4-013 showed `response.text()` reaching `parseYaml`. Semgrep flagged missing well-known fetch timeouts and frontmatter parsing without size limits.

## Stage 10 Notes

Exceptions are usually caught, so this is an availability issue; severity remains MEDIUM for automation/CI DoS.

## Recommended Fix

Use `AbortSignal.timeout()` for all well-known fetches, cap response bytes and index/file counts, and reject overly large/deep frontmatter before regex/YAML parsing.
