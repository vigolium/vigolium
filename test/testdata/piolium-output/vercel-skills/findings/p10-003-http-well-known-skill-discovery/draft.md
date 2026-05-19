---
id: p10-003
phase: P10
source-draft: p4-003
slug: http-well-known-skill-discovery
severity: medium
verdict: VALID
debate: piolium/chamber-workspace/c03-well-known-discovery/debate.md
---

PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous

# Well-known skill discovery accepts cleartext HTTP sources

## Summary

The well-known provider accepts `http://` URLs and fetches `index.json`, `SKILL.md`, and auxiliary files over cleartext transport. A network attacker can modify skill instructions in transit and persist them into local agent skill directories.

## Location

- Classification: `src/source-parser.ts:396-415` treats non-GitHub/GitLab `http://` URLs as well-known.
- Provider match: `src/providers/wellknown.ts:63-85` accepts `http://` and `https://`.
- Fetch sinks: `src/providers/wellknown.ts:134`, `:271`, and `:294`.

## Attacker Control

A network attacker or malicious proxy controls cleartext HTTP responses after a victim/automation runs a well-known install command using `http://`.

## Trust Boundary Crossed

Unauthenticated network content becomes persistent `SKILL.md` and auxiliary files loaded by downstream AI agents.

## Impact

MITM-modified agent instructions can lead to later secret exfiltration, code tampering, or unsafe tool use by agents running in the developer's project context.

## Evidence

Stage 04 CodeQL P4-006 showed CLI URL input reaches well-known fetches. Semgrep matched HTTP acceptance in both source parsing and provider matching.

## Stage 10 Notes

Severity is normalized to MEDIUM because the victim must use an insecure URL, but there is no explicit opt-in/warning and `-y` flows can install noninteractively.

## Recommended Fix

Require HTTPS by default. Gate HTTP behind an explicit `--allow-insecure-http` flag, warn loudly, and disallow cleartext installs in noninteractive `-y` mode unless explicitly opted in.
