---
id: p10-007
phase: P10
source-draft: p7-001
slug: rfc8615-path-relative-well-known-shadowing
severity: medium
verdict: VALID
debate: piolium/chamber-workspace/c03-well-known-discovery/debate.md
---

PoC-Status: executed
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous


# Path-relative `.well-known` discovery shadows origin-root RFC 8615 metadata

## Summary

RFC 8615 defines well-known URIs at the origin root, but the provider tries `{requested-path}/.well-known/...` before `/.well-known/...`. A path-level writer on a shared/trusted origin can shadow origin-wide skills for users who install from that path.

## Location

`src/providers/wellknown.ts:101-129` builds path-relative URLs first, then root URLs. `src/providers/wellknown.ts:132-158` returns the first valid index.

## Attacker Control

An attacker with write access to a path such as `https://trusted.example/users/evil/` controls the path-local `.well-known` files.

## Trust Boundary Crossed

Path-scoped content is treated as well-known skill metadata for the broader trusted origin.

## Impact

Victims can install attacker-controlled agent instructions under a trusted hostname's apparent well-known namespace, even when the origin root publishes different vetted metadata.

## Evidence

Stage 07 cited RFC 8615 §3 and §4.1 root semantics and mapped them to the provider URL order. Stage 10 found no prompt or display that clearly distinguishes path-scoped extension trust from origin-wide well-known metadata.

## Stage 10 Notes

Severity normalized to MEDIUM because exploitation requires a shared-origin/path-control setup and user invocation of the attacker's path.

## Recommended Fix

Use origin-root well-known URLs for RFC 8615 discovery. If path-scoped discovery remains as a custom extension, require explicit opt-in and display the exact resolved index URL and trust scope.
