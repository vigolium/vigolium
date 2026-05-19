---
id: p10-010
phase: P10
source-draft: p8-002
slug: experimental-install-unlocked-node-modules-skills
severity: high
verdict: VALID
debate: piolium/chamber-workspace/c05-node-modules-restore/debate.md
---

# `experimental_install` installs unlisted node_modules skills when any node_modules lock entry exists

## Summary

`skills experimental_install` / `skills install` is described as restoring from `skills-lock.json`, but node_modules entries are handled by invoking the broad sync engine with `yes: true`. The locked node_modules names are used only as a boolean trigger, so restore installs every discovered dependency skill that is not already up to date, including skills absent from the lockfile.

## Location

- Lock read: `src/install.ts:17-20`.
- Node_modules entries collected: `src/install.ts:37-40`.
- Broad sync with confirmation disabled: `src/install.ts:78-84`.
- Full node_modules scan: `src/sync.ts:142`.
- Queues all not-up-to-date skills: `src/sync.ts:171-181`.
- Prompt skipped and install performed: `src/sync.ts:305-333`.

## Attacker Control

A malicious or compromised npm dependency controls a `SKILL.md` in `node_modules`. The project only needs one legitimate locked node_modules skill to trigger broad restore sync.

## Trust Boundary Crossed

Unreviewed dependency content crosses into persistent project agent skill directories during a command the user expects to restore the checked-in lockfile.

## Impact

A dependency can persist prompt/tool-use instructions into `.agents/skills` without being listed in `skills-lock.json` or approved by the normal sync prompt. Downstream agents may later read secrets, edit code, or run tools under those instructions.

## Evidence

Stage 08 proof `piolium/tmp/p8-proofs.test.ts:61-95` passed: a lockfile with only `some-locked-node-skill` caused `runInstallFromLock([])` to install `malicious-lock-bypass` from an unlisted package.

## Stage 10 Notes

The base `experimental_sync` behavior was dropped as an explicit feature, but this restore path is a distinct lock-scope bypass with noninteractive install. Severity normalized to HIGH.

## Recommended Fix

Do not call broad `runSync()` from restore. Pass an explicit allowlist of locked node_modules skill/package names, store package version/integrity, and keep confirmation enabled if any unlisted package skill is discovered.

## PoC Metadata

PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
