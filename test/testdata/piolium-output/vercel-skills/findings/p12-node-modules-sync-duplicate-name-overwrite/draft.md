---
id: p12
slug: node-modules-sync-duplicate-name-overwrite
severity: info
---

Phase: 12
Sequence: 004
Slug: node-modules-sync-duplicate-name-overwrite
Verdict: VALID
Rationale: The duplicate-name identity bug also appears in `experimental_sync`, where dependency-controlled skill names are neither rejected nor disambiguated and later packages overwrite the same install and lock entry.
Severity-Original: MEDIUM
PoC-Status: executed
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
Origin-Finding: piolium/findings-draft/p10-005-duplicate-skill-name-first-wins.md
Origin-Pattern: AP-006

## Summary

`experimental_sync` discovers skills from every package in `node_modules` and identifies them only by frontmatter `name`. If two packages provide the same `name`, both are queued for the same `.agents/skills/<sanitized-name>` destination, the later install overwrites the earlier one, and `skills-lock.json` stores only one entry for that shared name.

## Location

- `src/sync.ts:45-77` pushes every parsed package skill into `discoveredSkills` without duplicate-name rejection.
- `src/sync.ts:171-181` checks `localLock.skills[skill.name]`, using only the untrusted frontmatter name as identity.
- `src/sync.ts:324-333` installs every queued skill to the same sanitized canonical destination through `installSkillForAgent()`.
- `src/local-lock.ts:149-155` writes lock entries as `lock.skills[skillName] = entry`, so duplicate names overwrite prior package provenance.

## Attacker Control

A malicious or compromised npm dependency controls its `SKILL.md` frontmatter `name` and can choose the same name as a legitimate package skill in the same project.

## Trust Boundary Crossed

Untrusted dependency metadata controls the persistent project agent skill namespace and lock provenance.

## Impact

A malicious dependency can shadow a legitimate dependency's skill under the same name during sync. The final installed instructions and lock source can point to the malicious package while CLI output collapses results by name, making the overwrite easy to miss.

## Evidence

- `piolium/tmp/p12-variant-proofs-output.txt` includes `node-modules-sync-duplicate-name-single-install-and-lock-entry`: two packages (`aaa-legit` and `zzz-malicious`) both declared `name: shared-name`; after `runSync(..., { yes: true })`, the installed `SKILL.md` contained the malicious body and `skills-lock.json` contained a single `shared-name` entry with `source: "zzz-malicious"`.
- The sync output in the same proof showed both duplicate names queued for `./.agents/skills/shared-name`, then summarized only one synced skill by name.

## Reproduction Steps

1. Create `node_modules/aaa-legit/SKILL.md` and `node_modules/zzz-malicious/SKILL.md` with identical frontmatter `name: shared-name` but different bodies.
2. Run `skills experimental_sync -y` in the project.
3. Inspect `.agents/skills/shared-name/SKILL.md` and `skills-lock.json`; only one name survives, with the later package's content/provenance.
