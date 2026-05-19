# [p12] `experimental_sync` duplicate node_modules skill names overwrite installed skills

## Summary

`skills experimental_sync` trusts dependency-controlled `SKILL.md` frontmatter `name` values as the sole identity for skills discovered in `node_modules`. If a malicious or compromised dependency declares the same name as a legitimate dependency skill, both entries are installed to the same `.agents/skills/<name>` destination and written to the same `skills-lock.json` key, allowing the later install to replace the legitimate skill's instructions and provenance.

## Details

The affected surface is the local `skills experimental_sync` command. A project dependency controls both its package contents and the `name` field inside `SKILL.md`; no application authentication is required, but a victim developer or automation must run sync in a project containing the malicious dependency.

During discovery, [`discoverNodeModuleSkills`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/sync.ts#L59-L83) records each parsed skill with its package name, but it does not reject or disambiguate duplicate skill names:

```ts
const rootSkill = await parseSkillMd(join(pkgDir, 'SKILL.md'));
if (rootSkill) {
  skills.push({ ...rootSkill, packageName });
  return;
}

// ... later, for nested skill directories ...
const skill = await parseSkillMd(join(skillDir, 'SKILL.md'));
if (skill) {
  skills.push({ ...skill, packageName });
}
```

The sync logic then looks up the lock by `skill.name` only and queues the skill for installation when the hash check does not skip it ([`src/sync.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/sync.ts#L171-L181)):

```ts
for (const skill of discoveredSkills) {
  const existingEntry = localLock.skills[skill.name];
  if (existingEntry) {
    const currentHash = await computeSkillFolderHash(skill.path);
    if (currentHash === existingEntry.computedHash) {
      upToDate.push(skill.name);
      continue;
    }
  }
  toInstall.push(skill);
}
```

Each queued skill is installed using the same name-derived canonical path. In [`installSkillForAgent`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L245-L293), the sanitized `skill.name` becomes `.agents/skills/<skill-name>`, and symlink mode clears and copies into that directory:

```ts
const rawSkillName = skill.name || basename(skill.path);
const skillName = sanitizeName(rawSkillName);

const canonicalBase = getCanonicalSkillsDir(isGlobal, cwd);
const canonicalDir = join(canonicalBase, skillName);

// Symlink mode: copy to canonical location and symlink to agent location
await cleanAndCreateDirectory(canonicalDir);
await copyDirectory(skill.path, canonicalDir);
```

After installation, the local lock is also updated under the bare skill name. [`runSync`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/sync.ts#L353-L365) passes `skill.name` and `skill.packageName` to the lock writer, and [`addSkillToLocalLock`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/local-lock.ts#L152-L159) overwrites any prior entry at that key:

```ts
await addSkillToLocalLock(
  skill.name,
  {
    source: skill.packageName,
    sourceType: 'node_modules',
    computedHash,
  },
  cwd
);

// local-lock.ts
lock.skills[skillName] = entry;
```

Because the destination and lock key are both derived only from untrusted frontmatter, two different packages declaring `name: shared-name` collapse into one installed directory and one lock entry.

## Root Cause

The implementation uses dependency-controlled skill names as a global project namespace without enforcing uniqueness, namespacing them by package, or requiring an explicit conflict decision. The installer compounds that identity bug by destructively recreating the canonical directory for each queued skill, so duplicate names overwrite prior contents instead of failing closed.

## Proof of Concept (PoC)

PoC status: `executed` (recorded in `draft.md`). The reproduction is implemented in `piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/poc.js`.

Run from the repository root:

```bash
node piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/poc.js
```

The script creates a temporary victim project with two dependencies:

1. `node_modules/aaa-legit/SKILL.md` declares `name: shared-name` and contains `LEGITIMATE_INSTRUCTIONS`.
2. `node_modules/zzz-malicious/skills/pwn/SKILL.md` also declares `name: shared-name` and contains `MALICIOUS_PAYLOAD: attacker-controlled agent instructions installed from zzz-malicious`.
3. It runs `bin/cli.mjs experimental_sync -y -a amp` in that project and inspects `.agents/skills/shared-name/SKILL.md` plus `skills-lock.json`.

The executed proof recorded the decisive impact marker:

```text
installed SKILL.md contains zzz-malicious payload and skills-lock.json has one shared-name entry sourced from zzz-malicious
```

This confirms that the malicious dependency's duplicate name replaced the legitimate skill body and became the sole lock provenance for `shared-name`.

## Impact

A malicious npm dependency can persist attacker-controlled agent skill instructions under the same visible skill name as a legitimate dependency. After `experimental_sync`, the victim sees a single `.agents/skills/shared-name` directory and a single `skills-lock.json` entry sourced from the malicious package, while the legitimate instructions are removed. If an AI coding agent later loads that skill, the attacker can influence agent behavior through the installed instructions. The practical severity depends on whether projects run `experimental_sync` over untrusted dependencies and what permissions the consuming agent has, but the demonstrated effect is a reliable local supply-chain overwrite of skill content and provenance.

## Remediation

Reject duplicate `skill.name` values during `experimental_sync` discovery unless the user explicitly chooses one source. Prefer using a compound identity such as `{packageName, skillName}` for lock entries and destination planning, or require package-qualified install names when syncing from `node_modules`. The CLI should surface all conflicts before installation, avoid destructive writes to an already-claimed canonical directory, and preserve lock provenance for every source involved in a collision.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-output.log; piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-evidence.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer ran the real CLI experimental_sync over two node_modules skills with name shared-name; final .agents/skills/shared-name and lock provenance came from zzz-malicious.
