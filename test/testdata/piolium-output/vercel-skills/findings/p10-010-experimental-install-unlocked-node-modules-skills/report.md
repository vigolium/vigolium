# [p10-010] `experimental_install` installs unlisted `node_modules` skills during lockfile restore

**Severity:** High  
**Vulnerability class:** lockfile scope bypass / untrusted dependency skill installation  
**PoC status:** executed

## Summary

`skills experimental_install` is intended to restore project skills from `skills-lock.json`, but the `node_modules` restore path treats the locked `node_modules` skill names only as a trigger. If the lockfile contains any legitimate `node_modules` skill, the command runs the broad `experimental_sync` engine with confirmations disabled, causing every discovered dependency-provided `SKILL.md` that is not already up to date to be installed into the project `.agents/skills` directory, even when that skill is absent from `skills-lock.json`.

## Details

The restore implementation reads `skills-lock.json` and separates entries by source type in [`runInstallFromLock`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/install.ts#L17-L84). For remote sources it scopes installation to the locked skill names, but for `node_modules` sources it only records the names in `nodeModuleSkills` and then calls `runSync` with `yes: true`:

```ts
// Separate node_modules skills from remote skills
const nodeModuleSkills: string[] = [];
const bySource = new Map<string, { sourceType: string; skills: string[] }>();

for (const [skillName, entry] of skillEntries) {
  if (entry.sourceType === 'node_modules') {
    nodeModuleSkills.push(skillName);
    continue;
  }

  // remote skills remain scoped by name/source here
}

// Handle node_modules skills via sync
if (nodeModuleSkills.length > 0) {
  const { options: syncOptions } = parseSyncOptions(args);
  await runSync(args, { ...syncOptions, yes: true, agent: universalAgentNames });
}
```

The callee is not given an allowlist of the locked `node_modules` skill names. Instead, [`runSync`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/sync.ts#L140-L182) scans the entire local `node_modules` tree and queues every discovered skill that does not match an existing lock entry and hash:

```ts
// 1. Discover skills from node_modules
spinner.start('Scanning node_modules for skills...');
const discoveredSkills = await discoverNodeModuleSkills(cwd);

// 2. Check which skills are already up-to-date via local lock
const localLock = await readLocalLock(cwd);
const toInstall: Array<Skill & { packageName: string }> = [];

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

Because `runInstallFromLock` forces `yes: true`, the normal sync confirmation in [`src/sync.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/sync.ts#L302-L332) is skipped before the queued skills are installed:

```ts
p.note(summaryLines.join('\n'), 'Sync Summary');

if (!options.yes) {
  const confirmed = await p.confirm({ message: 'Proceed with sync?' });
  if (p.isCancel(confirmed) || !confirmed) {
    p.cancel('Sync cancelled');
    process.exit(0);
  }
}

// 5. Install skills (always project-scoped, always symlink)
for (const skill of toInstall) {
  for (const agent of targetAgents) {
    const result = await installSkillForAgent(skill, agent, {
      global: false,
      cwd,
      mode: 'symlink',
    });
```

A malicious or compromised npm dependency therefore only needs to place a `SKILL.md` under its package directory. If the project lockfile contains one legitimate `node_modules` skill, restoring from the lockfile installs the attacker's unlisted skill noninteractively.

## Root Cause

The lockfile restore path delegates `node_modules` restoration to a broad discovery-and-sync operation without carrying forward the lockfile's intended allowlist. The locked names are used only as `nodeModuleSkills.length > 0`; they are not enforced as the set of skills that may be installed. The same path also disables the confirmation prompt by passing `yes: true`, so newly discovered dependency skills are treated as approved during what appears to be a lockfile restore.

## Proof of Concept (PoC)

The executed PoC is `piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/poc.js`. It creates a fixture project with two dependency packages:

1. `benign-skill-package` provides `safe-locked-skill` and is the only `node_modules` skill listed in `skills-lock.json`.
2. `transitive-evil-package` provides `malicious-lock-bypass`, which is not listed in the original lockfile.
3. The PoC runs `skills experimental_install` in the fixture project and checks whether `.agents/skills/malicious-lock-bypass/SKILL.md` was persisted.

Run:

```bash
cd /Users/bytedance/Desktop/oss-to-run/skills
node piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/poc.js
```

The captured exploit log shows that restore discovered and installed the unlisted dependency skill:

```text
Found 2 skills in node_modules
safe-locked-skill from benign-skill-package
malicious-lock-bypass from transitive-evil-package
1 skill already up to date
1 skill to install/update

Sync Summary
malicious-lock-bypass ← transitive-evil-package
  ./.agents/skills/malicious-lock-bypass

Sync complete
✓ malicious-lock-bypass ← transitive-evil-package
  ./.agents/skills/malicious-lock-bypass
```

The impact log confirms the security effect: the original lockfile did not contain the malicious skill, but the restore persisted it into the project agent skill directory:

```text
Impact: unlisted dependency-controlled skill persisted into the project agent skill directory.
Original lockfile skills: safe-locked-skill
Original lockfile contained malicious-lock-bypass: false
Post-install lockfile contains malicious-lock-bypass: true
Installed unlisted SKILL.md exists: true
ATTACKER_CONTROLLED_MARKER: unlisted-node-modules-skill-installed
```

## Impact

An attacker who controls any installed npm dependency can add a `SKILL.md` that becomes a persistent project skill when a developer restores skills from `skills-lock.json`, as long as the lockfile contains at least one legitimate `node_modules` skill. This bypasses both the lockfile review boundary and the normal sync confirmation prompt.

The observed impact is persistence of attacker-controlled skill instructions under `.agents/skills`. The likely downstream risk is prompt/tool-use compromise: future agent sessions may load the malicious skill and follow its instructions with the agent's project permissions, enabling code modification, secret discovery, or data exfiltration depending on the agent and user workflow.

## Remediation

Do not call unrestricted `runSync()` from the lockfile restore path. Instead:

- pass an explicit allowlist of locked `node_modules` skill names and package sources into the sync/install routine;
- ignore or fail closed on discovered `node_modules` skills that are absent from `skills-lock.json`;
- preserve confirmation for any newly discovered or changed dependency skill rather than forcing `yes: true`;
- record and verify package identity/version/integrity, not only the skill folder hash; and
- update `skills-lock.json` only for skills that were already allowed by the pre-restore lockfile or explicitly approved by the user.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-output.log; piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-evidence.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer ran the real CLI experimental_install with a lockfile listing only safe-locked-skill; an unlisted transitive-evil-package skill was installed and added to skills-lock.json.
