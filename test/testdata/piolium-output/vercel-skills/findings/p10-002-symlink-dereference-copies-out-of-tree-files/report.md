# [p10-002] Recursive install copy dereferences untrusted skill symlinks

**Severity:** High  
**CWE:** CWE-59: Improper Link Resolution Before File Access (`Link Following`)  
**PoC-Status:** executed

## Summary

Installing an attacker-controlled local or cloned skill can copy files from outside the skill repository into the victim's installed skill directory. The installer recursively copies skill contents with symlink dereferencing enabled, so a malicious skill can commit a symlink to a readable local path and have the target bytes materialized under `.agents/skills/<skill>` or the selected agent's skill directory.

## Details

The `add` flow ultimately calls `installSkillForAgent()`, which copies the selected skill tree into either the direct agent directory for `--copy` mode or the canonical `.agents/skills/<skill>` directory for symlink mode. This is visible in [`src/installer.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L278-L293):

```ts
if (installMode === 'copy') {
  await cleanAndCreateDirectory(agentDir);
  await copyDirectory(skill.path, agentDir);

  return {
    success: true,
    path: agentDir,
    mode: 'copy',
  };
}

// Symlink mode: copy to canonical location and symlink to agent location
await cleanAndCreateDirectory(canonicalDir);
await copyDirectory(skill.path, canonicalDir);
```

The vulnerable sink is `copyDirectory()`. It enumerates entries from the untrusted skill directory, treats symlinks as non-directories, and calls Node's `cp()` with `dereference: true` and `recursive: true` without first checking that the resolved path remains under the original skill root. The following code in [`copyDirectory`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L348-L380) proves the issue:

```ts
async function copyDirectory(src: string, dest: string): Promise<void> {
  await mkdir(dest, { recursive: true });

  const entries = await readdir(src, { withFileTypes: true });

  await Promise.all(
    entries
      .filter((entry) => !isExcluded(entry.name, entry.isDirectory()))
      .map(async (entry) => {
        const srcPath = join(src, entry.name);
        const destPath = join(dest, entry.name);

        if (entry.isDirectory()) {
          await copyDirectory(srcPath, destPath);
        } else {
          try {
            await cp(srcPath, destPath, {
              dereference: true,
              recursive: true,
            });
```

The only symlink-specific handling is for broken symlinks after `cp()` fails with `ENOENT`; valid symlinks to readable external files are not rejected. As a result, repository-controlled filesystem entries cross the trust boundary from an untrusted skill source into the victim's project or global agent skill directory.

## Root Cause

The installer intentionally dereferences symlinks while copying untrusted skill contents, but it does not perform an `lstat`/`realpath` containment check against the source skill root before copying. Path traversal in the skill name is checked, but path traversal through symlink targets inside the skill tree is not. This allows external local files to be read and rewritten as regular installed skill files.

## Proof of Concept (PoC)

The PoC is implemented in `piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/poc.sh` and was executed successfully against CLI version 1.5.3. It provisions a victim project and home directory, writes a victim-only secret at `victim-home/.config/cloud-token`, creates a malicious skill repository containing `SKILL.md` plus a committed symlink named `exfiltrated-token.txt`, and installs it with:

```sh
HOME="$VICTIM_HOME" \
XDG_CONFIG_HOME="$VICTIM_HOME/.config" \
NO_COLOR=1 \
node "$REPO_ROOT/bin/cli.mjs" add "$MALICIOUS_REPO" --agent codex -y --copy
```

The setup evidence shows the attacker-controlled repository committed a symlink entry:

```text
Committed git entries:
100644 4268ff639a728afd19edd8d76b752c22c75abc3a 0	SKILL.md
120000 ec8a8861e098553e93d2fa08f5d7f5c503c769dd 0	exfiltrated-token.txt
```

The impact evidence confirms the installed artifact is no longer a symlink: it is a regular file in the victim project's skill directory with the same hash and contents as the secret outside the skill tree:

```text
Installed artifact metadata:
-rw------- 1 bytedance staff 52 May  1 03:32 .../victim-project/.agents/skills/symlink-leak-demo/exfiltrated-token.txt
installed_artifact_type=regular_file
sha256: a64b713f17b55990c3f16b70cd9267f0db7c72ffd13f798f8c719ada832d59f9

Installed artifact contents:
PIOLIUM_SYMLINK_DEREF_SECRET_20260430T193210Z_73190
```

## Impact

A malicious skill source can cause locally readable files at predictable paths to be copied into `.agents/skills/<skill>` or agent-specific skill directories during installation. The CLI does not itself upload the copied file, but the file is moved into locations that agents, project tooling, backups, or accidental commits may later read or expose. This can disclose tokens, configuration files, or other secrets that the user did not intend to place inside the project or installed-skill tree.

## Remediation

Reject symlinks in untrusted skill trees, or copy them only after resolving each entry with `realpath` and verifying the resolved target remains within the resolved source skill root. Avoid `dereference: true` for attacker-controlled entries unless containment has already been enforced, and add regression tests covering external-file and external-directory symlinks.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-output.log; piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-evidence.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer installed a skill source containing a symlink to an out-of-tree secret in copy mode; the installed artifact was a regular file containing the secret marker.
