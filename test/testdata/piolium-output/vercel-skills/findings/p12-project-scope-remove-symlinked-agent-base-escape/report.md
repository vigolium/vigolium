# [p12] Project-scoped `skills remove` follows a symlinked agent base outside the project

## Summary

`skills remove` is intended to operate on project-local skills when `--global` is not supplied, but the project-scope removal path builds `.agents` and agent-specific paths from `cwd` without resolving symlinked parent directories before recursively deleting them. A malicious repository can include `.agents -> ../outside` (or another outside target); when a victim runs `skills remove <name> -y` from that checkout, the CLI deletes the matching skill directory in the symlink target instead of staying inside the project.

## Details

In project scope, `removeCommand` scans the canonical project skills directory and each agent skills directory by concatenating `cwd` with the configured relative path. If `.agents` is a symlink, the scan reads the target directory and treats its entries as installed project skills. The relevant project-scope scan and removal logic is in [`src/remove.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/remove.ts#L54-L58) and [`src/remove.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/remove.ts#L154-L180):

```ts
if (isGlobal) {
  await scanDir(getCanonicalSkillsDir(true, cwd));
  for (const agent of Object.values(agents)) {
    if (agent.globalSkillsDir !== undefined) {
      await scanDir(agent.globalSkillsDir);
    }
  }
} else {
  await scanDir(getCanonicalSkillsDir(false, cwd));
  for (const agent of Object.values(agents)) {
    await scanDir(join(cwd, agent.skillsDir));
  }
}

// ...

const canonicalPath = getCanonicalPath(skillName, { global: isGlobal, cwd });

for (const agentKey of targetAgents) {
  const agent = agents[agentKey];
  const skillPath = getInstallPath(skillName, agentKey, { global: isGlobal, cwd });

  const pathsToCleanup = new Set([skillPath]);
  const sanitizedName = sanitizeName(skillName);
  if (isGlobal && agent.globalSkillsDir) {
    pathsToCleanup.add(join(agent.globalSkillsDir, sanitizedName));
  } else {
    pathsToCleanup.add(join(cwd, agent.skillsDir, sanitizedName));
  }

  for (const pathToCleanup of pathsToCleanup) {
    if (pathToCleanup === canonicalPath) {
      continue;
    }

    const stats = await lstat(pathToCleanup).catch(() => null);
    if (stats) {
      await rm(pathToCleanup, { recursive: true, force: true });
    }
  }
}
```

The canonical project path is also removed unconditionally once no remaining agent use is detected, again without resolving the path through symlinked ancestors first ([`src/remove.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/remove.ts#L207-L208)):

```ts
if (!isStillUsed) {
  await rm(canonicalPath, { recursive: true, force: true });
}
```

The path-safety helper used by `getInstallPath` and `getCanonicalPath` only normalizes lexical path strings. It does not call `realpath()` on the base directory or target, so a path like `$project/.agents/skills/victim-skill` passes containment even when `.agents` is a symlink to a directory outside `$project` ([`src/installer.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L63-L67), [`src/installer.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L423-L439)):

```ts
function isPathSafe(basePath: string, targetPath: string): boolean {
  const normalizedBase = normalize(resolve(basePath));
  const normalizedTarget = normalize(resolve(targetPath));

  return normalizedTarget.startsWith(normalizedBase + sep) || normalizedTarget === normalizedBase;
}

export function getInstallPath(
  skillName: string,
  agentType: AgentType,
  options: { global?: boolean; cwd?: string } = {}
): string {
  const targetBase = getAgentBaseDir(agentType, options.global ?? false, options.cwd);
  const installPath = join(targetBase, sanitizeName(skillName));

  if (!isPathSafe(targetBase, installPath)) {
    throw new Error('Invalid skill name: potential path traversal detected');
  }

  return installPath;
}
```

## Root Cause

Project scope is enforced with string-based path construction and lexical prefix checks, not filesystem-resolved containment. The removal code trusts project-relative agent base directories such as `.agents/skills` even when an attacker-controlled checkout makes an ancestor component a symlink. The destructive `rm(..., { recursive: true, force: true })` calls therefore operate on the symlink target while the CLI still believes it is removing a project-local skill.

## Proof of Concept (PoC)

PoC status: **executed**. The reproduction script is `piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/poc.sh`.

The script creates an outside skill, creates a project checkout with `.agents` symlinked to that outside directory, and runs the project-scoped CLI command:

```bash
mkdir -p evidence/workdir/outside/skills/victim-skill evidence/workdir/project
printf 'P12_SYMLINK_ESCAPE_SENTINEL\n' > evidence/workdir/outside/skills/victim-skill/SKILL.md
(cd evidence/workdir/project && ln -s ../outside .agents)
(cd evidence/workdir/project && node /path/to/repo/src/cli.ts remove victim-skill -y)
```

The decisive lines from `evidence/impact.log` show the operation was project-scoped, exited successfully, and removed the outside skill through the symlinked `.agents` base:

```text
project_.agents_symlink=../outside
outside_skill=/Users/j3ssie/Desktop/oss-to-run/skills/piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/workdir/outside/skills/victim-skill
before_marker=P12_SYMLINK_ESCAPE_SENTINEL
cli_command=(cd project && node src/cli.ts remove victim-skill -y)
cli_exit=0
outside_victim_exists_after=no
{"status":"confirmed","evidence":"outside/skills/victim-skill removed through project .agents symlink","notes":"see evidence/impact.log"}
```

## Impact

A malicious repository can cause a user who runs `skills remove` in project scope to delete skills outside that repository. This can disrupt other projects that share the target directory and can remove persistent agent instructions, guardrail skills, or other local skill content the user did not intend to modify. Exploitation requires control of the project checkout contents and user execution of the remove command; it is not a remote unauthenticated service-side issue.

## Remediation

Before scanning or deleting project-scope skill paths, resolve the project root, agent base directory, and candidate deletion target with `realpath()`/`realpath.native()` and verify the resolved target remains under the resolved intended project base. Reject or skip symlinked project agent bases for destructive operations, and emit a warning rather than following them. Apply the same resolved-path containment check immediately before each recursive `rm`, including the final canonical-path deletion, and add regression tests covering `.agents` and other agent skill parent directories that are symlinks to paths outside the project.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-output.log; piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-evidence.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer ran the real CLI remove in a project whose .agents symlink pointed outside; the outside victim-skill directory existed before and was deleted after the project-scoped command.
