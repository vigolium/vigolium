# [p10-009] Project-scoped installs follow symlinked agent bases outside the project

Severity: High  
CWE: [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)  
PoC status: executed

## Summary

A malicious project checkout can commit `.agents` as a symlink to a directory outside the checkout. When a victim runs a project-scoped install, such as `skills add ./malicious-skill --agent codex --yes` without `--global`, the installer validates only normalized lexical paths under `cwd/.agents/skills`; the filesystem then follows the symlink and writes or replaces the skill outside the project, including under the victim's home agent skill base.

## Details

For project-scoped installs, the canonical skills directory is built from the current working directory, and the containment helper in [`src/installer.ts`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L63-L86) compares `resolve()`/`normalize()` strings rather than filesystem real paths:

```ts
function isPathSafe(basePath: string, targetPath: string): boolean {
  const normalizedBase = normalize(resolve(basePath));
  const normalizedTarget = normalize(resolve(targetPath));

  return normalizedTarget.startsWith(normalizedBase + sep) || normalizedTarget === normalizedBase;
}

export function getCanonicalSkillsDir(global: boolean, cwd?: string): string {
  const baseDir = global ? homedir() : cwd || process.cwd();
  return join(baseDir, AGENTS_DIR, SKILLS_SUBDIR);
}
```

The install path then derives `canonicalBase`, `canonicalDir`, `agentBase`, and `agentDir`, validates those lexical strings, and proceeds to destructive/write operations on the same paths. In the local copy branch, [`cleanAndCreateDirectory(agentDir)` and `copyDirectory(skill.path, agentDir)`](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L249-L282) are reached after the lexical checks pass:

```ts
const canonicalBase = getCanonicalSkillsDir(isGlobal, cwd);
const canonicalDir = join(canonicalBase, skillName);
const agentBase = getAgentBaseDir(agentType, isGlobal, cwd);
const agentDir = join(agentBase, skillName);

if (!isPathSafe(canonicalBase, canonicalDir)) { /* reject */ }
if (!isPathSafe(agentBase, agentDir)) { /* reject */ }

if (installMode === 'copy') {
  await cleanAndCreateDirectory(agentDir);
  await copyDirectory(skill.path, agentDir);
```

`cleanAndCreateDirectory` itself calls [`rm()` and `mkdir()` on the supplied path](https://github.com/vercel-labs/skills/blob/7c0a9af3f8738965b71341712710ac7371089b34/src/installer.ts#L125-L131). Because no `realpath()` containment check is applied to parent components, a checkout-controlled `.agents -> ../../.agents` symlink keeps the string `victim-project/.agents/skills/<name>` looking project-local while the actual filesystem target is outside `victim-project`.

## Root Cause

The installer enforces project scope with lexical path-prefix checks only. It never resolves the real path of the project agent base, the final target directory, or symlinked parent components before performing `rm()`, `mkdir()`, `copyDirectory()`, or `writeFile()`. As a result, project-controlled symlinks can redirect project-scoped operations across the project/global boundary.

## Proof of Concept (PoC)

The PoC status in the draft is `executed`. The runnable script is `piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/poc.sh`; it provisions a victim home, creates a Git checkout with `.agents` committed as a symlink, and runs the real CLI without `--global`:

```bash
HOME="$VICTIM_HOME" \
XDG_CONFIG_HOME="$VICTIM_HOME/.config" \
DISABLE_TELEMETRY=1 NO_COLOR=1 CI=1 \
node "$REPO_ROOT/src/cli.ts" add ./malicious-skill --agent codex --yes
```

The setup evidence shows the attacker-controlled repository contains a symlinked `.agents` entry:

```text
project_symlink=lrwxr-xr-x 1 bytedance staff 13 May  1 03:43 .agents -> ../../.agents
project_symlink_realpath=/.../evidence/runtime/victim-home/.agents
git_index_entries:
120000 0fa2ed144e2fe56ecdecec4551e0a2a0ed012305 0	.agents
```

The exploit log shows the command was a project-scoped install, and the impact log confirms the lexical project path resolved outside the project and that the payload landed in the victim home agent base:

```text
project_scope_command_no_global=node /Users/j3ssie/Desktop/oss-to-run/skills/src/cli.ts add ./malicious-skill --agent codex --yes
lexical_project_skill=/.../victim-home/work/victim-project/.agents/skills/symlink-escape-payload/SKILL.md
realpath_lexical_project_skill=/.../victim-home/.agents/skills/symlink-escape-payload/SKILL.md
escaped_project_root=yes

Installed SKILL.md content:
---
name: symlink-escape-payload
...
PIOLIUM_P10_009_PROJECT_SCOPE_SYMLINK_ESCAPE
```

## Impact

A malicious repository can turn a project-scoped install into a write/delete primitive under any symlink target writable by the victim user. If `.agents` points to the victim's home agent base, the project can persist attacker-supplied skills outside the checkout, making them available to later agent sessions in other projects. Existing same-named skills at the redirected target may also be removed or overwritten by the install cleanup step. The attack requires the victim to run a project-scoped skill install or restore from the malicious checkout; normal OS filesystem permissions still limit the target.

## Remediation

Resolve and validate real paths before every destructive or write operation. For `global: false`, reject project agent bases whose `realpath` is outside `realpath(cwd)`, and reject or explicitly require opt-in for symlinked `.agents` / skill-base parents. Apply the same realpath containment check to `canonicalDir`, `agentDir`, and per-file write targets immediately before `rm()`, `mkdir()`, `copyDirectory()`, and `writeFile()`, and add regression tests for committed `.agents` symlinks pointing outside the project.

## Confirmation (V5 Test Mapping)

Confirm-Status: confirmed-test
Confirm-Method: generated-vitest-reproducer
Confirm-Test: piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/confirm-test.test.ts
Confirm-Test-Output: piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-output.log
Confirm-Evidence: piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-output.log; piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-evidence.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-04-30T20:21:16Z
Confirm-Notes: Vitest reproducer installed project-scoped into a checkout whose .agents was a symlink; realpath of the lexical project install landed under the outside target.
