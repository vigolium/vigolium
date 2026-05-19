# Deep Probe Summary: Manual Attack Surface Probe

Status: complete
Loops: 1
Total hypotheses: 8
Validated: 2
Needs-Deeper: 2
Carry-forward / existing coverage: 4
Stop reason: highest-impact slices covered; remaining open items are either already drafted in P4/P7 or require Windows/PATH-specific follow-up.

Inventory: `piolium/attack-surface/manual-attack-surface-inventory.md`
Proof tests: `piolium/tmp/p8-proofs.test.ts`
Proof output: `piolium/tmp/p8-proofs-output.txt`

## Validated Hypotheses

### PH-P8-001: Project-scoped installs follow symlinked agent bases outside cwd

- Reasoning-Model: Backward + Contradiction
- Target: `src/installer.ts:63` — `isPathSafe()`; sink at `src/installer.ts:773` — `writeFile(fullPath, file.contents, 'utf-8')`
- Attack input: a project checkout with `.agents` symlinked to an external directory, then a project-scoped install/restore (`global: false`).
- Code path: `src/installer.ts:84-86` derives `cwd/.agents/skills` → `src/installer.ts:63-67` lexical containment passes → `src/installer.ts:125-130` removes/creates target → `src/installer.ts:779-785` writes files.
- Sanitizers on path: `isPathSafe()` — bypassable because it checks lexical paths and does not realpath symlinked parents before write/delete.
- Security consequence: project install can write/overwrite persistent skills outside the project, including global/shared agent skill dirs when symlink targets are predictable.
- Severity estimate: HIGH
- Evidence file: `piolium/findings-draft/p8-001-project-scope-symlinked-agent-base-escape.md`; proof `piolium/tmp/p8-proofs.test.ts:35-58`.

### PH-P8-002: `experimental_install` installs unlocked node_modules skills

- Reasoning-Model: Backward + Contradiction
- Target: `src/install.ts:84` — `runSync(args, { ...syncOptions, yes: true, agent: universalAgentNames })`
- Attack input: `skills-lock.json` containing any `sourceType: "node_modules"` entry plus an unlisted dependency package containing `SKILL.md`.
- Code path: `src/install.ts:17-20` reads lock → `src/install.ts:37-40` records node_modules names → `src/install.ts:78-84` calls full sync with `yes: true` → `src/sync.ts:142` scans all node_modules → `src/sync.ts:171-181` queues unlisted skill → `src/sync.ts:305-333` skips prompt and installs.
- Sanitizers on path: local lock hash/up-to-date check — bypassable because missing lock entries are treated as new `toInstall` items rather than rejected during restore.
- Security consequence: a malicious npm dependency can persist agent instructions during a lock restore even though its skill was absent from the reviewed lockfile.
- Severity estimate: HIGH
- Evidence file: `piolium/findings-draft/p8-002-experimental-install-unlocked-node-modules-skills.md`; proof `piolium/tmp/p8-proofs.test.ts:61-95`.

## NEEDS-DEEPER

### PH-P8-003: Windows update self-spawn shell quoting

- Why unresolved: `src/cli.ts:693-696` and `src/cli.ts:764-770` pass lock-derived `installUrl`/skill names to `spawnSync(..., { shell: process.platform === 'win32' })`. P8 was run on macOS and did not execute Windows command-line parsing; existing P4-007 covers lock-derived reinstall trust.
- Suggested follow-up: run a Windows proof with metacharacters in `skills-lock.json` `source`, `ref`, `skillPath`, and skill name to confirm whether Node's `spawnSync` argument quoting is safe with `shell:true`.

### PH-P8-004: PATH-resolved `gh auth token` helper

- Why unresolved: `src/skill-lock.ts:135-149` falls back to `execSync('gh auth token')` if `GITHUB_TOKEN`/`GH_TOKEN` are absent. This is command execution through inherited PATH, but exploitation depends on a realistic PATH-control route such as npm scripts placing `node_modules/.bin` before system paths.
- Suggested follow-up: test npm-script execution with a dependency-provided `node_modules/.bin/gh` and `skills add`/`update` paths that call `getGitHubToken()`.

## Existing / carry-forward findings not duplicated

- Direct git/ref to vulnerable `simple-git` clone: existing `p4-001-direct-git-url-ref-reaches-simple-git-clone.md`.
- Source symlink dereference during copy: existing `p4-002-symlink-dereference-copies-out-of-tree-files.md`.
- Well-known HTTP/missing limits/name constraints: existing P4/P7 drafts, especially `p7-001-rfc8615-path-relative-well-known-shadowing.md` and `p7-002-agent-skill-name-constraints-not-enforced.md`.
- General `experimental_sync` dependency-skill installation: existing `p4-008-node-modules-sync-installs-dependency-skills.md`; P8-002 is a stronger restore-specific variant.

## Coverage Summary

| Entry Point | Inline backward hypotheses | Inline contradiction hypotheses | Outcome |
|------------|:-:|:-:|---|
| `skills add <source>` | BWD-01, BWD-03 | CON-01 | P8-001 validated for filesystem scope escape; direct git carried forward from P4. |
| `skills experimental_install` | BWD-02 | CON-02 | P8-002 validated. |
| `skills experimental_sync` | BWD-02 path coverage | CON-02 | Restore-specific variant validated; general sync risk already P4-008. |
| `skills update|check|upgrade` | BWD-04 | — | Needs deeper on Windows; P4-007 already covers lock-derived self-spawn trust. |
| Well-known URL install | — | CON-03 | Existing P4/P7 coverage; no duplicate P8 draft. |
| Git clone transport | BWD-03 | — | Existing P4-001 coverage; no duplicate P8 draft. |
| `skills find` | Reviewed | — | No new higher-impact path beyond search-result-to-install trust in P4/K.B. |
| CI publish workflows | Reviewed | — | No new P8 finding; branch/secret protection remains external setting. |
