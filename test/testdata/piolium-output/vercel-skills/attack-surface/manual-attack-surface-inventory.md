# Stage 08 Manual Attack Surface Inventory

Generated: 2026-05-01
Target: `/Users/j3ssie/Desktop/oss-to-run/skills`
Mode: single-team manual probe

## P3-P7 inputs reviewed

- `piolium/attack-surface/knowledge-base-report.md`
- `piolium/attack-surface/architecture-entrypoints.md`
- `piolium/attack-surface/public-routes-authz-matrix.md`
- `piolium/attack-surface/source-sink-flows-all-severities.md`
- `piolium/attack-surface/patch-bypass-summary.md`
- `piolium/attack-surface/spec-gap-summary.md`
- `piolium/attack-surface/state-concurrency-summary.md`
- Existing drafts under `piolium/findings-draft/`

## Highest-impact slices selected

1. **Remote/local/well-known/blob install to agent directories** — public `skills add <source>` flows into git clone / HTTP fetch / frontmatter parse / filesystem writes and downstream agent execution.
2. **Lock restore + node_modules sync** — `skills experimental_install` is documented as restoring `skills-lock.json`, but delegates node_modules restoration to the broader sync engine.
3. **Project/global filesystem boundary** — project scope is expected to stay in the current repository while global scope persists under home/config agent directories.
4. **Native git/update command boundaries** — direct git/ref input to `simple-git`, plus lock-derived `skills update` self-spawns. These were mostly carried forward from P4 because P8 found no stronger non-duplicate proof in this pass.
5. **Well-known discovery** — arbitrary HTTP(S) origins and RFC 8615 path/name handling; existing P4/P7 drafts cover most of this slice.

## Public routes / URLs

This repository exposes no inbound HTTP routes; its public attack surface is CLI commands and outbound URLs.

| Surface | Public route / URL / command | Attacker-controlled input | Primary sinks | Source files |
|---|---|---|---|---|
| CLI install | `skills add <source>` / `add-skill <source>` | `source`, ref fragment, subpath, `--skill`, `--agent`, `--global`, `--yes`, cwd, env | `cloneRepo`, fetch, YAML parse, `install*ForAgent` writes | `src/add.ts:895`, `src/source-parser.ts:220`, `src/git.ts:28`, `src/installer.ts:226`, `src/installer.ts:720` |
| Restore | `skills experimental_install` / `skills install` with no args | `skills-lock.json`, `node_modules`, sync args, cwd symlinks | `runAdd(... yes: true)`, `runSync(... yes: true)`, installer writes | `src/install.ts:17`, `src/install.ts:65`, `src/install.ts:84`, `src/sync.ts:142`, `src/sync.ts:329` |
| Sync | `skills experimental_sync` | all `node_modules/**/SKILL.md`, package names, `--agent`, `--yes` | project `.agents/skills` writes and lock writes | `src/sync.ts:46`, `src/sync.ts:142`, `src/sync.ts:329`, `src/local-lock.ts:151` |
| Update | `skills update|check|upgrade` | global/project lock entries, skill filters, env | GitHub API hash fetch, self-spawned `skills add` | `src/cli.ts:595`, `src/cli.ts:683`, `src/cli.ts:693`, `src/cli.ts:751`, `src/cli.ts:764` |
| Find/search | `skills find [query]` | query, `skills.sh` search response source/name | terminal output, follow-on `runAdd` | `src/find.ts:33`, `src/find.ts:270`, `src/find.ts:339` |
| Well-known discovery | `{base}/.well-known/agent-skills/index.json`, `{base}/.well-known/skills/index.json` | arbitrary HTTP(S) origin, index names/files/content | fetches, YAML parse, file writes | `src/providers/wellknown.ts:96`, `src/providers/wellknown.ts:134`, `src/providers/wellknown.ts:271`, `src/installer.ts:652` |
| GitHub/raw/blob | `https://api.github.com/repos/{ownerRepo}/git/trees/{ref}?recursive=1`, `https://raw.githubusercontent.com/...`, `https://skills.sh/api/download/...` | owner/repo/ref/path, snapshot service response, `SKILLS_DOWNLOAD_URL` | raw fetch, snapshot write | `src/blob.ts:84`, `src/blob.ts:249`, `src/blob.ts:270`, `src/installer.ts:773` |
| Telemetry/audit | `https://add-skill.vercel.sh/t`, `https://add-skill.vercel.sh/audit` | source/skill metadata, query strings | outbound privacy boundary, terminal advisory output | `src/telemetry.ts:97`, `src/telemetry.ts:129` |
| CI publish | `.github/workflows/publish.yml` push/tag/dispatch | main branch code/deps, tags, dispatch bump choice | npm publish and GitHub release | `.github/workflows/publish.yml:3`, `.github/workflows/publish.yml:23`, `.github/workflows/publish.yml:118` |

## Attacker sources

| Source | Realistic attacker | Normalization / guard | Exploit-relevant sink |
|---|---|---|---|
| Git URL/ref/subpath | Malicious repository or copied command | `parseSource()` and `sanitizeSubpath()`; no first-party URL/ref allowlist | `src/git.ts:62` `git.clone(url, tempDir, cloneOptions)` |
| Remote `SKILL.md` frontmatter/body | Skill author, compromised repo/well-known host/blob service | type checks and terminal-escape stripping; name constraints not fully enforced | `src/installer.ts` writes agent-readable instructions |
| Well-known `index.json` | Arbitrary HTTP(S) host | shape checks; invalid multi-char names fail open (`src/providers/wellknown.ts:185-189`) | `fetchSkillByEntry()` URLs and `installName` |
| Project cwd symlinks (`.agents`, agent dirs) | Malicious project repository / local checkout | lexical `isPathSafe()` only (`src/installer.ts:63-67`) | `cleanAndCreateDirectory()` + `writeFile()` / `copyDirectory()` follow symlinked parents |
| `skills-lock.json` | Project contributor / dependency update / malicious PR | JSON shape only; node_modules entries trigger full sync | `src/install.ts:84` → `src/sync.ts:329` |
| `node_modules` package contents | Malicious/compromised npm package | no package allowlist; sync hashes after install | `src/sync.ts:142`, `src/sync.ts:329`, `src/local-lock.ts:357` |
| Environment / PATH | Shell, npm scripts, CI wrappers | mixed validation; `getGitHubToken()` shells out to `gh` if no env token | `src/skill-lock.ts:146` |

## High-value sinks

| Sink | File:line | Attacker input | Notes |
|---|---:|---|---|
| Native git clone | `src/git.ts:62` | source URL/ref from CLI/lock | Existing P4 direct-git finding; simple-git dependency advisory pressure remains. |
| Project/global installer writes | `src/installer.ts:281`, `src/installer.ts:292`, `src/installer.ts:652`, `src/installer.ts:773` | skill content + sanitized names + cwd/agent base paths | P8 found target-base symlink escape. |
| Directory cleanup | `src/installer.ts:125-130` | computed install directory | Removes and recreates path after only lexical containment checks. |
| Lock restore `runAdd` | `src/install.ts:65-69` | lock `source` and skill names | Existing P4 lock source trust finding. |
| Lock restore `runSync` | `src/install.ts:78-84` | any node_modules lock entry | P8 found unlisted dependency skills install. |
| Sync install loop | `src/sync.ts:327-333` | all discovered node_modules skills | Confirmation skipped when called by restore with `yes: true`. |
| Self-spawn update | `src/cli.ts:693`, `src/cli.ts:764` | lock-derived source/ref/skill name | Existing P4 finding; Windows `shell:true` remains a follow-up. |
| PATH-resolved `gh` | `src/skill-lock.ts:146` | inherited PATH / npm script PATH | Needs deeper exploitability triage; not redrafted in P8. |

## Exploit-relevant paths verified in P8

### Path A — Project-scope install follows a symlinked `.agents` parent outside cwd

1. Project-scoped install chooses base from cwd: `getCanonicalSkillsDir(false, cwd)` returns `join(cwd, '.agents', 'skills')` (`src/installer.ts:84-86`).
2. The target is checked with lexical `resolve()/normalize()` only (`src/installer.ts:63-67`); parent symlinks are not resolved before the safety decision.
3. The installer cleans/creates the target and writes files (`src/installer.ts:125-130`, `src/installer.ts:773`, `src/installer.ts:779-785`).
4. A project containing `.agents -> /outside` causes `.agents/skills/<skill>/SKILL.md` to be written under `/outside/skills/<skill>/SKILL.md` even though `global: false`.
5. Proof: `piolium/tmp/p8-proofs.test.ts:35-58`; output retained in `piolium/tmp/p8-proofs-output.txt`.

### Path B — `experimental_install` installs unlocked node_modules skills

1. `runInstallFromLock()` reads `skills-lock.json` (`src/install.ts:17-20`).
2. Any entry with `sourceType === 'node_modules'` is pushed to `nodeModuleSkills` (`src/install.ts:37-40`).
3. If the list is non-empty, restore calls `runSync(args, { ...syncOptions, yes: true, agent: universalAgentNames })` (`src/install.ts:78-84`) without passing the locked skill names as a filter.
4. `runSync()` scans all `node_modules` packages (`src/sync.ts:142`) and queues every discovered skill not already up-to-date (`src/sync.ts:171-181`).
5. Because restore set `yes: true`, the sync confirmation is skipped (`src/sync.ts:305-311`), and all queued dependency skills are installed (`src/sync.ts:327-333`).
6. Proof: `piolium/tmp/p8-proofs.test.ts:61-95`; output retained in `piolium/tmp/p8-proofs-output.txt`.

## Inline hypotheses and outcomes

| ID | Reasoning | Hypothesis | Verification | Outcome |
|---|---|---|---|---|
| BWD-01 | Backward from installer write sinks | A project checkout can make project-scoped installs write outside cwd by symlinking `.agents` or agent skill bases before `cleanAndCreateDirectory()`/`writeFile()`. | Read `src/installer.ts:63-67`, `src/installer.ts:84-86`, `src/installer.ts:125-130`, `src/installer.ts:773-785`; proof test `piolium/tmp/p8-proofs.test.ts:35-58` passed. | **VALIDATED** → `p8-001` |
| BWD-02 | Backward from noninteractive restore install | `experimental_install` restores more than the lock: any node_modules lock entry triggers a full `experimental_sync -y` and installs unlisted dependency skills. | Read `src/install.ts:37-40`, `src/install.ts:78-84`, `src/sync.ts:142`, `src/sync.ts:171-181`, `src/sync.ts:305-333`; proof test `piolium/tmp/p8-proofs.test.ts:61-95` passed. | **VALIDATED** → `p8-002` |
| BWD-03 | Backward from native command sink | Direct git URL/ref reaches simple-git clone with current vulnerable dependency. | Confirmed existing path `src/add.ts:1041/1053` → `src/git.ts:59-62`; already drafted as P4-001. | Carry-forward, no duplicate P8 draft |
| BWD-04 | Backward from self-spawn update sink | Windows `shell:true` may make lock-derived update source/skill name command-injectable. | Read `src/cli.ts:693-696`, `src/cli.ts:764-770`; not executed on Windows in this environment. | NEEDS-DEEPER / covered partly by P4-007 |
| CON-01 | Contradict “project scope confines writes to cwd” | Lexical path checks do not make the project boundary true if cwd contains symlinked parents. | Same as BWD-01. | **VALIDATED** → `p8-001` |
| CON-02 | Contradict “restore installs only locked skills” | `nodeModuleSkills` only gates whether to call sync; it is not used to constrain sync results. | Same as BWD-02. | **VALIDATED** → `p8-002` |
| CON-03 | Contradict “well-known name regex rejects invalid names” | Invalid multi-character names pass `isValidSkillEntry()` and flow to URL construction/installName. | Read `src/providers/wellknown.ts:185-189`, `src/providers/wellknown.ts:267-316`; existing P7-002 covers name-constraint consequences. | Existing finding, no duplicate P8 draft |
| CON-04 | Contradict “GitHub token lookup is passive” | If no env token exists, `execSync('gh auth token')` resolves `gh` through inherited PATH. | Read `src/skill-lock.ts:135-149`; exploitability depends on PATH control such as npm-script `node_modules/.bin`. | NEEDS-DEEPER |

## Draft findings written

- `piolium/findings-draft/p8-001-project-scope-symlinked-agent-base-escape.md`
- `piolium/findings-draft/p8-002-experimental-install-unlocked-node-modules-skills.md`

## Proof artifacts

- Proof tests: `piolium/tmp/p8-proofs.test.ts`
- Proof output: `piolium/tmp/p8-proofs-output.txt`
