# Architecture Entrypoints Inventory — Stage 03

Generated: 2026-05-01  
Target: `/Users/bytedance/Desktop/oss-to-run/skills`

## Runtime entry points

| Entry point | Command / trigger | Attacker-controlled sources | High-value sinks | Key source files |
|---|---|---|---|---|
| CLI bootstrap | `skills`, `add-skill`, `npx skills ...` | `process.argv`, cwd, environment | command dispatch, telemetry flush | `bin/cli.mjs`, `src/cli.ts` |
| Add/install | `skills add <source>` / aliases `a`, `install`, `i` | source string, refs/fragments, subpaths, `--skill`, `--agent`, `--global`, `--yes`, `--all`, `--copy`, `--full-depth` | native git clone, HTTP fetch, YAML parse, file write/copy/symlink, agent skill dirs | `src/add.ts`, `src/source-parser.ts`, `src/git.ts`, `src/blob.ts`, `src/providers/wellknown.ts`, `src/skills.ts`, `src/installer.ts` |
| Find/search | `skills find [query]` | query, search API response, selected result | terminal output, follow-on `runAdd` install, telemetry | `src/find.ts`, `src/add.ts`, `src/telemetry.ts` |
| List | `skills list`, `skills ls` | `--global`, `--agent`, `--json`; installed skill metadata from filesystem | terminal/JSON output, metadata parser | `src/list.ts`, `src/installer.ts`, `src/skills.ts` |
| Remove | `skills remove [skills]`, `rm`, `r` | skill args, `--global`, `--agent`, `--all`, installed directory names | recursive `rm`, lock deletion, telemetry | `src/remove.ts`, `src/installer.ts`, `src/skill-lock.ts` |
| Update/check | `skills update [skills...]`, `check`, `upgrade` | lockfile entries, skill filters, env, installed dirs | GitHub API hash checks, self-`spawnSync` `skills add`, file writes | `src/cli.ts`, `src/skill-lock.ts`, `src/local-lock.ts`, `src/update-source.ts`, `src/add.ts` |
| Init | `skills init [name]` | skill name arg, cwd | `mkdirSync`, `writeFileSync` new `SKILL.md` | `src/cli.ts` |
| Restore from lock | `skills experimental_install` | `skills-lock.json`, sync args | grouped `runAdd`, `experimental_sync` | `src/install.ts`, `src/local-lock.ts`, `src/add.ts`, `src/sync.ts` |
| Sync node_modules | `skills experimental_sync` | `node_modules` package contents, `SKILL.md`, package names, `--agent`, `--force`, `--yes` | project skill install, local lock write | `src/sync.ts`, `src/installer.ts`, `src/local-lock.ts` |

## Public routes / URLs visible

This project exposes no inbound web server routes. The following outbound URL patterns are security-relevant:

| URL / pattern | Method/use | Attacker influence | Sink/asset | Source files |
|---|---|---|---|---|
| `https://api.github.com/repos/{owner}/{repo}` | repo privacy check | owner/repo from CLI source | telemetry gating/privacy | `src/source-parser.ts`, `src/add.ts`, `src/find.ts` |
| `https://api.github.com/repos/{ownerRepo}/git/trees/{ref}?recursive=1` | GitHub tree/hash fetch | ownerRepo/ref from CLI or lock | blob discovery, update integrity | `src/blob.ts`, `src/skill-lock.ts` |
| `https://raw.githubusercontent.com/{ownerRepo}/{branch}/{skillMdPath}` | raw `SKILL.md` fetch | ownerRepo/branch/path from GitHub tree/source | YAML parse, skill metadata | `src/blob.ts` |
| `https://skills.sh/api/download/{owner}/{repo}/{slug}` | blob snapshot download | owner/repo/slug from source/frontmatter; base override by `SKILLS_DOWNLOAD_URL` | installed file contents | `src/blob.ts` |
| `https://skills.sh/api/search?q={query}&limit=10` | search skills | query; base override by `SKILLS_API_URL` | terminal output, install recommendation | `src/find.ts` |
| `{base}/.well-known/agent-skills/index.json` | preferred well-known index | arbitrary CLI URL host/path | index JSON parser | `src/providers/wellknown.ts` |
| `{base}/.well-known/skills/index.json` | legacy well-known index | arbitrary CLI URL host/path | index JSON parser | `src/providers/wellknown.ts` |
| `{base}/.well-known/{agent-skills|skills}/{entry.name}/SKILL.md` | fetch required skill file | index `name` | YAML parser, installed content | `src/providers/wellknown.ts` |
| `{base}/.well-known/{agent-skills|skills}/{entry.name}/{filePath}` | fetch auxiliary files | index `files[]` | file writes | `src/providers/wellknown.ts`, `src/installer.ts` |
| `https://add-skill.vercel.sh/audit?...` | partner security audit display | ownerRepo and skill names | terminal advisory display | `src/telemetry.ts`, `src/add.ts` |
| `https://add-skill.vercel.sh/t?...` | telemetry | event metadata, source, skills, agents | privacy boundary | `src/telemetry.ts` |
| Git clone URL (`https://...git`, `git@...`, direct fallback) | native git transport | CLI/lock source | native subprocess, credentials | `src/source-parser.ts`, `src/git.ts` |

## Attacker-controlled source inventory

| Source | Origin | Normalization/validation | Main consumers | Notes |
|---|---|---|---|---|
| CLI `source` argument | User/automation/copy-paste | `parseSource()`, source aliases, local path detection, regex URL parsing | `runAdd`, `cloneRepo`, well-known/blob/local handlers | Highest-risk entry point. |
| URL fragment ref/skill | `#ref`, `#ref@skill`, `owner/repo@skill` | `decodeURIComponent`, `looksLikeGitSource`, `sanitizeSubpath` for paths | clone branch, skill filter | Ref is not strictly allowlisted before git. |
| GitHub/GitLab tree subpath | URL path or shorthand `owner/repo/path` | `sanitizeSubpath` rejects `..`; `isSubpathSafe` lexical containment | `discoverSkills` | Symlink realpath gap remains. |
| Remote git repository contents | Third-party repo | Git clone; discovery skip list; YAML required fields | `discoverSkills`, `copyDirectory` | May include symlinks/plugin manifests/large files. |
| `SKILL.md` frontmatter/body | Git/local/well-known/blob/node_modules | YAML-only parse; name/description type check; metadata sanitization for some fields | selection, install, terminal output, downstream agents | Prompt-injection content is expected but dangerous. |
| `.claude-plugin/*.json` manifests | Remote/local repo | JSON parse; `./` path convention; lexical containment | plugin grouping/search dirs | Remote plugin sources are skipped. |
| Well-known `index.json` | Arbitrary HTTP(S) host | structure and file path checks; name regex currently fail-open for invalid multi-char names | file fetch, install name, terminal output | Accepts HTTP and path-relative discovery. |
| Well-known/snapshot file paths | index/files response | `file.includes('..')` for well-known; `isPathSafe` on write for both | `writeFile` | Need size/count/realpath limits. |
| `node_modules` package dirs | Project dependencies | directory walk; `parseSkillMd`; local lock hash | `experimental_sync` | Supply-chain boundary. |
| Global/project lockfiles | home/XDG state and cwd | JSON schema version check; hashes in local lock | update/restore/remove | Tampering redirects future installs. |
| Environment variables | Shell/CI/local wrappers | mixed validation | API bases, token lookup, config paths, telemetry, git env | Treat as LocalUserInput in CodeQL. |
| Search API results | `skills.sh` | metadata sanitization | display and selected install | External recommendation trust. |
| GitHub workflow events | GitHub CI | workflow triggers/permissions | build/test/publish jobs | No AI action usage currently. |

## High-value sinks inventory

| Sink | Type | Attacker input reaching it | File / symbol | Review priority |
|---|---|---|---|---|
| `git.clone(url, tempDir, cloneOptions)` | command execution | source URL and ref | `src/git.ts::cloneRepo` | Critical |
| `spawnSync(process.execPath, [cliEntry, 'add', installUrl,...])` | command execution | lockfile-derived update source, skill names | `src/cli.ts::updateGlobalSkills`, `updateProjectSkills` | High |
| `execSync('gh auth token')` | command execution / credential access | PATH/env (indirect), local environment | `src/skill-lock.ts::getGitHubToken` | Medium |
| `fetch(indexUrl/skillMdUrl/fileUrl)` | HTTP request | arbitrary well-known URL, index names/files | `src/providers/wellknown.ts` | High |
| `fetch(GitHub/raw/skills.sh/search/audit/telemetry)` | HTTP request | source/query/env override/event metadata | `src/blob.ts`, `src/find.ts`, `src/telemetry.ts`, `src/source-parser.ts` | Medium-High |
| `parseYaml(match[1])` | parser/deserialization | untrusted `SKILL.md` frontmatter | `src/frontmatter.ts::parseFrontmatter` | Medium |
| `writeFile(fullPath, content)` | file write | well-known/blob/lock/init content and paths | `src/installer.ts`, `src/local-lock.ts`, `src/skill-lock.ts`, `src/cli.ts` | High |
| `cp(srcPath, destPath, { dereference:true })` | file read/write | untrusted local/temp repo entries | `src/installer.ts::copyDirectory` | High |
| `symlink(relativePath, linkPath)` | filesystem link | skill name/agent path/canonical path | `src/installer.ts::createSymlink` | Medium-High |
| `rm(path, { recursive:true, force:true })` | file delete | skill names, install paths, cleanup temp | `src/installer.ts`, `src/remove.ts`, `src/git.ts` | High |
| Terminal output (`console`, `p.log`, `p.note`) | terminal/log injection | names/descriptions/installName/source | `src/add.ts`, `src/find.ts`, `src/list.ts`, `src/remove.ts` | Medium |
| Agent skill directories | downstream execution context | installed markdown/files | `src/installer.ts`, `src/agents.ts` | High |
| npm publish / GitHub release | release/supply-chain | main branch code/deps/workflow inputs | `.github/workflows/publish.yml` | High |

## Security-critical source files

| File | Why important |
|---|---|
| `src/cli.ts` | Top-level dispatch, update self-spawn, init file write, global lock read path. |
| `src/add.ts` | Main install orchestration, source privacy checks, OpenClaw policy, blob fallback, prompts, telemetry. |
| `src/source-parser.ts` | Source type/ref/subpath/URL classification and privacy owner/repo extraction. |
| `src/git.ts` | simple-git/native git subprocess with inherited env and clone options. |
| `src/blob.ts` | GitHub/raw/skills.sh fast path and snapshot-to-install flow. |
| `src/providers/wellknown.ts` | Arbitrary URL well-known discovery and file fetch. |
| `src/frontmatter.ts` | YAML parser wrapper; historically security-sensitive replacement for gray-matter JS frontmatter. |
| `src/skills.ts` | Skill discovery, recursive search, dedupe by name, internal gating, subpath containment. |
| `src/plugin-manifest.ts` | Plugin manifest parsing and path containment. |
| `src/installer.ts` | Name sanitization, path safety, copy/symlink/write/remove/list scanning. |
| `src/remove.ts` | Recursive cleanup of canonical and agent-specific dirs. |
| `src/sync.ts` | node_modules discovery and project install. |
| `src/install.ts` | Lockfile restore, groups lock entries into `runAdd`. |
| `src/update-source.ts` | Converts lock `skillPath` into new install sources. |
| `src/skill-lock.ts` | Global lock path, token lookup via env/gh CLI, GitHub tree hash lookup. |
| `src/local-lock.ts` | Project lock hash computation and lock writes. |
| `src/find.ts` | Search API trust and direct call to `runAdd`. |
| `src/telemetry.ts` | Privacy/telemetry enablement and outbound event fields. |
| `src/agents.ts` | Agent path map and env-controlled config dirs. |
| `.github/workflows/ci.yml` | PR/push build and tests. |
| `.github/workflows/publish.yml` | npm publish and release with tokens/permissions. |
| `.github/workflows/agents.yml` | Agent config validation and README/package sync automation. |
| `package.json`, `pnpm-lock.yaml`, `build.config.mjs` | Dependency/build/release supply-chain metadata. |
