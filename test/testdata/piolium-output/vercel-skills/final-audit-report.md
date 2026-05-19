# Security Audit Report: vercel-labs/skills

## Executive Summary

The audit confirmed **14 security findings** against `vercel-labs/skills`: **0 Critical**, **4 High**, and **10 Medium**. The highest-risk issues cluster around the project's role as an AI-agent skill package manager: untrusted source strings cross into native `git` execution, project-scoped filesystem operations can escape via symlinked agent bases, and lockfile restore can install dependency-provided skills that were not listed in the lockfile. Medium findings further show cleartext transport acceptance, unbounded parser/fetch resource usage, weak skill identity constraints, and provenance gaps between GitHub discovery and snapshot installation. No inbound web service was identified; risk is primarily local developer/CI compromise and persistent downstream agent-instruction poisoning after a user or automation runs the CLI on attacker-influenced input.

## Summary of Findings

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 4 |
| Medium | 10 |
| **Total** | **14** |

All confirmed findings have executed PoCs and links to their detailed reports, PoC scripts, and evidence directories in the severity tables below.

## Findings by Severity

Report assembly verified that every directory under `piolium/findings/` contains `report.md` larger than 500 bytes. All confirmed findings include an executed PoC script and evidence directory.

### Critical

_No confirmed findings._

### High

| ID | Finding | PoC | Parent / Origin | Links |
|---|---|---|---|---|
| `p10-001` | Direct git URL/ref reaches vulnerable simple-git clone boundary | executed | -- | [piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/report.md](findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/report.md); [poc.sh](findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/poc.sh); [evidence](findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/) |
| `p10-002` | Recursive install copy dereferences untrusted skill symlinks | executed | -- | [piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/report.md](findings/p10-002-symlink-dereference-copies-out-of-tree-files/report.md); [poc.sh](findings/p10-002-symlink-dereference-copies-out-of-tree-files/poc.sh); [evidence](findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/) |
| `p10-009` | Project-scoped installs follow symlinked agent bases outside the project | executed | -- | [piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/report.md](findings/p10-009-project-scope-symlinked-agent-base-escape/report.md); [poc.sh](findings/p10-009-project-scope-symlinked-agent-base-escape/poc.sh); [evidence](findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/) |
| `p10-010` | `experimental_install` installs unlisted `node_modules` skills during lockfile restore | executed | -- | [piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/report.md](findings/p10-010-experimental-install-unlocked-node-modules-skills/report.md); [poc.js](findings/p10-010-experimental-install-unlocked-node-modules-skills/poc.js); [evidence](findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/) |

#### `p10-001` — Direct git URL/ref reaches vulnerable simple-git clone boundary

- **Severity:** High
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/report.md`](findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/poc.sh`](findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/poc.sh); [`piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/`](findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/)
- **Key Code Reference:** Source: `src/add.ts:895-942` (`runAdd(args)` parses the user `source`).; Parser: `src/source-parser.ts:220-386` accepts GitHub/GitLab/direct-git inputs and falls back to `{ type: 'git', url: input }`.; Sink: `src/git.ts:25-62` passes `url` and optional `['--branch', ref]` to `git.clone(url, tempDir, cloneOptions)`.
- **Summary:** The `skills add <source>#<ref>` path accepts attacker-controlled direct git sources and refs, then forwards them to `simple-git` without a first-party scheme or ref allowlist. The installed lockfile resolves `simple-git` to `3.30.0`, which the audit draft identified as affected by 2026 command/protocol bypass advisories fixed in `>=3.32.3`. A malicious skill publisher can therefore hand a victim or automation a crafted `skills add` command that crosses into native `git clone` execution under the developer/CI user's environment.
- **Impact:** A malicious skill publisher, README, issue comment, or automation input can provide a crafted `skills add <source>#<ref>` value that is interpreted as a direct git source and reaches `git clone`. When the underlying git/simple-git protocol or argument bypass is exploitable, the attacker can execute commands on the developer workstation or CI runner with that user's privileges. In practical terms, this can expose repository contents, SSH/Git credentials, package registry tokens, cloud credentials in environment variables, and any files readable by the process. Severity is High rather than Critical because exploitation requires a victim or automation to run the local CLI with attacker-influenced input.
- **Root Cause:** The implementation relies on `simple-git`/native `git` as the validation boundary for untrusted repository identifiers. Instead, the CLI should enforce its own allowlist before invoking `git clone`: accepted schemes, hosts, URL syntax, and ref syntax should be constrained by the `skills` CLI, and dangerous git protocols/configuration-driven transports should be rejected or disabled. This validation gap is amplified by the outdated `simple-git@3.30.0` version identified in the audit as affected by protocol/command bypass advisories.

#### `p10-002` — Recursive install copy dereferences untrusted skill symlinks

- **Severity:** High
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/report.md`](findings/p10-002-symlink-dereference-copies-out-of-tree-files/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/poc.sh`](findings/p10-002-symlink-dereference-copies-out-of-tree-files/poc.sh); [`piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/`](findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/)
- **Key Code Reference:** Install path: `src/add.ts` selected skills -> `installSkillForAgent()`.; Copy sink: `src/installer.ts:349-369` calls `cp(srcPath, destPath, { dereference: true, recursive: true })` for non-directory entries.
- **Summary:** Installing an attacker-controlled local or cloned skill can copy files from outside the skill repository into the victim's installed skill directory. The installer recursively copies skill contents with symlink dereferencing enabled, so a malicious skill can commit a symlink to a readable local path and have the target bytes materialized under `.agents/skills/<skill>` or the selected agent's skill directory.
- **Impact:** A malicious skill source can cause locally readable files at predictable paths to be copied into `.agents/skills/<skill>` or agent-specific skill directories during installation. The CLI does not itself upload the copied file, but the file is moved into locations that agents, project tooling, backups, or accidental commits may later read or expose. This can disclose tokens, configuration files, or other secrets that the user did not intend to place inside the project or installed-skill tree.
- **Root Cause:** The installer intentionally dereferences symlinks while copying untrusted skill contents, but it does not perform an `lstat`/`realpath` containment check against the source skill root before copying. Path traversal in the skill name is checked, but path traversal through symlink targets inside the skill tree is not. This allows external local files to be read and rewritten as regular installed skill files.

#### `p10-009` — Project-scoped installs follow symlinked agent bases outside the project

- **Severity:** High
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/report.md`](findings/p10-009-project-scope-symlinked-agent-base-escape/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/poc.sh`](findings/p10-009-project-scope-symlinked-agent-base-escape/poc.sh); [`piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/`](findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/)
- **Key Code Reference:** Lexical safety check: `src/installer.ts:63-67`.; Project canonical base: `src/installer.ts:84-86` returns `join(cwd, '.agents', 'skills')`.; Destructive/write operations: `src/installer.ts:125-130`, `src/installer.ts:281-292`, `src/installer.ts:617-652`, `src/installer.ts:754-785`.
- **Summary:** A malicious project checkout can commit `.agents` as a symlink to a directory outside the checkout. When a victim runs a project-scoped install, such as `skills add ./malicious-skill --agent codex --yes` without `--global`, the installer validates only normalized lexical paths under `cwd/.agents/skills`; the filesystem then follows the symlink and writes or replaces the skill outside the project, including under the victim's home agent skill base.
- **Impact:** A malicious repository can turn a project-scoped install into a write/delete primitive under any symlink target writable by the victim user. If `.agents` points to the victim's home agent base, the project can persist attacker-supplied skills outside the checkout, making them available to later agent sessions in other projects. Existing same-named skills at the redirected target may also be removed or overwritten by the install cleanup step. The attack requires the victim to run a project-scoped skill install or restore from the malicious checkout; normal OS filesystem permissions still limit the target.
- **Root Cause:** The installer enforces project scope with lexical path-prefix checks only. It never resolves the real path of the project agent base, the final target directory, or symlinked parent components before performing `rm()`, `mkdir()`, `copyDirectory()`, or `writeFile()`. As a result, project-controlled symlinks can redirect project-scoped operations across the project/global boundary.

#### `p10-010` — `experimental_install` installs unlisted `node_modules` skills during lockfile restore

- **Severity:** High
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/report.md`](findings/p10-010-experimental-install-unlocked-node-modules-skills/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/poc.js`](findings/p10-010-experimental-install-unlocked-node-modules-skills/poc.js); [`piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/`](findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/)
- **Key Code Reference:** Lock read: `src/install.ts:17-20`.; Node_modules entries collected: `src/install.ts:37-40`.; Broad sync with confirmation disabled: `src/install.ts:78-84`.
- **Summary:** `skills experimental_install` is intended to restore project skills from `skills-lock.json`, but the `node_modules` restore path treats the locked `node_modules` skill names only as a trigger. If the lockfile contains any legitimate `node_modules` skill, the command runs the broad `experimental_sync` engine with confirmations disabled, causing every discovered dependency-provided `SKILL.md` that is not already up to date to be installed into the project `.agents/skills` directory, even when that skill is absent from `skills-lock.json`.
- **Impact:** An attacker who controls any installed npm dependency can add a `SKILL.md` that becomes a persistent project skill when a developer restores skills from `skills-lock.json`, as long as the lockfile contains at least one legitimate `node_modules` skill. This bypasses both the lockfile review boundary and the normal sync confirmation prompt.
- **Root Cause:** The lockfile restore path delegates `node_modules` restoration to a broad discovery-and-sync operation without carrying forward the lockfile's intended allowlist. The locked names are used only as `nodeModuleSkills.length > 0`; they are not enforced as the set of skills that may be installed. The same path also disables the confirmation prompt by passing `yes: true`, so newly discovered dependency skills are treated as approved during what appears to be a lockfile restore.

### Medium

| ID | Finding | PoC | Parent / Origin | Links |
|---|---|---|---|---|
| `p10-003` | Cleartext HTTP well-known skill discovery can persist attacker-controlled skills | executed | -- | [piolium/findings/p10-003-http-well-known-skill-discovery/report.md](findings/p10-003-http-well-known-skill-discovery/report.md); [poc.py](findings/p10-003-http-well-known-skill-discovery/poc.py); [evidence](findings/p10-003-http-well-known-skill-discovery/evidence/) |
| `p10-004` | Unbounded well-known fetch and frontmatter parsing can hang CLI discovery | executed | -- | [piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/report.md](findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/report.md); [poc.js](findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/poc.js); [evidence](findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/evidence/) |
| `p10-005` | Duplicate skill names are silently first-wins | executed | -- | [piolium/findings/p10-005-duplicate-skill-name-first-wins/report.md](findings/p10-005-duplicate-skill-name-first-wins/report.md); [poc.py](findings/p10-005-duplicate-skill-name-first-wins/poc.py); [evidence](findings/p10-005-duplicate-skill-name-first-wins/evidence/) |
| `p10-006` | Blob snapshot installs are not verified against the resolved GitHub tree | executed | -- | [piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/report.md](findings/p10-006-blob-snapshot-not-verified-against-github-tree/report.md); [poc.py](findings/p10-006-blob-snapshot-not-verified-against-github-tree/poc.py); [evidence](findings/p10-006-blob-snapshot-not-verified-against-github-tree/evidence/) |
| `p10-007` | Path-relative `.well-known` discovery shadows origin-root RFC 8615 metadata | executed | -- | [piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/report.md](findings/p10-007-rfc8615-path-relative-well-known-shadowing/report.md); [poc.py](findings/p10-007-rfc8615-path-relative-well-known-shadowing/poc.py); [evidence](findings/p10-007-rfc8615-path-relative-well-known-shadowing/evidence/) |
| `p10-008` | Agent Skill `name` constraints are not enforced before deriving install directories | executed | -- | [piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/report.md](findings/p10-008-agent-skill-name-constraints-not-enforced/report.md); [poc.py](findings/p10-008-agent-skill-name-constraints-not-enforced/poc.py); [evidence](findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/) |
| `p12-001` | Cleartext HTTP Git Sources Allow MITM Skill Injection | executed | p10-003 | [piolium/findings/p12-cleartext-http-git-sources/report.md](findings/p12-cleartext-http-git-sources/report.md); [poc.py](findings/p12-cleartext-http-git-sources/poc.py); [evidence](findings/p12-cleartext-http-git-sources/evidence/) |
| `p12-002` | Unbounded SKILL.md frontmatter parsing from git, local, and package sources | executed | p10-004 | [piolium/findings/p12-unbounded-git-local-frontmatter-parse/report.md](findings/p12-unbounded-git-local-frontmatter-parse/report.md); [poc.py](findings/p12-unbounded-git-local-frontmatter-parse/poc.py); [evidence](findings/p12-unbounded-git-local-frontmatter-parse/evidence/) |
| `p12-003` | Project-scoped `skills remove` follows a symlinked agent base outside the project | executed | p10-009 | [piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/report.md](findings/p12-project-scope-remove-symlinked-agent-base-escape/report.md); [poc.sh](findings/p12-project-scope-remove-symlinked-agent-base-escape/poc.sh); [evidence](findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/) |
| `p12-004` | `experimental_sync` duplicate node_modules skill names overwrite installed skills | executed | p10-005 | [piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/report.md](findings/p12-node-modules-sync-duplicate-name-overwrite/report.md); [poc.js](findings/p12-node-modules-sync-duplicate-name-overwrite/poc.js); [evidence](findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/) |

#### `p10-003` — Cleartext HTTP well-known skill discovery can persist attacker-controlled skills

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-003-http-well-known-skill-discovery/report.md`](findings/p10-003-http-well-known-skill-discovery/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-003-http-well-known-skill-discovery/poc.py`](findings/p10-003-http-well-known-skill-discovery/poc.py); [`piolium/findings/p10-003-http-well-known-skill-discovery/evidence/`](findings/p10-003-http-well-known-skill-discovery/evidence/)
- **Key Code Reference:** Classification: `src/source-parser.ts:396-415` treats non-GitHub/GitLab `http://` URLs as well-known.; Provider match: `src/providers/wellknown.ts:63-85` accepts `http://` and `https://`.; Fetch sinks: `src/providers/wellknown.ts:134`, `:271`, and `:294`.
- **Summary:** The well-known skill provider accepts `http://` sources and fetches `index.json`, `SKILL.md`, and auxiliary files over cleartext transport. If a victim or automation installs from an insecure well-known URL, a network attacker or malicious proxy can modify those responses in transit and persist attacker-controlled skill instructions into the local agent skill directory. PoC status: **executed**.
- **Impact:** Observed impact: a cleartext well-known source can install attacker-controlled `SKILL.md` instructions and auxiliary files into the local project skill directory with no authentication. Practical exploitation requires the victim or an automation flow to install from an `http://` well-known URL while an attacker can modify network traffic, DNS/proxy behavior, or the HTTP origin. Once persisted, the modified skill may later be loaded by an AI agent running with the developer's project context and tool permissions, enabling downstream secret exposure, code tampering, or unsafe tool use depending on the agent configuration.
- **Root Cause:** Well-known discovery treats cleartext HTTP and HTTPS as equivalent trusted transports. The implementation validates only URL shape and host exclusions, then derives all discovery and file-download URLs from the attacker-supplied scheme without requiring TLS, warning, integrity verification, or a separate explicit `--allow-insecure-http` decision for noninteractive installs.

#### `p10-004` — Unbounded well-known fetch and frontmatter parsing can hang CLI discovery

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/report.md`](findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/poc.js`](findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/poc.js); [`piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/evidence/`](findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/evidence/)
- **Key Code Reference:** Index fetch: `src/providers/wellknown.ts:134`.; `SKILL.md` fetch/body read: `src/providers/wellknown.ts:271-278`.; Auxiliary file fetch/body read: `src/providers/wellknown.ts:294-296`.
- **Summary:** The well-known skills provider fetches attacker-controlled `index.json`, `SKILL.md`, and auxiliary files without explicit timeouts or response-size limits, then parses the entire `SKILL.md` YAML frontmatter without a size/depth guard. An anonymous malicious well-known host can keep a response open indefinitely or return oversized metadata/files, causing `skills add <url> --list -y` and similar noninteractive setup flows to hang or consume CPU/memory.
- **Impact:** This is an availability issue. A malicious or compromised well-known host can slow, hang, or resource-exhaust developer setup, CI bootstrap, or project restore flows that run well-known discovery noninteractively. The demonstrated effect is a CLI hang and unbounded processing of attacker-supplied bytes; no code execution or data disclosure was observed. Because errors are generally caught and the primary consequence is denial of service in automation, medium severity is appropriate.
- **Root Cause:** The well-known provider treats remote discovery content as trusted-sized input. It lacks defense-in-depth resource controls at every boundary: fetch deadlines, streaming byte limits, maximum index/auxiliary file counts, aggregate byte limits, and frontmatter/YAML complexity limits before parsing.

#### `p10-005` — Duplicate skill names are silently first-wins

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-005-duplicate-skill-name-first-wins/report.md`](findings/p10-005-duplicate-skill-name-first-wins/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-005-duplicate-skill-name-first-wins/poc.py`](findings/p10-005-duplicate-skill-name-first-wins/poc.py); [`piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/`](findings/p10-005-duplicate-skill-name-first-wins/evidence/)
- **Key Code Reference:** Discovery state: `src/skills.ts:108-109` initializes `seenNames`.; Priority-directory dedupe: `src/skills.ts:192-199` only pushes when `!seenNames.has(skill.name)`.; Recursive dedupe: `src/skills.ts:213-219` applies the same first-wins behavior.
- **Summary:** Skill discovery trusts the `name` value declared in each untrusted `SKILL.md` frontmatter and silently deduplicates by that name. In a catalog that contains two skills with the same name, the first path encountered is the only skill shown and installed, allowing an attacker-controlled skill to shadow a legitimate curated skill under a trusted name.
- **Impact:** Users who install skills from a multi-skill catalog can be misled into installing attacker-controlled instructions under a trusted skill name when an attacker can contribute a same-name skill in an earlier-discovered path. The demonstrated impact is provenance and review bypass for agent instructions: the CLI lists and installs only the attacker-controlled `trusted-build` implementation while dropping the legitimate duplicate silently. If the installed skill is later invoked by an agent with repository or secret access, the malicious instructions can influence code changes, build steps, or secret handling. This does not by itself prove automatic secret exfiltration; it proves that the wrong skill content can be selected and installed without any duplicate-name warning.
- **Root Cause:** Skill identity is based only on attacker-controlled frontmatter `name`, and duplicate identities are handled by silent first-wins filtering instead of fail-closed validation or path-scoped selection. The lock/install flow also records the selected name without preserving enough provenance to distinguish two same-name candidates during discovery.

#### `p10-006` — Blob snapshot installs are not verified against the resolved GitHub tree

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/report.md`](findings/p10-006-blob-snapshot-not-verified-against-github-tree/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/poc.py`](findings/p10-006-blob-snapshot-not-verified-against-github-tree/poc.py); [`piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/evidence/`](findings/p10-006-blob-snapshot-not-verified-against-github-tree/evidence/)
- **Key Code Reference:** GitHub tree/raw discovery: `src/blob.ts:84-123`, `src/blob.ts:249-265`.; Snapshot fetch: `src/blob.ts:270-287`.; Snapshot install write: `src/installer.ts:720-787`.
- **Summary:** The GitHub blob fast path for allowlisted owners (`vercel`, `vercel-labs`, and `heygen-com`) discovers skills from GitHub, but installs the actual file bodies returned by the separate `skills.sh` snapshot download API. Because those snapshot files are not checked against the resolved GitHub tree/ref before being written to the agent skill directory, a compromised or redirected snapshot service, or a process with control over `SKILLS_DOWNLOAD_URL`, can install skill instructions and auxiliary files that differ from the reviewed GitHub repository. Severity: Medium. CWE-494 (Download of Code Without Integrity Check) is the closest fit.
- **Impact:** A user can believe they installed a skill from a trusted, allowlisted GitHub repository and ref while actually persisting instructions and files supplied by a different service. In practical terms, compromise of the snapshot service, service misrouting, or local/process-level control of `SKILLS_DOWNLOAD_URL` can substitute malicious skill prompts, tool-use instructions, or helper files under `.agents/skills/<skill>/`. Those skills are later consumed by AI agents and the CLI warns that they run with full agent permissions, so the substituted instructions can influence future agent behavior in the user's project. Exposure is reduced by the owner allowlist and by fallback to clone when the snapshot API fails, but those controls do not provide end-to-end integrity for successful blob installs.
- **Root Cause:** The blob fast path relocates trust from GitHub to a separate snapshot service after GitHub has only been used for discovery and frontmatter parsing. The resolved GitHub tree/ref is not bound to the installed payload: snapshot paths are not required to exist in the tree, snapshot contents are not compared to GitHub blob SHAs or raw contents, and the snapshot `hash` is not verified against a GitHub-derived value before installation.

#### `p10-007` — Path-relative `.well-known` discovery shadows origin-root RFC 8615 metadata

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/report.md`](findings/p10-007-rfc8615-path-relative-well-known-shadowing/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/poc.py`](findings/p10-007-rfc8615-path-relative-well-known-shadowing/poc.py); [`piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/evidence/`](findings/p10-007-rfc8615-path-relative-well-known-shadowing/evidence/)
- **Key Code Reference:** `src/providers/wellknown.ts:101-129` builds path-relative URLs first, then root URLs. `src/providers/wellknown.ts:132-158` returns the first valid index.
- **Summary:** The well-known skills provider treats a user-supplied URL path as part of the discovery scope and probes `{requested-path}/.well-known/...` before the origin-root `/.well-known/...` location defined by RFC 8615. On shared or trusted origins where an attacker controls only a path such as `/users/evil/`, the attacker can publish path-local well-known skill metadata and have it selected instead of the vetted origin-root skill index when a victim installs from that path.
- **Impact:** An attacker who can publish files under a path on a shared or otherwise trusted origin can cause victims installing from that path to receive attacker-controlled agent instructions and skill files, even when the origin root publishes different vetted well-known metadata. The installed skill runs with the normal permissions granted to the target agent, so the practical consequence is malicious or untrusted agent behavior under the apparent trust of the shared hostname. Exploitation requires a shared-origin/path-control setup and a victim installing from the attacker-controlled path, so this is best treated as Medium severity rather than a universal remote compromise.
- **Root Cause:** The implementation conflates a convenience extension for path-scoped discovery with RFC 8615 origin-root well-known discovery. Because the path-relative candidate is tried first and accepted on basic schema validity alone, path-scoped content can shadow origin-wide metadata on the same host. The trust decision is therefore based on the URL path supplied by the installer rather than the origin-root well-known namespace.

#### `p10-008` — Agent Skill `name` constraints are not enforced before deriving install directories

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/report.md`](findings/p10-008-agent-skill-name-constraints-not-enforced/report.md)
- **PoC / Evidence:** [`piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/poc.py`](findings/p10-008-agent-skill-name-constraints-not-enforced/poc.py); [`piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/`](findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/)
- **Key Code Reference:** `src/skills.ts:29-59` only type-checks and terminal-sanitizes `data.name`.; `src/installer.ts:40-54` sanitizes arbitrary names rather than rejecting invalid ones.; `src/installer.ts:245-247` derives the install directory from `skill.name || basename(skill.path)`.
- **Summary:** The skills CLI accepts attacker-controlled `SKILL.md` frontmatter names that violate the Agent Skills naming rules, then derives the persistent install directory from a lossy sanitized version of that name. A malicious skill whose source directory is not trusted can therefore normalize into a trusted or already-installed skill namespace and overwrite or shadow that skill.
- **Impact:** An attacker who can supply a skill source, or a well-known index entry, can choose an invalid name that normalizes to an existing or trusted skill namespace. When a user or automation installs that source, the malicious skill can shadow or overwrite the trusted skill under `.agents/skills/<name>`, misleading users and downstream agents about the skill's provenance. Because installed skills are later consumed by AI agents and the CLI warns that they run with full agent permissions, the practical impact is trusted-skill replacement and agent instruction/tooling manipulation. Path traversal outside the skills directory is not demonstrated here; the observed issue is namespace/provenance confusion and overwrite within the skill installation root.
- **Root Cause:** The implementation confuses display/path sanitization with specification validation. Invalid, attacker-supplied skill names are canonicalized into filesystem-safe names and then trusted as stable identifiers. Because there is no fail-closed validation against the Agent Skills naming rules and no check that the frontmatter `name` equals the `SKILL.md` parent directory, different sources can collapse into the same installed namespace.

#### `p12-001` — Cleartext HTTP Git Sources Allow MITM Skill Injection

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p12-cleartext-http-git-sources/report.md`](findings/p12-cleartext-http-git-sources/report.md)
- **PoC / Evidence:** [`piolium/findings/p12-cleartext-http-git-sources/poc.py`](findings/p12-cleartext-http-git-sources/poc.py); [`piolium/findings/p12-cleartext-http-git-sources/evidence/`](findings/p12-cleartext-http-git-sources/evidence/)
- **Variant Origin:** `p10-003`
- **Key Code Reference:** `src/source-parser.ts:304-325` captures `(https?)` for arbitrary GitLab-style tree URLs and returns `${protocol}://${hostname}/... .git`, preserving `http://`.; `src/source-parser.ts:394-405` excludes `.git` URLs from well-known handling, after which `src/source-parser.ts:382-386` falls back to `{ type: 'git', url: input }` for direct git URLs.; `src/add.ts:1051-1056` sends GitLab and generic git sources to `cloneRepo(parsed.url, parsed.ref)`.
- **Summary:** `skills add` accepts custom GitLab tree URLs and direct `.git` URLs over `http://`, preserves the cleartext scheme when deriving the clone URL, and installs the cloned `SKILL.md` content into agent skill directories. A network attacker between the user and the Git server can replace repository contents in transit, causing attacker-controlled skill instructions and auxiliary files to persist locally.
- **Impact:** Users who install skills from copied custom GitLab tree URLs or direct Git URLs over cleartext HTTP can receive attacker-modified skill content. The demonstrated effect is persistent installation of attacker-controlled `SKILL.md` instructions and files under the victim project's `.agents/skills` directory. When a compatible coding agent later loads that skill, the malicious instructions may influence agent behavior with the user's project permissions. Exploitability requires the user to add an `http://` Git source or an attacker to provide/modify such a source, and a network position capable of altering cleartext Git traffic.
- **Root Cause:** Remote Git sources are normalized and cloned without enforcing transport integrity. The parser treats `http://` and `https://` as equally valid for custom GitLab tree URLs, preserves direct `http://...git` inputs, and the installer later trusts the cloned repository contents without an HTTPS-only policy, commit pin, signature check, or explicit insecure-transport opt-in.

#### `p12-002` — Unbounded SKILL.md frontmatter parsing from git, local, and package sources

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p12-unbounded-git-local-frontmatter-parse/report.md`](findings/p12-unbounded-git-local-frontmatter-parse/report.md)
- **PoC / Evidence:** [`piolium/findings/p12-unbounded-git-local-frontmatter-parse/poc.py`](findings/p12-unbounded-git-local-frontmatter-parse/poc.py); [`piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/`](findings/p12-unbounded-git-local-frontmatter-parse/evidence/)
- **Variant Origin:** `p10-004`
- **Key Code Reference:** `src/skills.ts:29-35` reads `SKILL.md` with `readFile(..., 'utf-8')` and calls `parseFrontmatter(content)`.; `src/frontmatter.ts:8-15` applies an unbounded frontmatter regex and `parseYaml(match[1]!)`.; `src/add.ts:1041-1056` clones remote git/GitHub/GitLab sources and calls `discoverSkills()`, which reaches `parseSkillMd()`.
- **Summary:** This p12 variant of the earlier well-known frontmatter parsing issue lets an attacker-controlled skill repository, local checkout, or npm package provide a large or pathological `SKILL.md` YAML frontmatter block that the `skills` CLI reads and parses without byte, depth, or parser-resource limits. When a victim or CI job runs `skills add`/`skills experimental_sync` against that source, the local Node process can consume excessive memory/CPU and abort.
- **Impact:** A malicious skill source can crash or hang noninteractive developer setup, bootstrap, restore, or CI flows that install or sync skills from untrusted git repositories, local checkouts, or npm dependencies. The demonstrated payload is small enough to live in a normal git repository and requires no authentication beyond convincing the victim workflow to process the source. The PoC used a constrained heap to make the abort deterministic; on default heaps, the same absence of limits still allows proportionally larger frontmatter payloads or deeply nested YAML to consume excessive local resources.
- **Root Cause:** The implementation treats skill metadata from untrusted repositories and packages as small, trusted local input. It performs full-file reads and unbounded YAML parsing before applying any resource guard, so attacker-controlled `SKILL.md` contents cross the repository/package trust boundary directly into a memory- and CPU-intensive parser. This is an uncontrolled resource consumption issue (CWE-400).

#### `p12-003` — Project-scoped `skills remove` follows a symlinked agent base outside the project

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/report.md`](findings/p12-project-scope-remove-symlinked-agent-base-escape/report.md)
- **PoC / Evidence:** [`piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/poc.sh`](findings/p12-project-scope-remove-symlinked-agent-base-escape/poc.sh); [`piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/`](findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/)
- **Variant Origin:** `p10-009`
- **Key Code Reference:** `src/remove.ts:42-51` scans project-scope canonical and agent-specific directories under `cwd`.; `src/remove.ts:157-180` computes cleanup paths using `getInstallPath()`/agent directories and calls `rm(pathToCleanup, { recursive: true, force: true })`.; `src/remove.ts:196-207` removes the canonical path with `rm(canonicalPath, { recursive: true, force: true })`.
- **Summary:** `skills remove` is intended to operate on project-local skills when `--global` is not supplied, but the project-scope removal path builds `.agents` and agent-specific paths from `cwd` without resolving symlinked parent directories before recursively deleting them. A malicious repository can include `.agents -> ../outside` (or another outside target); when a victim runs `skills remove <name> -y` from that checkout, the CLI deletes the matching skill directory in the symlink target instead of staying inside the project.
- **Impact:** A malicious repository can cause a user who runs `skills remove` in project scope to delete skills outside that repository. This can disrupt other projects that share the target directory and can remove persistent agent instructions, guardrail skills, or other local skill content the user did not intend to modify. Exploitation requires control of the project checkout contents and user execution of the remove command; it is not a remote unauthenticated service-side issue.
- **Root Cause:** Project scope is enforced with string-based path construction and lexical prefix checks, not filesystem-resolved containment. The removal code trusts project-relative agent base directories such as `.agents/skills` even when an attacker-controlled checkout makes an ancestor component a symlink. The destructive `rm(..., { recursive: true, force: true })` calls therefore operate on the symlink target while the CLI still believes it is removing a project-local skill.

#### `p12-004` — `experimental_sync` duplicate node_modules skill names overwrite installed skills

- **Severity:** Medium
- **PoC Status:** executed
- **Report:** [`piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/report.md`](findings/p12-node-modules-sync-duplicate-name-overwrite/report.md)
- **PoC / Evidence:** [`piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/poc.js`](findings/p12-node-modules-sync-duplicate-name-overwrite/poc.js); [`piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/`](findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/)
- **Variant Origin:** `p10-005`
- **Key Code Reference:** `src/sync.ts:45-77` pushes every parsed package skill into `discoveredSkills` without duplicate-name rejection.; `src/sync.ts:171-181` checks `localLock.skills[skill.name]`, using only the untrusted frontmatter name as identity.; `src/sync.ts:324-333` installs every queued skill to the same sanitized canonical destination through `installSkillForAgent()`.
- **Summary:** `skills experimental_sync` trusts dependency-controlled `SKILL.md` frontmatter `name` values as the sole identity for skills discovered in `node_modules`. If a malicious or compromised dependency declares the same name as a legitimate dependency skill, both entries are installed to the same `.agents/skills/<name>` destination and written to the same `skills-lock.json` key, allowing the later install to replace the legitimate skill's instructions and provenance.
- **Impact:** A malicious npm dependency can persist attacker-controlled agent skill instructions under the same visible skill name as a legitimate dependency. After `experimental_sync`, the victim sees a single `.agents/skills/shared-name` directory and a single `skills-lock.json` entry sourced from the malicious package, while the legitimate instructions are removed. If an AI coding agent later loads that skill, the attacker can influence agent behavior through the installed instructions. The practical severity depends on whether projects run `experimental_sync` over untrusted dependencies and what permissions the consuming agent has, but the demonstrated effect is a reliable local supply-chain overwrite of skill content and provenance.
- **Root Cause:** The implementation uses dependency-controlled skill names as a global project namespace without enforcing uniqueness, namespacing them by package, or requiring an explicit conflict decision. The installer compounds that identity bug by destructively recreating the canonical directory for each queued skill, so duplicate names overwrite prior contents instead of failing closed.

## Attack Surface Summary

The project is a TypeScript/Node CLI and package-manager-style installer for AI-agent skills. It has no inbound HTTP route surface, but it crosses several high-value local and outbound trust boundaries: user/automation-controlled CLI arguments, native `git` subprocess execution, arbitrary HTTP(S)/well-known fetches, GitHub/raw/skills.sh snapshot downloads, local filesystem writes/removals under project and home agent directories, lockfile-driven update/restore, `node_modules` discovery, telemetry/search APIs, and GitHub Actions release workflows.

Key attack-surface artifacts:

- [Knowledge base / architecture and threat model](attack-surface/knowledge-base-report.md) (`piolium/attack-surface/knowledge-base-report.md`)
- [Architecture entrypoints](attack-surface/architecture-entrypoints.md) (`piolium/attack-surface/architecture-entrypoints.md`)
- [Manual attack-surface inventory](attack-surface/manual-attack-surface-inventory.md) (`piolium/attack-surface/manual-attack-surface-inventory.md`)
- [Public routes and authz matrix](attack-surface/public-routes-authz-matrix.md) (`piolium/attack-surface/public-routes-authz-matrix.md`)
- [Source-to-sink flow summary](attack-surface/source-sink-flows-all-severities.md) (`piolium/attack-surface/source-sink-flows-all-severities.md`)
- [Spec-gap summary](attack-surface/spec-gap-summary.md) (`piolium/attack-surface/spec-gap-summary.md`)
- [State/concurrency summary](attack-surface/state-concurrency-summary.md) (`piolium/attack-surface/state-concurrency-summary.md`)
- [SAST merged SARIF](attack-surface/sast-merged.sarif) (`piolium/attack-surface/sast-merged.sarif`)
- [Advisory summary](attack-surface/advisory-summary.md) (`piolium/attack-surface/advisory-summary.md`)
- [Advisory inventory JSON](attack-surface/advisory-inventory.json) (`piolium/attack-surface/advisory-inventory.json`)
- [Patch bypass summary](attack-surface/patch-bypass-summary.md) (`piolium/attack-surface/patch-bypass-summary.md`)
- [Deep probe summary](attack-surface/deep-probe-summary.md) (`piolium/attack-surface/deep-probe-summary.md`)
- [Cross-service edge inventory](attack-surface/cross-service-edges.json) (`piolium/attack-surface/cross-service-edges.json`)
- [Raw advisory/domain-research artifacts](attack-surface/raw/) (`piolium/attack-surface/raw/`)

Primary modeled high-risk boundaries:

- **Native git boundary:** `skills add <source>#<ref>` routes attacker-influenced URLs/refs to `simple-git`/native git.
- **Agent skill persistence boundary:** installed `SKILL.md` and auxiliary files become durable instructions for downstream coding agents.
- **Filesystem boundary:** project/global agent paths are computed from `cwd`/home and can be affected by symlink and realpath semantics.
- **HTTP/snapshot boundary:** well-known indexes/files and `skills.sh` snapshots provide content that is later written locally.
- **Package/dependency boundary:** `experimental_sync` and lockfile restore consume dependency-controlled `node_modules/**/SKILL.md`.
- **CI/release boundary:** workflows publish the npm CLI package; no AI agent actions were detected, but release settings and dependency scripts remain supply-chain controls.

## Coverage Gaps

- **Cold-review gap:** `piolium/adversarial-reviews/stage11-blocked.md` records that one cold-verification stage could not start because no single draft path was provided. High findings nevertheless have executed PoCs in their finding directories, but an isolated adversarial re-review should be rerun before disclosure if strict P9/P11 evidence is required.
- **Repository settings not externally verified:** branch protection, environment protection, npm token scoping, workflow-dispatch actor restrictions, and GitHub secret policies are outside the source tree. See [`piolium/authz-coverage-gaps.md`](authz-coverage-gaps.md).
- **Distributed bundle parity:** the source audit focused on `src/**/*.ts`, workflows, and CLI source; `dist/cli.mjs` was not present in the scanned source tree, so source-to-published-bundle parity remains a release validation task.
- **Advisory collection limits:** earlier GitHub API advisory collection had authentication/401 gaps, so private or repository-scoped security advisories may be incomplete.
- **Downstream agent behavior:** the audit treats installed skills as high-impact because agents may read/write files and use tools, but each downstream agent's sandbox/tool-permission model was not dynamically verified.
- **Platform coverage:** macOS/Linux-style PoCs were executed for confirmed issues; Windows-specific shell, junction, and symlink behavior should receive separate dynamic testing.
- **Fuzzing breadth:** PoCs demonstrate the confirmed exploit paths, but broad parser, URL, lockfile, and filesystem race fuzzing outside those paths was not exhaustive.

## Methodology Notes

- **Intelligence gathering:** dependency/advisory inventory, patch-bypass analysis, GitHub/npm/OSV/NVD data collection, and domain research for simple-git, YAML/frontmatter parsing, well-known URI handling, AI-agent skill supply chain, and symlink/path traversal.
- **Knowledge-base construction:** architecture inventory, DFD/CFD slices, trust-boundary mapping, threat model, source/sink inventory, spec-gap candidates, state/concurrency analysis, and authorization-surface notes were consolidated under `piolium/attack-surface/`.
- **Static analysis:** CodeQL structural extraction and custom source-to-sink queries, Semgrep Pro security suites/custom rules, SARIF merging, and agentic-actions workflow review. The merged SAST artifact contains 113 results and is linked above.
- **Review chambers:** `6` chamber clusters reviewed `13` hypotheses; `10` survived into P10 and `3` were dropped as false positives or insufficient. `10` attack patterns were registered in [`piolium/attack-pattern-registry.json`](attack-pattern-registry.json).
- **Variant analysis:** `4` Medium+ variants were retained in Stage 12 and are summarized in [`piolium/variant-summary.md`](variant-summary.md).
- **PoC/report completeness:** `14` finding directories were checked; every `report.md` is present and >500 bytes, every finding has `draft.md`, and every finding includes a `poc.sh`, `poc.py`, or `poc.js`.
- **Prioritization:** severity reflects realistic attacker preconditions for a local CLI: Critical would require broadly reachable pre-install command execution or release-token compromise; High covers developer/CI command execution, filesystem escape, or silent durable agent-skill poisoning; Medium covers MITM/provenance/resource/identity issues requiring user or automation interaction.

### Consistency Check Notes

Assembly checks passed for finding report size, finding completeness, Low-severity leakage, stale top-level legacy reports, major KB sections, and CodeQL artifact presence. `validate_phase_output.py 10 piolium/` passed. `validate_phase_output.py all piolium/` failed because the legacy validator expects different phase-output mapping/names: four P12 `findings-draft/` files were not matched to their promoted `piolium/findings/` directories, and it flagged root-level/support directories or files (`attack-surface/`, `bypass-analysis/`, `agentic-actions-res/`, `tmp/`, `authz-coverage-gaps.md`, `variant-summary.md`) as orphan/unexpected.

## Conclusion

`vercel-labs/skills` has a security-sensitive design because it installs third-party instructions into directories consumed by powerful local AI agents. The most important remediation themes are: enforce strict source/ref/protocol validation before native git execution, use realpath-aware filesystem containment for writes/removals/copies, make lockfile restore honor exact allowlists, require secure transport and end-to-end snapshot integrity, and reject ambiguous or invalid skill identities. Until those areas are hardened, users should treat arbitrary remote skills, project checkouts, and dependency-provided skills as untrusted executable supply-chain inputs.
