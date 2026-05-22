# Advisory Summary — Stage 01 Intelligence & Dependency Risk

## Advisory Intelligence

Generated: 2026-05-01  
Target: `/Users/j3ssie/Desktop/oss-to-run/skills` (`vercel-labs/skills`)

### Advisory Inventory

**Collection result:** no published CVE/GHSA/OSV/NVD advisory was found for the npm package `skills` or for the GitHub repo `vercel-labs/skills` itself. One non-indexed first-party security issue was found via supplementary GitHub issue search (#353, namespace-squatting in skill discovery). The remaining entries below are dependency advisories and active lockfile advisories that shape the project’s reachable attack surface.

| ID | Scope | Severity / CVSS | Affected component | Affected versions / current status | Patch commit(s) / version | CWE | Source | Summary |
|---|---|---:|---|---|---|---|---|---|
| GHSA-r275-fr43-pm7q / CVE-2026-28292 | Dependency (runtime bundled) | CRITICAL / 9.8 | simple-git git subprocess / clone path | simple-git >=3.15.0 <3.32.3; current lock 3.30.0 is affected and bundled in dist | simple-git 3.32.3; commit f7042088aa2dac59e3c49a84d7a2f4b26048a257 | CWE-78, CWE-178 | OSV, NVD, pnpm audit | Case-insensitive protocol.allow config bypass in simple-git unsafe-operation blocking enables RCE. |
| GHSA-mw96-cpmx-2vgc / CVE-2026-27606 | Transitive dependency (active dev/build) | CRITICAL / 9.8 | Rollup build artifact writer | rollup >=4.0.0 <4.59.0; current 4.55.1 via Vite/Vitest is affected | rollup 4.59.0; commits c60770d, c8cf1f9, d6dee5e | CWE-22 | OSV, NVD, pnpm audit | Path traversal in Rollup 4 can write files outside the intended output directory. |
| GHSA-9crc-q9x8-hgqq / CVE-2025-24964 | Dependency (historical dev/test) | CRITICAL / 9.6 | Vitest API server / browser-to-localhost dev server | vitest 0.x/1.x/2.x/3.x before 1.6.1/2.1.9/3.0.5; current 4.0.18 not affected | vitest 1.6.1, 2.1.9, 3.0.5; commits 191ef9e, 7ce9fbb, e0fe1d8 | CWE-1385 | OSV, NVD | Malicious website can reach a listening Vitest API server and trigger remote code execution. |
| GHSA-jcxm-m3jx-f287 / CVE-2026-28291 | Dependency (runtime bundled) | HIGH / 8.1 | simple-git option parser / git argv boundary | simple-git <3.32.0; current lock 3.30.0 is affected and bundled in dist | simple-git 3.32.0; commit 1effd8e5012a5da05a9776512fac3e39b11f2d2d | CWE-78 | OSV, NVD, pnpm audit | Option parsing bypass allows attacker-controlled values to execute arbitrary git/native commands. |
| GHSA-v2wj-q39q-566r / CVE-2026-39364 | Transitive dependency (active dev/test) | HIGH / 7.5 | Vite dev server fs deny checks | vite >=7.1.0 <7.3.2; current 7.3.1 via Vitest is affected | vite 7.3.2 / 8.0.5; commit a9a3df299378d9cbc5f069e3536a369f8188c8ff | CWE-180, CWE-284 | OSV, NVD, pnpm audit | Query handling bypasses Vite server.fs.deny and exposes denied files. |
| GHSA-p9ff-h696-f583 / CVE-2026-39363 | Transitive dependency (active dev/test) | HIGH / 7.5 | Vite dev server WebSocket | vite 6.x/7.x below 6.4.2/7.3.2/8.0.5; current 7.3.1 via Vitest is affected | vite 7.3.2 / 8.0.5; commit f02d9fde0b195afe3ea2944414186962fbbe41e0 | CWE-200, CWE-306 | OSV, NVD, pnpm audit | Unauthenticated WebSocket access can read arbitrary files from the Vite dev server context. |
| GHSA-737v-mqg7-c878 / CVE-2026-35209 | Transitive dependency (active build config) | HIGH / 7.5 | defu recursive defaults merge | defu <=6.1.4; current 6.1.4 via obuild/c12 is affected | defu 6.1.5; commit 3942bfbbcaa72084bd4284846c83bd61ed7c8b29 | CWE-1321 | OSV, NVD, pnpm audit | Prototype pollution via __proto__ in defaults argument when unsanitized objects are merged. |
| GHSA-c2c7-rcm5-vvqj / CVE-2026-33671 | Transitive dependency (active glob parsing) | HIGH / 7.5 | picomatch glob parser | picomatch <2.3.2 / 3.x<3.0.2 / 4.x<4.0.4; current 2.3.1 and 4.0.3 are affected | picomatch 2.3.2 / 4.0.4; commit 5eceecd27543b8e056b9307d69e105ea03618a7d | CWE-1333 | OSV, NVD, pnpm audit | ReDoS via extglob quantifiers in glob patterns. |
| GitHub issue #353 (non-indexed) | Project disclosure signal | HIGH / n/a | Skill discovery / name deduplication / install naming | Reported on skills 1.3.8; issue remains open; current code still deduplicates by frontmatter name | PR #356 proposed but open/unmerged; no local patch commit | CWE-345/CWE-829 (inferred) | GitHub issue/PR supplementary API search | Namespace-squatting: attacker-controlled SKILL.md can claim a legitimate frontmatter name and shadow the intended skill. |
| GHSA-f9xv-q969-pqx4 / CVE-2023-2251 | Dependency (historical parser) | HIGH / 7.5 | yaml frontmatter parser | yaml >=2.0.0-5 <2.2.2; current 2.8.3 not affected | yaml 2.2.2; commit 984f5781ffd807e58cad3b5c8da1f940dab75fba | CWE-248 | OSV, NVD | Uncaught exception in yaml parser can crash consumers on crafted input. |
| GHSA-9w5j-4mwv-2wj8 / CVE-2022-25860 | Dependency (historical git/RCE) | HIGH / 8.1 | simple-git clone/pull/push/listRemote | simple-git <3.16.0; current 3.30.0 not affected by this older issue | simple-git 3.16.0; commits ec97a39, 9545931 | CWE-78, CWE-94 | OSV, NVD | RCE through crafted git options/URLs in high-risk simple-git operations. |
| GHSA-9p95-fxvg-qgq2 / CVE-2022-25912 | Dependency (historical git/RCE) | HIGH / 8.1 | simple-git ext transport protocol | simple-git <3.15.0; current 3.30.0 not affected by this older issue | simple-git 3.15.0; commit 774648049eb3e628379e292ea172dccaba610504 | CWE-78 | OSV, NVD | RCE when enabling Git ext transport protocol via clone/fetch style operations. |
| GHSA-28xr-mwxg-3qc8 / CVE-2022-24066 | Dependency (historical git injection) | HIGH / 8.1 | simple-git argument construction | simple-git <3.5.0; current 3.30.0 not affected by this older issue | simple-git 3.5.0; commit 2040de601c894363050fef9f28af367b169a56c5 | CWE-88 | OSV, NVD | Incomplete command-injection fix in simple-git argument handling. |
| GHSA-3f95-r44v-8mrg / CVE-2022-24433 | Dependency (historical git injection) | HIGH / 8.1 | simple-git fetch argument injection | simple-git <3.3.0; current 3.30.0 not affected by this older issue | simple-git 3.3.0; PR #767 | CWE-88 | OSV, NVD | Argument injection in simple-git fetch(remote, branch) style calls. |
| GHSA-qx2v-qp2m-jg93 / CVE-2026-41305 | Transitive dependency (active CSS stringify) | MEDIUM / 6.1 | PostCSS CSS stringifier | postcss <8.5.10; current 8.5.6 via Vite is affected | postcss 8.5.10 | CWE-79 | OSV, NVD, pnpm audit | Unescaped </style> in CSS stringify output can produce XSS in consumers that embed output into HTML. |
| GHSA-4w7w-66w2-5vf9 / CVE-2026-39365 | Transitive dependency (active dev/test) | MEDIUM / 5.3 | Vite optimized dependency sourcemap handling | vite 6.x/7.x below 6.4.2/7.3.2/8.0.5; current 7.3.1 via Vitest is affected | vite 7.3.2 / 8.0.5; commit 79f002f2286c03c88c7b74c511c7f9fc6dc46694 | CWE-22 | OSV, NVD, pnpm audit | Path traversal in optimized dependency .map request handling. |
| GHSA-3v7f-55p6-f55p / CVE-2026-33672 | Transitive dependency (active glob parsing) | MEDIUM / 5.3 | picomatch POSIX class handling | picomatch <2.3.2 / 3.x<3.0.2 / 4.x<4.0.4; current 2.3.1 and 4.0.3 are affected | picomatch 2.3.2 / 4.0.4; commit 4516eb521f13a46b2fe1a1d2c9ef6b20ddc0e903 | CWE-1321 | OSV, NVD, pnpm audit | Method injection in POSIX character classes can alter glob matching results. |
| GHSA-48c2-rrv3-qjmp / CVE-2026-33532 | Dependency (historical/runtime parser) | MEDIUM / 4.3 | yaml nested collection parser | yaml 2.x <2.8.3 and 1.x <1.10.3; current 2.8.3 is fixed | yaml 2.8.3 / 1.10.3; commit 1e84ebbea7ec35011a4c61bbb820a529ee4f359b | CWE-674 | OSV, NVD | Deeply nested YAML collections can trigger stack overflow / availability impact. |

#### Historical coverage metadata

- **Tier reached:** Tier 2 (all-time). Tier 1 recent first-party/package advisories were below the 15-advisory signal threshold; collection expanded to all-time and dependency/ecosystem advisories for pattern coverage.
- **Total advisories/signals collected:** 18 total in the table: 1 first-party non-indexed issue, 17 dependency advisories. Recent 2yr: 13. Older: 5.
- **Exact target package/repo advisories:** 0 structured advisories from OSV (`npm/skills`), GitHub repo security advisories, GitHub advisory `affects=skills`, and NVD exact `vercel-labs skills`/`npm skills` all-time queries.
- **Severity distribution:** CRITICAL: 3, HIGH: 11, MEDIUM: 4, LOW: 0. Medium coverage is represented; no low-severity advisories were found for exact target or relevant dependencies.
- **Repository identity:** `vercel-labs/skills` resolved via git remote (`origin`). `OWNER=vercel-labs`, `REPO=skills`.
- **Git history available:** true (per `PIGOLIUM_GIT_AVAILABLE` default and `git rev-parse` actual check).
- **Coverage gaps recorded:**
  - Source 2 primary `gh api` GitHub Security Advisory GraphQL/REST attempts failed with HTTP 401 `Bad credentials`; unauthenticated curl fallback found 0 repo advisories and 0 `affects=skills` advisories, but this is not full `gh api` coverage.
  - NVD two-year date-window query returned HTTP 404 (public API date-window restriction); all-time exact and generic keyword queries were used instead. Generic `keywordSearch=skills` returned 15 unrelated skill/AI-skill advisories and was excluded from the target inventory.
  - Patch-commit discovery for first-party CVE/GHSA advisories was not applicable because there are no indexed first-party CVE/GHSA records. For non-indexed issue #353, PR #356 is open/unmerged; no local merged patch commit exists. Dependency patch commits were captured from OSV references where available.
- **Raw evidence retained:** `piolium/attack-surface/raw/` contains local grep, OSV, NVD, pnpm audit/outdated/why, npm metadata, GitHub issue/PR fallback, and patch-reference artifacts.

### Vulnerability Pattern Analysis

#### Component Vulnerability Heatmap

| Rank | Component / module | Count | Severity distribution | Dominant bug types | Phase priority |
|---:|---|---:|---|---|---|
| 1 | `simple-git` / `src/git.ts` clone boundary | 6 | 1 Critical, 5 High | Command/argument injection, git option parsing bypass, RCE | **HIGH-HEAT**: runtime-bundled dependency mediates user-supplied repository URLs/refs. |
| 2 | Vite/Vitest/Rollup/PostCSS dev/build stack | 6 | 2 Critical, 2 High, 2 Medium | Dev-server file read/RCE, build path traversal/write, XSS in generated output | **HIGH-HEAT**: mostly CI/dev, but severe if dev servers/build inputs are exposed or attacker-controlled. |
| 3 | Skill discovery/install naming (`src/skills.ts`, `src/installer.ts`) | 1 first-party signal | 1 High | Namespace squatting, duplicate-name shadowing, untrusted content selection | **HIGH-HEAT by impact**: project-specific supply-chain installation path. |
| 4 | Glob/config parser stack (`picomatch`, `defu`, lock/build config) | 3 | 2 High, 1 Medium | ReDoS, method/prototype pollution | **HIGH-HEAT**: parser/config bugs recur in build and discovery helpers. |
| 5 | YAML frontmatter parser (`src/frontmatter.ts`, `src/skills.ts`) | 2 | 1 High, 1 Medium | Parser crash/DoS, stack overflow | Watch: runtime parser for untrusted remote `SKILL.md` metadata. |

#### Bug Type Recurrence

| Bug class | CWEs | Count | Examples | Phase 8 priority |
|---|---|---:|---|---|
| Command injection / RCE | CWE-78, CWE-88, CWE-94, CWE-1385 | 7 | simple-git CVE-2022-24433/24066/25912/25860/2026-28291/28292; Vitest CVE-2025-24964 | **Mandatory** |
| Path traversal / arbitrary file read-write / access-control bypass | CWE-22, CWE-23, CWE-180, CWE-200, CWE-284, CWE-306 | 4 active + broader Vite history | Rollup CVE-2026-27606; Vite CVE-2026-39363/39364/39365 | **Mandatory** |
| Parser DoS / resource exhaustion | CWE-674, CWE-1333, CWE-248 | 4 | yaml CVE-2026-33532/CVE-2023-2251; picomatch CVE-2026-33671 | **Mandatory** |
| Prototype/method pollution | CWE-1321 | 2 | defu CVE-2026-35209; picomatch CVE-2026-33672 | **Mandatory** |
| XSS / generated-output injection | CWE-79 | 1 active + historical Vite/Rollup DOM clobbering | PostCSS CVE-2026-41305; historical Vite/Rollup DOM clobbering advisories | Opportunistic |
| Supply-chain namespace confusion | CWE-345/CWE-829 (inferred) | 1 first-party signal | GitHub issue #353: duplicate frontmatter `name` shadows intended skill | **Mandatory** |

#### Attack Surface Trends

1. **Untrusted git/source input -> native git subprocess:** `skills add <source>` accepts GitHub/GitLab shorthand, arbitrary git URLs, refs, and subpaths; `src/git.ts` delegates clone to bundled `simple-git`.
2. **Remote/local skill metadata parsing -> install decisions:** `SKILL.md` YAML frontmatter controls display name, description, filtering, dedupe, and installation directory naming.
3. **Filesystem installation boundary:** canonical `.agents/skills/<name>` and global agent directories are created, removed, copied, or symlinked based on untrusted skill metadata after sanitization.
4. **Dev/build server/tooling exposure:** Vite/Vitest advisories repeatedly exploit localhost/dev-server assumptions; relevant to CI, maintainers, and any exposed test API server.
5. **Config/glob/parser input:** plugin manifests, node_modules sync, YAML, and glob/build tools are recurring parser/config trust boundaries.
6. **AI-skill ecosystem analogs:** NVD generic `skills` search surfaced unrelated OpenClaw skill path traversal/archive-packaging CVEs; not target advisories, but they reinforce path-containment and archive/symlink review priorities for this class of tool.

#### Patch Quality Signals

- **Structural recurrence: `simple-git` command execution boundary.** Multiple 2022 and 2026 command-injection/RCE fixes show repeated bypasses in the same conceptual boundary. Do not rely only on library blocking; Phase 2/5 should validate local URL/ref allowlisting and fixed argv construction around `cloneRepo()`.
- **Structural recurrence: Vite dev-server `server.fs.deny`.** Vite has a long series of file-read bypasses; treat any local dev/test server exposure as high risk, even though it is not a production runtime component.
- **Structural recurrence: skill discovery name binding.** PR #356 proposes rejecting name-directory mismatches and duplicate names, but it remains unmerged. Current code still uses frontmatter name for dedupe/install naming.
- **Parser/resource guardrail gap:** YAML and glob advisories suggest adding size/depth/time limits for `SKILL.md`, plugin manifests, and repository discovery where practical.

#### Audit targeting recommendations

> Based on pattern analysis: Phase 3 should prioritize DFD slices for `skills add` remote-source ingestion, `cloneRepo()`/simple-git subprocess invocation, skill discovery/deduplication, and filesystem install/symlink flows. Phase 5 deep probe should target untrusted repository URLs/refs/subpaths, malicious `SKILL.md` frontmatter, duplicate skill names, symlink/copy path containment, and node_modules/well-known sync inputs. Phase 8 chambers should include command injection, path traversal/arbitrary write, parser DoS, prototype pollution, and namespace-confusion attack modes. Patch-bypass-checker should flag `simple-git` usage and skill discovery name binding as `structural-recurrence` candidates.

### Architecture Inventory

- **Components:** Node.js CLI (`bin/cli.mjs`, `src/cli.ts`); command handlers (`add`, `list`, `find`, `remove`, `update`, `init`, `experimental_install`, `experimental_sync`); source parser; git clone wrapper; blob/GitHub tree downloader; skill discovery/frontmatter parser; plugin manifest parser; installer/remover; global/project lockfiles; telemetry/audit client.
- **Transports:** CLI args/stdin prompts; native `git` subprocess via `simple-git`; HTTPS fetch to GitHub API/raw content, `skills.sh` download API, and `add-skill.vercel.sh` telemetry/audit; local filesystem copy/symlink/rm; JSON/YAML files; GitHub Actions CI/publish workflows.
- **Trust boundaries:** public internet repositories and well-known endpoints -> local developer machine; remote skill metadata -> agent-readable skill directories; project-local `.agents/skills` vs global home/config agent dirs; CI build/publish environment; telemetry/audit external service response -> terminal output; npm dependency/build supply chain -> published CLI bundle.
- **Execution environments:** Node >=18 on developer machines; GitHub Actions Linux/Windows CI; npm package bundle built by `obuild`; optional global installs under home/XDG config paths.
- **Highest-risk flows:**
  1. `skills add <source>` -> `parseSource()` -> blob/GitHub tree fetch or `cloneRepo()` -> `discoverSkills()` -> `parseFrontmatter()` -> `installSkillForAgent()`.
  2. `cloneRepo(url, ref)` -> simple-git/native git with user-controlled URL/ref and environment inherited from the user.
  3. Well-known HTTP source -> remote JSON/SKILL content -> install without repository history.
  4. `experimental_sync` -> scan `node_modules` packages for `SKILL.md` -> install into agent directories.
  5. Remove/update flows -> lockfile state -> recursive filesystem deletion/copy/symlink operations.

### Dependency Intelligence

- **Active lockfile advisories:** `pnpm audit` reported 12 active installed advisories: 1 critical, 7 high, 4 moderate by npm severity across `simple-git`, `rollup`, `vite`, `picomatch`, `defu`, and `postcss`.
- **Runtime-bundled dependency concern:** `simple-git` is declared as a devDependency but bundled into `dist/cli.mjs` and used at runtime for cloning. Current lock `3.30.0` is affected by CVE-2026-28291 and CVE-2026-28292. Upgrade to `>=3.32.3` (prefer latest `3.36.0`) and harden local URL/ref validation.
- **Runtime parser:** `yaml@2.8.3` is current and fixed for CVE-2026-33532, but it parses untrusted `SKILL.md` frontmatter. Maintain file-size/depth limits and fail-closed parse behavior.
- **Build/test stack:** `obuild@0.4.22`, `vitest@4.0.18`, Vite/Rollup/PostCSS transitive versions are behind fixed releases. CI/dev risk rises if tests/dev servers or build inputs are attacker-controlled.
- **Config/glob stack:** `picomatch` and `defu` active advisories map to glob/config parser abuse. Any future feature accepting user-supplied globs/config should be threat-modeled.
- **Outdated direct dependencies:** `@clack/prompts`, `obuild`, `simple-git`, `vitest`, `lint-staged`, `prettier`, type packages have newer releases. Security-relevant upgrades: `simple-git >=3.32.3`, `obuild` latest, `vitest` latest, `vite >=7.3.2/8.0.5`, `rollup >=4.59.0`, `picomatch >=4.0.4` and `>=2.3.2`, `defu >=6.1.5`, `postcss >=8.5.10`.
- **Supply-chain-risk-auditor delegation:** supply-chain-risk-auditor methodology was loaded and the existing `.supply-chain-risk-auditor/results.md` was incorporated. Its GitHub repo-stat scan was limited by the same `gh api` 401 credential issue; npm metadata, pnpm audit, OSV, and NVD enrichment were used instead.

### Patch Commit Discovery Notes

- No first-party CVE/GHSA patch commits exist because no indexed first-party advisories were found.
- Non-indexed issue #353 has proposed PR #356 (`fix/prevent-namespace-squatting`) but it is open/unmerged (`merged_at: null`), with no local patch commit.
- Dependency patch references captured for later patch-bypass analysis include simple-git commits `f7042088`, `1effd8e`, historical `2040de6`/`7746480`/`ec97a39`; Rollup `c60770d`/`c8cf1f9`/`d6dee5e`; Vite `f02d9fd`/`a9a3df2`/`79f002f`; defu `3942bfb`; picomatch `5eceecd`/`4516eb5`; yaml `1e84ebb`/`984f578`.

