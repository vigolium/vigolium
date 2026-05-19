# Stage 02 — Patch History & Bypass Review

Generated: 2026-05-01  
Repository: `/Users/bytedance/Desktop/oss-to-run/skills` (`vercel-labs/skills`)  
Scan bounds: `MAX_COMMITS=500`, `MAX_AGE=60 days ago` (defaults from `${PIGOLIUM_COMMIT_SCAN_LIMIT:-500}` / `${PIGOLIUM_COMMIT_SCAN_SINCE:-60 days ago}`). All Stage 02 `git log` sweeps used `-n "$MAX_COMMITS" --since="$MAX_AGE"`. Raw logs are in `piolium/attack-surface/raw/git-history/`.

## Executive conclusions

1. **Sound direct fix:** JS-frontmatter execution removal (`10438af`) appears sound for its original bug class today.
2. **Terminal escape bypass found:** `5516b8a` sanitizes most skill metadata, but well-known `index.json` `entry.name` is accepted as unsanitized `installName` and printed by `handleWellKnownSkills()`.
3. **Relocated path-boundary risk:** `..` subpath traversal is blocked, but filesystem containment is only lexical. Symlink subpaths and dereferenced source symlinks can still cross repository/skill boundaries; Stage 02 proof tests are stored under `piolium/tmp/stage02-symlink-*.test.ts`.
4. **Unfixed dependency patch:** Current `simple-git` remains `3.30.0`, below upstream fixes for 2026 command/protocol bypass advisories. The CLI still passes user-controlled source URLs and refs to `simple-git.clone()`.
5. **Policy-only protections:** The OpenClaw block is bypassable via mirrors/local/well-known sources and should not be treated as a supply-chain security boundary.
6. **Snapshot trust relocation:** Blob install path traversal is guarded, but the trust boundary moved from GitHub clone contents to the external `skills.sh` snapshot API without client-side verification that snapshot contents match the GitHub tree/ref.

## Relevant commits and bypass assessment

| Commit | Date | Cluster | Why security-relevant | Bypass attempts performed | Verdict today |
|---|---:|---|---|---|---|
| `10438af` | 2026-04-01 | C-PARSER-FRONTMATTER | [undisclosed] Removed `gray-matter` in favor of YAML-only `parseFrontmatter()`, explicitly avoiding `---js`/`---javascript` eval. | Checked all metadata parsers route through `parseFrontmatter()`; `---js` no longer matches the delimiter regex and callers reject missing `name`/`description`. | **sound** for JS-frontmatter RCE; parser DoS remains separate. |
| `1b2e671` | 2026-03-05 | C-PATH-CONTAINMENT | [undisclosed] Added `sanitizeSubpath()` and `isSubpathSafe()` to prevent `../` subpath traversal out of cloned repos. | Existing tests reject `../`, nested traversal, and backslashes. Added Stage 02 symlink tests: `skills/link` symlink to outside dir passes lexical check and is followed; source symlink files are dereferenced and copied. | **relocated**: `..` fixed, symlink/realpath containment gap remains. |
| `5516b8a` | 2026-04-21 | C-TERMINAL-SANITIZE | [undisclosed] Added terminal escape stripping for untrusted metadata and applied it across add/list/find/blob/well-known/update surfaces. | Ran `tests/sanitize-terminal.test.ts`; added Stage 02 proof that well-known `index.json` `entry.name` with `\x1b[2J` is accepted as unsanitized `installName` and printed by `handleWellKnownSkills()`. | **bypassable** via well-known `installName` alternate entry point. |
| `6995e1b` | 2026-04-05 | C-SUPPLY-POLICY | [undisclosed] Blocks `openclaw/*` sources unless an explicit dangerous flag is supplied. | Checked normalization through `getOwnerRepo()` for GitHub shorthand/URL/SSH. Considered mirrors, forks, local paths, well-known URLs, and explicit opt-in flag. | **bypassable** as a policy/blocklist; useful warning, not complete mitigation. |
| `eb33656` (+ `5516b8a` allowlist extension) | 2026-04-03 / 2026-04-21 | C-BLOB-SNAPSHOT | [undisclosed] Introduced blob snapshot installs for allowlisted GitHub owners and path-confined blob file writes; later added `heygen-com` and metadata sanitization. | Reviewed `installBlobSkillForAgent()` path checks; tested traversal-style paths are lexically skipped by `isPathSafe()`. Compared GitHub tree/raw discovery to unverified `skills.sh` file snapshot retrieval. | **relocated**: arbitrary write guarded, but content trust moved to snapshot API without end-to-end GitHub tree/ref verification. |
| `4f1d38e`, `08314e2` | 2026-03-11 / 2026-04-28 | C-SYMLINK-FS | [undisclosed] Changed install/list behavior for symlinks: skip broken source symlinks; discover symlinked skill directories. | Added Stage 02 tests showing live source symlinks are dereferenced and copied, and symlinked dirs outside base are followed for discovery/listing. | **relocated** filesystem boundary risk. |
| `327162e`, `f2b8d81` | 2026-04-17 / 2026-04-27 | C-GIT-LFS-HARDENING | [undisclosed] Skip/disable Git LFS smudge/filter process during clone to avoid huge downloads and missing `git-lfs`. | Reviewed `GIT_LFS_SKIP_SMUDGE=1` and `filter.lfs.*` overrides in `src/git.ts`. This prevents LFS filter execution/download but does not constrain clone URL/ref injection. | **sound** for LFS bloat/filter failure; not a fix for simple-git RCE advisories. |
| `69844c3`, `a3c296f`, `c03683e`, `57f3351` | 2026-03-31..2026-04-27 | C-UPDATE-INTEGRITY | [undisclosed] Added ref-aware lock/update sources, skillPath tracking, non-GitHub local hash computation, and cached GitHub tree hash extraction. | Checked `buildLocalUpdateSource()`/`buildUpdateInstallSource()` and lock writes. New local entries include `skillPath`; legacy project entries are skipped. Non-GitHub global update checks still call GitHub-tree code. | **partially sound**; non-GitHub integrity/update verification remains incomplete. |
| `bd5c490` | 2026-04-27 | C-TELEMETRY-PRIVACY | [undisclosed] Starts `isRepoPrivate()` checks earlier to avoid telemetry-gating stalls. | Verified GitHub telemetry only sends on `isPrivate === false`. Well-known/private internal hosts are outside the GitHub private-repo gate. | **sound** for scheduling; privacy policy gap remains for non-GitHub private sources. |
| `a3c296f` / dependency state | 2026-04-28 | C-GIT-DEPENDENCY | Dependency advisory follow-up: `ThirdPartyNoticeText.txt` mentions `simple-git@3.36.0`. | Checked `package.json`, `pnpm-lock.yaml`, and `node_modules/simple-git/package.json`: actual version is still `3.30.0`. `cloneRepo(url, ref)` still accepts user-controlled URLs/refs. | **bypassable/unfixed** for GHSA-r275-fr43-pm7q and GHSA-jcxm-m3jx-f287 until dependency is upgraded. |

## Bypass evidence

- Regression/security tests run: `tests/subpath-traversal.test.ts`, `tests/sanitize-terminal.test.ts`, parser/update/local-lock/list/install-copy tests — **100 tests passed**.
- Stage 02 added proof tests in `piolium/tmp/`:
  - `stage02-symlink-bypass.test.ts`: lexical `isSubpathSafe()` allows a symlink subpath that resolves outside the repo and `discoverSkills()` follows it.
  - `stage02-symlink-copy.test.ts`: `installSkillForAgent()` dereferences a source symlink and copies target bytes into `.agents/skills/<skill>`.
  - `stage02-wellknown-installname-escape.test.ts`: a well-known `index.json` name containing an ESC sequence is accepted and returned unsanitized as `installName`.
- Captured output: `piolium/attack-surface/raw/git-history/stage02-bypass-test-output.txt`.

## Reviewed but lower-security commits

The bounded sweeps also flagged prompt redraw, timeout, lockfile, agent-addition, and docs commits. They were reviewed for security relevance and not treated as historical security fixes unless they touched a trust boundary above. Examples: `26f26c0` (prompt redraw), `2865943` (clone timeout), `5fab90d` (telemetry flush), `6ccf4ac` (license generation cwd handling), and agent-support additions.

## Carry-forward items for later phases

1. **Fix well-known installName sanitization:** Correct `isValidSkillEntry()` and/or apply `sanitizeMetadata()` to `installName` before all CLI rendering.
2. **File a path-boundary finding candidate:** Realpath-check cloned/local skill roots before discovery/copy, or refuse/don't dereference symlinks from untrusted skill sources.
3. **Upgrade simple-git:** Move lockfile to `simple-git >=3.32.3` (prefer latest) and consider first-party URL/ref allowlisting or `--`/argv hardening around `cloneRepo()`.
4. **Verify blob snapshots:** Bind `skills.sh` downloads to GitHub tree SHA/ref or disable blob mode for security-sensitive installs (`--full-depth` currently avoids it).
5. **Treat OpenClaw block as UX only:** Do not rely on owner blocklists for malicious-skill prevention; address namespace-squatting issue #353 separately.
