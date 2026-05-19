# Confirmation Report

| Field | Value |
|-------|-------|
| Audit ID | 2026-04-30T17:51:36.608Z |
| Repository | vercel-labs/skills |
| Confirmed at | 2026-04-30T20:26:47Z |
| Environment | node-cli-binary (base_url=null, cli=node ./bin/cli.mjs) |
| Target URL / base_url | local-cli:node ./bin/cli.mjs |
| Original audit mode | deep |

## Summary

| Status | Count | Findings |
|--------|-------|----------|
| confirmed-live | 5 | p10-003-http-well-known-skill-discovery, p10-004-unbounded-well-known-fetch-and-frontmatter-parse, p10-006-blob-snapshot-not-verified-against-github-tree, p10-007-rfc8615-path-relative-well-known-shadowing, p12-cleartext-http-git-sources |
| confirmed-test | 9 | p10-001-direct-git-url-ref-reaches-simple-git-clone, p10-002-symlink-dereference-copies-out-of-tree-files, p10-005-duplicate-skill-name-first-wins, p10-008-agent-skill-name-constraints-not-enforced, p10-009-project-scope-symlinked-agent-base-escape, p10-010-experimental-install-unlocked-node-modules-skills, p12-node-modules-sync-duplicate-name-overwrite, p12-project-scope-remove-symlinked-agent-base-escape, p12-unbounded-git-local-frontmatter-parse |
| confirmed-fp | 0 | — |
| analytical-only | 0 | — |
| unconfirmed | 0 | — |
| inconclusive | 0 | — |
| blocked | 0 | — |
| no-poc | 0 | — |
| error | 0 | — |

**Confirmation rate**: 14/14 findings confirmed (100%) — `confirmed-fp` and `analytical-only` are excluded from the denominator.

**False-positive count**: 0.

## One-line Finding Inventory

| Finding | Severity | Exploitability | Status | Evidence pointer | Reproduction command summary | Observation |
|---------|----------|----------------|--------|------------------|------------------------------|-------------|
| `p10-001-direct-git-url-ref-reaches-simple-git-clone` — Direct git URL/ref reaches vulnerable simple-git clone boundary | HIGH | local-exploitable | confirmed-test | `piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-output.log; piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-evidence.log; piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-impact.log` | `timeout 90 pnpm exec vitest run piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer ran the real CLI with an ext:: direct-git source under an isolated HOME that enabled protocol.ext; native git executed the helper and wrote uid/gid to confirm-impact.log before clone failure. |
| `p10-002-symlink-dereference-copies-out-of-tree-files` — Recursive install copy dereferences untrusted skill symlinks | HIGH | local-exploitable | confirmed-test | `piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-output.log; piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-evidence.log` | `timeout 90 pnpm exec vitest run piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer installed a skill source containing a symlink to an out-of-tree secret in copy mode; the installed artifact was a regular file containing the secret marker. |
| `p10-003-http-well-known-skill-discovery` — Cleartext HTTP well-known skill discovery can persist attacker-controlled skills | MEDIUM | network-exploitable | confirmed-live | `piolium/findings/p10-003-http-well-known-skill-discovery/evidence/confirmed-20260430T201612Z.log` | `/opt/homebrew/bin/python3 piolium/findings/p10-003-http-well-known-skill-discovery/poc.py` | MITM marker persisted in installed SKILL.md and auxiliary file |
| `p10-004-unbounded-well-known-fetch-and-frontmatter-parse` — Unbounded well-known fetch and frontmatter parsing can hang CLI discovery | MEDIUM | network-exploitable | confirmed-live | `piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/evidence/confirmed-20260430T201612Z.log` | `/opt/homebrew/bin/node piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/poc.js` | CLI hung on never-ending well-known SKILL.md body for 3005ms |
| `p10-005-duplicate-skill-name-first-wins` — Duplicate skill names are silently first-wins | MEDIUM | local-exploitable | confirmed-test | `piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-output.log; piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-evidence.log` | `timeout 90 pnpm exec vitest run piolium/findings/p10-005-duplicate-skill-name-first-wins/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer created duplicate trusted-build skills in attacker and curated paths; discover/install surfaced one candidate from the attacker path and installed the attacker marker. |
| `p10-006-blob-snapshot-not-verified-against-github-tree` — Blob snapshot installs are not verified against the resolved GitHub tree | MEDIUM | network-exploitable | confirmed-live | `piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/evidence/confirmed-20260430T201612Z.log` | `/opt/homebrew/bin/python3 piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/poc.py` | installed web-design-guidelines/SKILL.md contains attacker marker P10_006_SNAPSHOT_SUBSTITUTION_MARKER |
| `p10-007-rfc8615-path-relative-well-known-shadowing` — Path-relative `.well-known` discovery shadows origin-root RFC 8615 metadata | MEDIUM | network-exploitable | confirmed-live | `piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/evidence/confirmed-20260430T201612Z.log` | `/opt/homebrew/bin/python3 piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/poc.py` | attacker path-local evil-shadow skill installed while origin-root trusted-root existed |
| `p10-008-agent-skill-name-constraints-not-enforced` — Agent Skill `name` constraints are not enforced before deriving install directories | MEDIUM | local-exploitable | confirmed-test | `piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-output.log; piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-evidence.log` | `timeout 90 pnpm exec vitest run piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer parsed name ../trusted-skill, installed it after a legitimate trusted-skill, and observed the sanitized destination overwrite with attacker content. |
| `p10-009-project-scope-symlinked-agent-base-escape` — Project-scoped installs follow symlinked agent bases outside the project | HIGH | local-exploitable | confirmed-test | `piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-output.log; piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-evidence.log` | `timeout 90 pnpm exec vitest run piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer installed project-scoped into a checkout whose .agents was a symlink; realpath of the lexical project install landed under the outside target. |
| `p10-010-experimental-install-unlocked-node-modules-skills` — `experimental_install` installs unlisted `node_modules` skills during lockfile restore | HIGH | local-exploitable | confirmed-test | `piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-output.log; piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-evidence.log` | `timeout 90 pnpm exec vitest run piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer ran the real CLI experimental_install with a lockfile listing only safe-locked-skill; an unlisted transitive-evil-package skill was installed and added to skills-lock.json. |
| `p12-cleartext-http-git-sources` — Cleartext HTTP Git Sources Allow MITM Skill Injection | MEDIUM | network-exploitable | confirmed-live | `piolium/findings/p12-cleartext-http-git-sources/evidence/confirmed-20260430T201612Z.log` | `/opt/homebrew/bin/python3 piolium/findings/p12-cleartext-http-git-sources/poc.py` | installed SKILL.md contains P12_CLEAR_HTTP_GIT_MITM_MARKER from HTTP git clone |
| `p12-node-modules-sync-duplicate-name-overwrite` — `experimental_sync` duplicate node_modules skill names overwrite installed skills | MEDIUM | local-exploitable | confirmed-test | `piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-output.log; piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-evidence.log` | `timeout 90 pnpm exec vitest run piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer ran the real CLI experimental_sync over two node_modules skills with name shared-name; final .agents/skills/shared-name and lock provenance came from zzz-malicious. |
| `p12-project-scope-remove-symlinked-agent-base-escape` — Project-scoped `skills remove` follows a symlinked agent base outside the project | MEDIUM | local-exploitable | confirmed-test | `piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-output.log; piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-evidence.log` | `timeout 90 pnpm exec vitest run piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer ran the real CLI remove in a project whose .agents symlink pointed outside; the outside victim-skill directory existed before and was deleted after the project-scoped command. |
| `p12-unbounded-git-local-frontmatter-parse` — Unbounded SKILL.md frontmatter parsing from git, local, and package sources | MEDIUM | local-exploitable | confirmed-test | `piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-output.log; piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-evidence.log` | `timeout 90 pnpm exec vitest run piolium/findings/p12-unbounded-git-local-frontmatter-parse/confirm-test.test.ts --testTimeout=60000 --reporter=verbose` | Vitest reproducer ran the real CLI against a local SKILL.md with 500k frontmatter keys under NODE_OPTIONS=--max-old-space-size=32; the child process aborted with V8 heap out-of-memory stack trace. |

## Inventory Metadata

| Finding | Original PoC-Status | Confirm-Status | Confirm-Method | Source evidence field |
|---------|---------------------|----------------|----------------|-----------------------|
| `p10-001-direct-git-url-ref-reaches-simple-git-clone` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-output.log; piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-evidence.log; piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-impact.log` |
| `p10-002-symlink-dereference-copies-out-of-tree-files` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-output.log; piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-evidence.log` |
| `p10-003-http-well-known-skill-discovery` | executed | confirmed-live | poc-live | `piolium/findings/p10-003-http-well-known-skill-discovery/evidence/confirmed-20260430T201612Z.log` |
| `p10-004-unbounded-well-known-fetch-and-frontmatter-parse` | executed | confirmed-live | poc-live | `piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/evidence/confirmed-20260430T201612Z.log` |
| `p10-005-duplicate-skill-name-first-wins` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-output.log; piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-evidence.log` |
| `p10-006-blob-snapshot-not-verified-against-github-tree` | executed | confirmed-live | poc-live | `piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/evidence/confirmed-20260430T201612Z.log` |
| `p10-007-rfc8615-path-relative-well-known-shadowing` | executed | confirmed-live | poc-live | `piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/evidence/confirmed-20260430T201612Z.log` |
| `p10-008-agent-skill-name-constraints-not-enforced` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-output.log; piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-evidence.log` |
| `p10-009-project-scope-symlinked-agent-base-escape` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-output.log; piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-evidence.log` |
| `p10-010-experimental-install-unlocked-node-modules-skills` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-output.log; piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-evidence.log` |
| `p12-cleartext-http-git-sources` | executed | confirmed-live | poc-live | `piolium/findings/p12-cleartext-http-git-sources/evidence/confirmed-20260430T201612Z.log` |
| `p12-node-modules-sync-duplicate-name-overwrite` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-output.log; piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-evidence.log` |
| `p12-project-scope-remove-symlinked-agent-base-escape` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-output.log; piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-evidence.log` |
| `p12-unbounded-git-local-frontmatter-parse` | executed | confirmed-test | generated-vitest-reproducer | `piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-output.log; piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-evidence.log` |

## Breakdown by Exploitability Class

| Class | Total | confirmed-live | confirmed-test | unconfirmed | blocked | analytical-only |
|-------|-------|----------------|----------------|-------------|---------|-----------------|
| network-exploitable | 5 | 5 | 0 | 0 | 0 | 0 |
| local-exploitable | 9 | 0 | 9 | 0 | 0 | 0 |
| non-exploitable | 0 | 0 | 0 | 0 | 0 | 0 |

## Confirmed Findings (Live)

### `p10-003-http-well-known-skill-discovery` — Cleartext HTTP well-known skill discovery can persist attacker-controlled skills [MEDIUM]

- **Vulnerability**: Cleartext HTTP well-known skill discovery / MITM skill injection
- **Exploitability class**: network-exploitable
- **Method**: PoC executed against `node-cli-binary` local CLI environment (`base_url=null`); PoCs started local attacker-controlled servers/remotes where required.
- **Evidence**: `piolium/findings/p10-003-http-well-known-skill-discovery/evidence/confirmed-20260430T201612Z.log`
- **Execution time**: 1.578s
- **Reproduction**: `/opt/homebrew/bin/python3 piolium/findings/p10-003-http-well-known-skill-discovery/poc.py`
- **Observation**: MITM marker persisted in installed SKILL.md and auxiliary file

---

### `p10-004-unbounded-well-known-fetch-and-frontmatter-parse` — Unbounded well-known fetch and frontmatter parsing can hang CLI discovery [MEDIUM]

- **Vulnerability**: CWE-400: Uncontrolled resource consumption in well-known fetch/frontmatter parsing
- **Exploitability class**: network-exploitable
- **Method**: PoC executed against `node-cli-binary` local CLI environment (`base_url=null`); PoCs started local attacker-controlled servers/remotes where required.
- **Evidence**: `piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/evidence/confirmed-20260430T201612Z.log`
- **Execution time**: 3.526s
- **Reproduction**: `/opt/homebrew/bin/node piolium/findings/p10-004-unbounded-well-known-fetch-and-frontmatter-parse/poc.js`
- **Observation**: CLI hung on never-ending well-known SKILL.md body for 3005ms

---

### `p10-006-blob-snapshot-not-verified-against-github-tree` — Blob snapshot installs are not verified against the resolved GitHub tree [MEDIUM]

- **Vulnerability**: CWE-494: Download of code without integrity check / unverified blob snapshot
- **Exploitability class**: network-exploitable
- **Method**: PoC executed against `node-cli-binary` local CLI environment (`base_url=null`); PoCs started local attacker-controlled servers/remotes where required.
- **Evidence**: `piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/evidence/confirmed-20260430T201612Z.log`
- **Execution time**: 1.98s
- **Reproduction**: `/opt/homebrew/bin/python3 piolium/findings/p10-006-blob-snapshot-not-verified-against-github-tree/poc.py`
- **Observation**: installed web-design-guidelines/SKILL.md contains attacker marker P10_006_SNAPSHOT_SUBSTITUTION_MARKER

---

### `p10-007-rfc8615-path-relative-well-known-shadowing` — Path-relative `.well-known` discovery shadows origin-root RFC 8615 metadata [MEDIUM]

- **Vulnerability**: RFC 8615 well-known path shadowing / trust-scope confusion
- **Exploitability class**: network-exploitable
- **Method**: PoC executed against `node-cli-binary` local CLI environment (`base_url=null`); PoCs started local attacker-controlled servers/remotes where required.
- **Evidence**: `piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/evidence/confirmed-20260430T201612Z.log`
- **Execution time**: 1.277s
- **Reproduction**: `/opt/homebrew/bin/python3 piolium/findings/p10-007-rfc8615-path-relative-well-known-shadowing/poc.py`
- **Observation**: attacker path-local evil-shadow skill installed while origin-root trusted-root existed

---

### `p12-cleartext-http-git-sources` — Cleartext HTTP Git Sources Allow MITM Skill Injection [MEDIUM]

- **Vulnerability**: Cleartext HTTP Git transport / MITM skill injection
- **Exploitability class**: network-exploitable
- **Method**: PoC executed against `node-cli-binary` local CLI environment (`base_url=null`); PoCs started local attacker-controlled servers/remotes where required.
- **Evidence**: `piolium/findings/p12-cleartext-http-git-sources/evidence/confirmed-20260430T201612Z.log`
- **Execution time**: 12.298s
- **Reproduction**: `/opt/homebrew/bin/python3 piolium/findings/p12-cleartext-http-git-sources/poc.py`
- **Observation**: installed SKILL.md contains P12_CLEAR_HTTP_GIT_MITM_MARKER from HTTP git clone

---

## Confirmed Findings (Test)

### `p10-001-direct-git-url-ref-reaches-simple-git-clone` — Direct git URL/ref reaches vulnerable simple-git clone boundary [HIGH]

- **Vulnerability**: Unsafe direct git clone / command execution boundary
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/confirm-test.test.ts`
- **Test output**: `piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-output.log; piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-test-evidence.log; piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/evidence/confirm-impact.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p10-001-direct-git-url-ref-reaches-simple-git-clone/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer ran the real CLI with an ext:: direct-git source under an isolated HOME that enabled protocol.ext; native git executed the helper and wrote uid/gid to confirm-impact.log before clone failure.

---

### `p10-002-symlink-dereference-copies-out-of-tree-files` — Recursive install copy dereferences untrusted skill symlinks [HIGH]

- **Vulnerability**: CWE-59: Improper Link Resolution Before File Access (`Link Following`)
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/confirm-test.test.ts`
- **Test output**: `piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-output.log; piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/evidence/confirm-test-evidence.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p10-002-symlink-dereference-copies-out-of-tree-files/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer installed a skill source containing a symlink to an out-of-tree secret in copy mode; the installed artifact was a regular file containing the secret marker.

---

### `p10-005-duplicate-skill-name-first-wins` — Duplicate skill names are silently first-wins [MEDIUM]

- **Vulnerability**: Skill namespace shadowing / provenance confusion
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p10-005-duplicate-skill-name-first-wins/confirm-test.test.ts`
- **Test output**: `piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-output.log; piolium/findings/p10-005-duplicate-skill-name-first-wins/evidence/confirm-test-evidence.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p10-005-duplicate-skill-name-first-wins/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer created duplicate trusted-build skills in attacker and curated paths; discover/install surfaced one candidate from the attacker path and installed the attacker marker.

---

### `p10-008-agent-skill-name-constraints-not-enforced` — Agent Skill `name` constraints are not enforced before deriving install directories [MEDIUM]

- **Vulnerability**: CWE-20 (Improper Input Validation)
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/confirm-test.test.ts`
- **Test output**: `piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-output.log; piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/evidence/confirm-test-evidence.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p10-008-agent-skill-name-constraints-not-enforced/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer parsed name ../trusted-skill, installed it after a legitimate trusted-skill, and observed the sanitized destination overwrite with attacker content.

---

### `p10-009-project-scope-symlinked-agent-base-escape` — Project-scoped installs follow symlinked agent bases outside the project [HIGH]

- **Vulnerability**: [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/confirm-test.test.ts`
- **Test output**: `piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-output.log; piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/evidence/confirm-test-evidence.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p10-009-project-scope-symlinked-agent-base-escape/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer installed project-scoped into a checkout whose .agents was a symlink; realpath of the lexical project install landed under the outside target.

---

### `p10-010-experimental-install-unlocked-node-modules-skills` — `experimental_install` installs unlisted `node_modules` skills during lockfile restore [HIGH]

- **Vulnerability**: lockfile scope bypass / untrusted dependency skill installation
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/confirm-test.test.ts`
- **Test output**: `piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-output.log; piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/evidence/confirm-test-evidence.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p10-010-experimental-install-unlocked-node-modules-skills/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer ran the real CLI experimental_install with a lockfile listing only safe-locked-skill; an unlisted transitive-evil-package skill was installed and added to skills-lock.json.

---

### `p12-node-modules-sync-duplicate-name-overwrite` — `experimental_sync` duplicate node_modules skill names overwrite installed skills [MEDIUM]

- **Vulnerability**: node_modules skill namespace collision / duplicate-name overwrite
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/confirm-test.test.ts`
- **Test output**: `piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-output.log; piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/evidence/confirm-test-evidence.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p12-node-modules-sync-duplicate-name-overwrite/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer ran the real CLI experimental_sync over two node_modules skills with name shared-name; final .agents/skills/shared-name and lock provenance came from zzz-malicious.

---

### `p12-project-scope-remove-symlinked-agent-base-escape` — Project-scoped `skills remove` follows a symlinked agent base outside the project [MEDIUM]

- **Vulnerability**: CWE-59: Symlinked project agent-base deletion escape
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/confirm-test.test.ts`
- **Test output**: `piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-output.log; piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/evidence/confirm-test-evidence.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p12-project-scope-remove-symlinked-agent-base-escape/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer ran the real CLI remove in a project whose .agents symlink pointed outside; the outside victim-skill directory existed before and was deleted after the project-scoped command.

---

### `p12-unbounded-git-local-frontmatter-parse` — Unbounded SKILL.md frontmatter parsing from git, local, and package sources [MEDIUM]

- **Vulnerability**: CWE-400: Uncontrolled resource consumption in SKILL.md frontmatter parsing
- **Exploitability class**: local-exploitable
- **Method**: Generated vitest reproducer test
- **Test file**: `piolium/findings/p12-unbounded-git-local-frontmatter-parse/confirm-test.test.ts`
- **Test output**: `piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-output.log`
- **Evidence**: `piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-output.log; piolium/findings/p12-unbounded-git-local-frontmatter-parse/evidence/confirm-test-evidence.log`
- **Reproduction**: `timeout 90 pnpm exec vitest run piolium/findings/p12-unbounded-git-local-frontmatter-parse/confirm-test.test.ts --testTimeout=60000 --reporter=verbose`
- **Observation**: Vitest reproducer ran the real CLI against a local SKILL.md with 500k frontmatter keys under NODE_OPTIONS=--max-old-space-size=32; the child process aborted with V8 heap out-of-memory stack trace.

---

## Analytical-only Findings

None.

## Unconfirmed / Inconclusive Findings

None.

## Blocked Findings

None. V4 routed nine local-only findings to V5, and each was subsequently confirmed by a generated Vitest reproducer; those V4 routing entries are not counted as final blockers.

## No-PoC / Error Findings

None.

## False-positive Findings

False-positive directories scanned with `piolium/findings/FP-*`: **0**.
False-positive rename log: `piolium/confirm-workspace/false-positive-renames.json` (`renames`: 0).

No `FP-*` finding directories were present after V5; no finding was downgraded by fp-check in this confirmation run.

## Environment Details

- **Session UUID**: `c44d2b43-8b4d-48e7-ae92-850980bd6884`
- **Provisioning method**: `node-cli-binary`
- **Target URL / base_url**: `null` (local CLI target)
- **CLI command**: `node ./bin/cli.mjs`
- **CLI version**: `1.5.3`
- **Actual port** (after fallback): `none`
- **Startup duration**: `1s`
- **Healthcheck**: `cli:node ./bin/cli.mjs --version` → passed; output `1.5.3`
- **Containers/processes**: none (process_pid=None; no long-running service for CLI target)
- **Setup log**: `piolium/confirm-workspace/setup.log`
- **Cleanup command**: `true # no persistent process/container; local CLI only`
- **Cleanup result**: `# Piolium cleanup timestamp=2026-04-30T20:24:09Z cmd=true # no persistent process/container; local CLI only exit_code=0 result=no persistent processes or containers to clean up` (log: `piolium/confirm-workspace/cleanup.log`)

## Environment Setup Notes

- The target is a Node.js/TypeScript CLI rather than a long-running HTTP application; `base_url` is intentionally `null`.
- V3 selected `node-cli-binary` from `package.json` and verified `node ./bin/cli.mjs --version` returned `1.5.3`.
- Build/install steps were skipped because `node_modules/` and `dist/cli.mjs` were already present; no Docker services, databases, migrations, ports, or seed identities were required.
- V4 live PoCs used local attacker-controlled HTTP/Git endpoints where needed, while still exercising the real local CLI binary.
- V5 generated isolated Vitest tests for local-only findings and ran each test with an outer `timeout 90` and `--testTimeout=60000`.

## Auth Context

No test identities were needed or created. `auth-spec.json` reports authentication is unsupported because this repository is a local CLI without accounts, roles, sessions, or tokens.

## Methodology

1. Scanned every `piolium/findings/*/report.md` plus `piolium/findings/FP-*` directories. Report `Confirm-*` fields were treated as the final source of truth, with `findings-inventory.json`, `poc-results.json`, and `test-mapping.json` used for supplemental class, command, and duration metadata.
2. Applied the required deduplication priority: `confirmed-live` > `confirmed-test` > `confirmed-fp` > `analytical-only` > `unconfirmed` > `inconclusive` > `blocked` > `no-poc` > `error`.
3. Counted V4 structured PoC outputs with `status: confirmed` as `confirmed-live`; counted V5 generated Vitest reproducers with exit code 0 and `Confirm-Status: confirmed-test` as `confirmed-test`.
4. Drained any `FP-*`/fp-check false positives from severity and confirmation-rate denominators. No such directories or rename entries were present in this run.
5. Local-only findings that V4 marked `blocked` only because they were routed to V5 were not counted as final blocked when V5 confirmed them by test.

