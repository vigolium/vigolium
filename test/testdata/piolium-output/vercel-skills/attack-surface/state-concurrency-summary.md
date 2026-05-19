# Stage 06 — State Machine & Concurrency Audit

Generated: 2026-05-01  
Target: `/Users/bytedance/Desktop/oss-to-run/skills`

## Context

This repository is a local Node/TypeScript CLI and installer for agent skill bundles. It has no server routes, no database schema/ORM migrations, and no payment/webhook/callback handlers. The mutable state that matters for this phase is filesystem state: installed skill directories and JSON lockfiles that record provenance and update hashes.

## State-holding entities catalogued

| # | Entity | Store / owner | Mutable state | Allowed values / notes |
|---:|---|---|---|---|
| 1 | Global skill lock | `~/.agents/.skill-lock.json` or `$XDG_STATE_HOME/skills/.skill-lock.json`; `SkillLockFile` in `src/skill-lock.ts` | `version`, `skills`, `dismissed`, `lastSelectedAgents` | `version` currently `3`; `skills` is keyed by skill name. |
| 2 | Global skill entry | `SkillLockEntry` in `src/skill-lock.ts` | `source`, `sourceType`, `sourceUrl`, `ref`, `skillPath`, `skillFolderHash`, `installedAt`, `updatedAt`, `pluginName` | `sourceType` is documented as provider/source type; no runtime enum constraint at write time. |
| 3 | Dismissed prompt state | `SkillLockFile.dismissed.findSkillsPrompt` | prompt lifecycle boolean | Boolean; mutated by `dismissPrompt()`. |
| 4 | Last selected agents | `SkillLockFile.lastSelectedAgents` | last agent selection array | Should contain `AgentType` names, but persisted as strings in JSON. |
| 5 | Project skill lock | `<cwd>/skills-lock.json`; `LocalSkillLockFile` in `src/local-lock.ts` | `version`, `skills` | `version` currently `1`; project-scoped provenance/update hashes. |
| 6 | Project skill entry | `LocalSkillLockEntry` in `src/local-lock.ts` | `source`, `ref`, `sourceType`, `skillPath`, `computedHash` | `sourceType` includes values such as `github`, `gitlab`, `git`, `well-known`, `node_modules`, `local`. |
| 7 | Installed skill directories | `.agents/skills/<sanitized-name>`, `~/.agents/skills/<sanitized-name>`, and agent-specific skill dirs from `src/agents.ts` | installed `SKILL.md` and auxiliary files; symlinks/copies to agent dirs | Directory name derived by `sanitizeName()`; content comes from local/git/blob/well-known sources. |
| 8 | Remote snapshot/hash state | GitHub tree SHA, blob `snapshotHash`, local `computedHash` | update/provenance comparison state | Stored in lock entries after installation; used by `skills update` and `experimental_install`. |

### Schema-level state columns

No database schema, migrations, or ORM models were present. Application-level enum/choice fields observed include `ParsedSource.type` (`github | gitlab | git | local | well-known`), `AgentType`, `InstallMode` (`symlink | copy`), and update scope (`project | global | both`), but the persistent JSON lockfiles do not enforce them as database constraints.

### Financial / quota / capacity state

No balances, credits, quotas, inventory, or other double-spend-sensitive financial/capacity entities were found in first-party source.

### Idempotency / dedup infrastructure

No idempotency tables/keys, request logs, processed-event stores, JWT `jti`, nonce, or webhook event deduplication infrastructure was found. This is not filed as a finding because the KB and source show no inbound payment, webhook, OAuth callback, or other externally retried event endpoint.

### Lifecycle transition functions

No `transition_to_*`, `advance_*`, `complete_*`, `approve_*`, `reject_*`, `publish_*`, `cancel_*`, or `refund_*` lifecycle transition functions were found in first-party runtime code.

## Concurrency primitives observed

Repository-level searches excluding `piolium/`, `.git`, and dependency directories found no language-level mutex/queue primitives, no database transactions, no `SELECT FOR UPDATE`, no advisory locks, and no Redis/distributed locks. Lockfile writes use direct `writeFile()` replacements.

## Temporal paths reviewed

| Path | State read | State written | Result |
|---|---|---|---|
| `skills add -g` | global lock via `readSkillLock()` | installed global dirs, then `addSkillToLock()` | Finding filed: read-modify-write lockfile clobber. |
| project `skills add` | project lock via `readLocalLock()` | project `.agents/skills`, then `addSkillToLocalLock()` | Covered by same finding. |
| `experimental_sync` | `skills-lock.json` hashes | project installed dirs and local lock | Covered by same finding. |
| `skills remove -g` | installed dirs and global lock entry | removes dirs, then `removeSkillFromLock()` | Same RMW lockfile issue applies; not split into a duplicate draft. |
| `skills update` | global/project lock snapshot | self-spawns `skills add` | Prior P4 draft covers lock-derived source trust; no separate concurrency draft beyond lock RMW. |
| well-known/blob file writes | remote file paths validated before write | skill directory files | Local same-user path races exist in theory, but no remote-only exploit path was strong enough for a draft. |

## Drafts filed

| Draft | Class | Severity | Summary |
|---|---|---|---|
| `piolium/findings-draft/p6-001-lockfile-rmw-loses-concurrent-updates.md` | `rmw-no-txn` | HIGH | Concurrent lockfile mutations read and rewrite the whole JSON document without an inter-process lock or CAS, allowing installed skills to lose provenance/update entries. |

## Outcome

- State-holding entities catalogued: 8
- Concurrency primitives observed: none
- Idempotency infrastructure: absent; no payment/webhook/OAuth callback channel present
- Drafts filed: 1 (`rmw-no-txn`: 1)
