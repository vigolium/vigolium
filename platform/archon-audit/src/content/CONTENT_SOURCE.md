# Vendored Content

This directory mirrors the canonical security-audit methodology from
[`archon-audit`](https://github.com/vigolium/archon-audit). archon is
authoritative going forward; the snapshot below is for traceability only.

## Last sync

- **Source**: `/Users/j3ssie/Desktop/external/archon-audit`
- **Commit**: `26e7f8783cc26e029d559f8cfa601196e17c6f4b`
- **Synced**: 2026-05-09
- **Inventory**:
  - `agent-defs/`: 31 specialist agent prompts
  - `command-defs/`: 9 mode workflows (lite, balanced, deep, diff, confirm,
    merge, revisit, reinvest, status)
  - `skills/`: 20 reusable workflow definitions
  - `harnesses/{claude,codex}/`: platform-specific frontmatter deltas
  - `skills-lock.json`: skill version locks (carried over verbatim)

## Layout

- `agent-defs/<name>.md` — canonical agent prompts. Frontmatter is intentionally
  thin (description only); platform deltas live in `harnesses/`.
- `command-defs/<mode>.md` — orchestration workflows. archon adds a YAML
  `phases:` block to each so the engine can parse them without LLM intervention.
- `skills/<name>/SKILL.md` — agent-invokable workflows. Reference scripts and
  templates live alongside; `{baseDir}` placeholder is resolved at content
  extraction time.
- `harnesses/{claude,codex}/frontmatter.yaml` — install-time merge config for
  per-platform agent overrides (tools, models, exclusions).
- `sdk-variants/` — *generated* SDK-safe versions of `agent-defs/`. Produced by
  `scripts/transform-content.ts`; not committed (see `.gitignore`).

## Sync policy

archon owns this content from now on. To pull in upstream changes from
archon-audit, run `scripts/sync-from-archon-audit.sh` (TODO) and review the diff.
