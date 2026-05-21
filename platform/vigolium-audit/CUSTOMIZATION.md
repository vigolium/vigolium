# Customization

Vigolium-Audit is delivered as a single binary with all audit content (agent prompts, command workflows, skills, harness configs) embedded. You can customize behavior in three layers, in order of precedence:

1. **Per-user overrides** — drop replacement files into `~/.config/vigolium-audit/` and they win at runtime.
2. **Project-local overrides** — set `VIGOLIUM_AUDIT_CONFIG_DIR=/path/to/dir` to point at a per-project override root.
3. **Vendored content** — edit `src/content/` directly and rebuild the binary (contributors / forks).

This document covers all three.

## Override directory

By default the loader checks `~/.config/vigolium-audit/` for overrides. Set `VIGOLIUM_AUDIT_CONFIG_DIR` to point somewhere else (e.g. `./vigolium-audit-config` inside a repo).

```
~/.config/vigolium-audit/
├── agents/           # override or add agent definitions
│   └── <name>.md
├── commands/         # override or add mode workflows
│   └── <mode>.md
└── skills/           # override skills (full directory replacement)
    └── <name>/
        ├── SKILL.md
        └── …
```

Resolution rules (see `src/content-loader.ts`):

- `agents/<name>.md` — replaces the embedded agent of the same name. Frontmatter is parsed for `description`, `model`, `allowed-tools`/`tools`. The body is sent to the agent verbatim.
- `commands/<mode>.md` — replaces the embedded mode workflow. Must contain a YAML `phases:` block (the engine parses this without LLM intervention).
- `skills/<name>/` — replaces the embedded skill directory wholesale. Must contain a `SKILL.md`. Reference scripts and templates can sit beside it; the `{baseDir}` placeholder is rewritten at extraction time.

If no override exists, the embedded copy is used. If you want to **add** a new agent or skill, just drop it in — there's no registration step.

## Customizing agents

Agents live in `src/content/agent-defs/<name>.md`. Each has thin frontmatter:

```yaml
---
description: One-line description shown in the agent picker
model: opus            # optional — defaults to harness setting
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Agent
---
```

The body is the prompt. To override:

```bash
mkdir -p ~/.config/vigolium-audit/agents
cp src/content/agent-defs/probe-lead.md ~/.config/vigolium-audit/agents/
$EDITOR ~/.config/vigolium-audit/agents/probe-lead.md
```

Tweak the prompt, narrow `allowed-tools`, swap the `model` — the next `vigolium-audit run` picks it up.

## Customizing modes (commands)

Mode workflows live in `src/content/command-defs/<mode>.md`. The frontmatter declares the phase graph that the orchestrator executes:

```yaml
---
description: What this mode does
argument-hint: "Optional arg shown in --help"
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Agent, AskUserQuestion, TaskCreate, TaskGet, TaskList, TaskUpdate
mode: deep
phases:
  - id: "1"
    title: Intelligence Gathering
    agent: cve-scout         # null for orchestrator-driven phases
    requires_git: true             # skip phase if .git is unavailable
    parallel_with: []              # phase IDs to run concurrently
    depends_on: []                 # phase IDs that must complete first
  …
---
```

Common override scenarios:

- **Drop a phase you don't need** — remove its entry from `phases:` and update any `depends_on` lists that referenced it.
- **Restrict scope** — pin `requires_git: true` on phases that touch git history, so they're skipped on plain-source-folder runs.
- **Swap the agent** — change `agent: probe-lead` to a custom agent you authored under `~/.config/vigolium-audit/agents/`.
- **Add a new mode** — drop `~/.config/vigolium-audit/commands/myaudit.md` with its own `phases:` block; invoke with `vigolium-audit run --mode myaudit`.

## Customizing skills

Skills are full directories with their own `SKILL.md` and (optionally) reference scripts, templates, hooks. To override:

```bash
mkdir -p ~/.config/vigolium-audit/skills/
cp -r src/content/skills/audit ~/.config/vigolium-audit/skills/
$EDITOR ~/.config/vigolium-audit/skills/audit/SKILL.md
```

Override is wholesale — if you copy `audit/` you're now responsible for everything inside it, including `assets/`, `references/`, `scripts/`. The original is shadowed completely until you delete the override.

`src/content/skills/skills-lock.json` records the upstream provenance + version of each skill (carried over verbatim from vigolium-audit). It's informational; the loader doesn't enforce it.

## Customizing harnesses

Per-platform configuration (Claude Code vs Codex) lives in `src/content/harnesses/<platform>/`:

- `frontmatter.yaml` — install-time merge config: per-agent tool allow-lists, model assignments, exclusions.
- `plugin.json` (claude only) — Claude Code plugin manifest.
- `agents-dispatch.md` (codex only) — Codex dispatch prompt.
- `subagent-preamble.md` (codex only) — preamble injected into every subagent invocation.

These are consumed automatically when `vigolium-audit run -i` starts: the harness frontmatter is merged into the agent definitions and written to the platform's expected config location (`~/.config/vigolium-audit/harness-claude/` or `~/.codex/agents/vigolium-audit-*.toml`) for the lifetime of the session, then removed on exit.

To customize platform behavior, edit these files and re-run `vigolium-audit run -i`. Note: there's no per-user override path for harnesses — these require a rebuild of the binary (or running from source) since the harness is rebuilt fresh on every interactive session.

## SDK variants

`src/content/sdk-variants/` holds SDK-safe variants of `agent-defs/` and `command-defs/`. They're generated by `scripts/transform-content.ts` (so the directory is `.gitignore`'d) and selected when an agent runs through an SDK rather than a CLI subprocess — the transformation strips frontmatter fields and tool calls the SDK doesn't understand.

To regenerate after editing `agent-defs/` or `command-defs/`:

```bash
bun run scripts/transform-content.ts
```

`loadAgent` / `loadCommand` accept `{ variant: "sdk" }` to opt into the variant; the engine sets this automatically when `--agent claude` resolves to the SDK adapter.

## Environment variables

| Var | Purpose |
|---|---|
| `VIGOLIUM_AUDIT_CONFIG_DIR` | Override directory for agents/commands/skills. Default: `~/.config/vigolium-audit/` |
| `VIGOLIUM_AUDIT_BIN_DIR` | Where the installer drops the `vigolium-audit` binary. Default: `~/.local/bin/` |
| `VIGOLIUM_AUDIT_VERSION` | Pin a specific release version at install / build time |
| `VIGOLIUM_AUDIT_BUILD_NO_INSTALL` | Skip the post-build copy to `VIGOLIUM_AUDIT_BIN_DIR` |
| `VIGOLIUM_AUDIT_RELEASE_SKIP_BUILD` | Reuse `build/dist/` from a prior `bun run build:all` |
| `VIGOLIUM_AUDIT_RELEASE_DRY_RUN` | Skip the `mc` upload step in `bun run release` |
| `SKIP_PATH_SETUP` | Don't append `VIGOLIUM_AUDIT_BIN_DIR` to your shell `PATH` during install |

Auth-related (one-shot, applied for the lifetime of a single `vigolium-audit run`):

| Flag | Effect |
|---|---|
| `--api-key <key>` | Sets `ANTHROPIC_API_KEY` (claude) or `OPENAI_API_KEY` (codex) |
| `--oauth-token <token>` | Sets `CLAUDE_CODE_OAUTH_TOKEN` |
| `--oauth-cred-file <path>` | Temporarily replaces `~/.claude/.credentials.json` (claude) or `~/.codex/auth.json` (codex); the original is moved to `<target>.vigolium-audit-backup` and restored on exit (including on Ctrl-C / SIGTERM) |

Secrets passed via flag are redacted in the `[auth] applied: …` log line.

## Rebuilding after edits to vendored content

Edits to `src/content/` only take effect in dev mode (`bun run dev`) until you rebuild the binary:

```bash
bun run build           # current platform → build/dist/ + ~/.local/bin/vigolium-audit
bun run build:all       # all 4 targets
```

The build inlines the entire `src/content/` tree into `src/content-bundle.json` and embeds it into the compiled binary. On first run, the binary extracts the bundle to `~/.cache/vigolium-audit/content-<hash>/` and reads from there; subsequent runs reuse the cache. Bumping the bundle invalidates the cache automatically (the hash is derived from the bundle's `generated_at` timestamp).

## Verifying overrides

```bash
vigolium-audit verify claude
```

The preflight checks the binary, auth, content extraction, harness install, and a real message round-trip. Add `--json` for machine-readable output:

```bash
vigolium-audit verify claude --json | jq '.content.overrides'
```

If an override file fails to parse, `verify` surfaces the error with the offending path so you can fix it before kicking off a multi-hour run.
