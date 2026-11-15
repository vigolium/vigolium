# vigolium-scanner

Coding-agent skill for operating the [Vigolium](https://www.vigolium.com/) web
vulnerability scanner CLI. Teaches Claude Code, Codex, Cursor, Pi, or any
[agentskills.io](https://agentskills.io)-compatible agent how to pick the right
command, construct correct flags, triage findings, and confirm them.

## Install

The skill is embedded in the `vigolium` binary, so the installed copy always
matches your CLI version. Prefer this over copying files by hand:

```bash
vigolium skills install --agent claude --scope project   # --agent claude|codex|agents
vigolium skills                                          # list bundled skills
vigolium skills get vigolium-scanner --full              # print SKILL.md + every reference
```

| `--agent` | `--scope project` | `--scope global` |
|-----------|-------------------|------------------|
| `claude` | `.claude/skills/` | `~/.claude/skills/` |
| `codex` \| `agents` | `.agents/skills/` | `~/.agents/skills/` |

### Keeping it current

Each install writes `.vigolium-skill.json` beside `SKILL.md`: the skill name,
the installing binary's `binary_version` and `commit`, the `bundle_sha256`, the
sha256 of every file, and `installed_at`. Agents ignore the dotfile, and
`SKILL.md` is copied unchanged. After upgrading vigolium:

```bash
vigolium skills ls                        # state of every install location
vigolium skills install --force           # refresh one (same --agent/--scope)
vigolium doctor --fix --only skill        # refresh every stale copy in place
```

`skills ls` checks `./.claude/skills`, `~/.claude/skills`, `./.agents/skills`
and `~/.agents/skills` and reports each copy as `current`, `stale` (from another
bundle, or an install that has no manifest), `modified` (a listed file was
edited or removed) or `missing`. `skills ls -j` returns the same data under
`installed`. A plain `skills install` leaves an existing copy alone and prints
`stale: run vigolium skills install --force` when it is out of date. `--force`
deletes the files the old manifest lists that the new bundle no longer ships
and keeps files you added. An install without a manifest is moved to
`<dir>.bak-<timestamp>` (its `SKILL.md` renamed to `SKILL.md.bak` so the agent
does not load it twice) before the fresh copy is written. `doctor` warns about
stale and modified copies. `doctor --fix` reinstalls only the stale ones, so
your local edits are never overwritten.

Once installed it auto-triggers on mentions of scanning, vigolium, DAST, or
vulnerability testing. In Claude Code you can also invoke it explicitly as
`/vigolium-scanner`.

Alternatives (not version-matched): `bunx skills add vigolium/skills --skill
vigolium-scanner --agent <name> --yes`, or clone
[vigolium/skills](https://github.com/vigolium/skills) and copy the folder into
`~/.claude/skills/` or `~/.agents/skills/`.

## Layout

```
vigolium-scanner/
├── SKILL.md                      # always loaded: contract, loop, router, rules
└── references/                   # loaded on demand, one hop from SKILL.md
    ├── agent-loop.md             # ★ driving vigolium from an agent: start here (token
    │                             #   discipline, gotchas, which loop-*.md has each step)
    ├── loop-scan.md              # scope, host-list sweep, --dry-run plan, scan document, gates
    ├── loop-watch.md             # --events stream, statuses, coverage, scan status/wait/stop
    ├── loop-read.md              # finding/traffic triage, exports, --format fs trees
    ├── loop-confirm.md           # verify, replay, mark, diff, bulk replay, fuzz
    ├── loop-handoff.md           # Burp/Caido, curl, reports, agent-run documents
    ├── invariants.md             # cross-command rules -h won't tell you, the -j envelope,
    │                             #   error codes and exit codes
    ├── recipes.md                # multi-step workflows (plan → wait → new-since, …)
    ├── scanning.md               # scan, scan-url, scan-request, run, phases, strategies,
    │                             #   pace + per-phase dials, tool shims (ffuf/nuclei/…)
    ├── fuzzing.md                # vigolium fuzz: positions, attack modes, anomaly scoring
    ├── kit.md                    # vigolium kit: secret-scan, js-beautify, oast, harvest, …
    ├── burp.md                   # Burp bridge, Repeater/Organizer/Site map, --send-via-burp
    ├── agent-modes.md            # agent query/autopilot/swarm/audit/olium/triage/session
    ├── auth.md                   # --auth-file / --auth, YAML format, extract rules
    ├── data.md                   # db, finding, traffic, module, ext, js, config, export
    ├── server.md                 # vigolium server: REST API, recording/MITM proxy, live mirror
    ├── ingest.md                 # vigolium ingest: local/remote, per-format input examples
    ├── extensions.md             # writing JS scanner modules against vigolium.*
    └── flags.generated.md        # GENERATED from the cobra tree — grep it by flag name
```

`SKILL.md` is the only file always in context; it routes to at most one reference
per task. If you are building an agent integration, start with
`references/agent-loop.md` — it maps the `scope → plan → scan → watch → read →
confirm → mark → diff → hand off` loop onto one `loop-*.md` file per step and
states the token-bounding flags; `references/invariants.md` holds the `-j`
envelope, the `error.code` table and the exit codes. Without the skill on disk,
`vigolium skills get vigolium-scanner --ref <file>` prints one reference.

## Maintaining

`references/flags.generated.md` is generated — never edit it by hand:

```bash
make skill-flags          # or: vigolium skills gen-flags
```

Re-run it whenever a flag is added, renamed, or given a shorthand; the file is
committed so the embedded bundle stays self-contained.

Everything else is hand-written prose. Two rules keep it useful:

1. **Keep `SKILL.md` under ~500 lines.** It is loaded in full every time the
   skill triggers, so anything that belongs to one topic belongs in that topic's
   reference instead.
2. **Don't restate flags.** If `vigolium <cmd> -h` answers it, link to the
   generated reference rather than copying rows that will drift.

## Docs

- Install & usage guide: [`docs/agentic-scan/using-vigolium-in-agent.md`](../../docs/agentic-scan/using-vigolium-in-agent.md)
- Driving vigolium from an agent: [`docs/coding-agent.md`](../../docs/coding-agent.md)
- Full documentation: [docs.vigolium.com](https://docs.vigolium.com/)
- Cheat sheet: [docs.vigolium.com/getting-started/cheat-sheet](https://docs.vigolium.com/getting-started/cheat-sheet)
- Skills repository: [github.com/vigolium/skills](https://github.com/vigolium/skills)
