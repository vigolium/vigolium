<p align="center">
  <a href="https://github.com/vigolium"><img alt="Vigolium" src="https://avatars.githubusercontent.com/u/266502139?s=200&v=4" height="140" /></a>
  <br />
  <strong>Vigolium - High-fidelity vulnerability scanner with native scan precision and agentic scan intelligence.</strong>
  <br />

  <p align="center"><a href="https://www.vigolium.com">www.vigolium.com</a> - <a href="https://docs.vigolium.com"> docs.vigolium.com</a></p>
</p>

# Archon Audit

Archon is an autonomous agent within Vigolium that performs comprehensive security audits on your repository, focusing on uncovering exploitable vulnerabilities with high accuracy.

> [!WARNING]
> A full audit run can take a few hours. Go enjoy your coffee ☕ and take a walk. Don't worry, it's worth the wait.

## Why?

Static analysis tools bury you in false positives. Manual audits are thorough but slow and expensive. `archon-audit` runs security audits as a multi-agent pipeline: each phase builds on the last — from gathering advisories, to flagging candidates, to proposing attack paths, to debating exploitability, to a final verification pass that kills false positives. The workflow is resumable and incremental — re-run after a code change and only affected phases re-execute.

The goal is simple: spend machine time instead of human time, and only surface findings that are real.

## Install

```bash
npm install -g @vigolium/archon-audit
```

Or via curl:

```bash
curl -fsSL https://cdn.vigolium.com/archon-audit/install.sh | bash
```

The installer detects your platform (darwin/linux × arm64/x64), verifies the
sha256 checksum, drops `archon-audit` into `~/.local/bin/`, and adds that directory
to your shell `PATH`. Override env vars (`ARCHON_BIN_DIR`, `ARCHON_VERSION`,
`SKIP_PATH_SETUP`, …) — see [`build/scripts/install.sh`](./build/scripts/install.sh).

## Status

Pre-alpha. Under active development.

## Requirements

`archon-audit` is a slim binary that drives Claude or Codex via their official SDKs. Users must have one (or both) of:

- [`claude`](https://www.npmjs.com/package/@anthropic-ai/claude-code) on PATH (for `--agent claude`)
- [`codex`](https://www.npmjs.com/package/@openai/codex) on PATH (for `--agent codex`)

Plus the corresponding API key, or ambient subscription auth on the CLI.

## Quickstart

```bash
# just start the audit
archon-audit run --mode balanced --target /path/to/repo/

# Run a deep audit interactively (auto-installs the harness for the session
# and removes it on exit — leave-no-trace)
archon-audit run --mode deep --agent claude -i

# Headless deep audit, abort if cost exceeds $20
archon-audit run --mode deep --agent codex --max-cost 20

# Preflight: binary, auth, content, real message round-trip
archon-audit verify claude
```

### Auth overrides

Three flags on `archon-audit run` swap auth in for the lifetime of one run, then
restore the original state on exit:

```bash
# Pass an API key via flag (claude → ANTHROPIC_API_KEY, codex → OPENAI_API_KEY)
archon-audit run --mode deep --agent claude --api-key sk-ant-...

# Set CLAUDE_CODE_OAUTH_TOKEN for the subprocess / SDK
archon-audit run --mode deep --agent claude --oauth-token sk-ant-oat01-...

# Temporarily replace ~/.codex/auth.json with a custom file
# (~/.claude/.credentials.json for --agent claude). The original file is moved
# to <target>.archon-backup before the run and restored on exit.
archon-audit run --mode deep --agent codex --oauth-cred-file ./codex-auth.json
```

Secrets passed via flag are redacted in the `[auth] applied: …` log line. The
cred-file backup is also restored on Ctrl-C / SIGTERM.

### Machine-readable output

Every command supports `--json` for tooling. Logs stay on stderr; structured
JSON goes to stdout (single object for verify/uninstall, NDJSON event
stream for `run`).

```bash
archon-audit verify claude --json | jq .ok
archon-audit run --mode lite --agent claude --json | jq -c 'select(.kind == "phaseEnd")'
```

## Audit Modes

Archon ships a handful of audit modes — each is a different phase graph
selecting how thorough vs. fast the run is, and what it focuses on. The
short version:

| Mode | Use it when |
|------|-------------|
| `lite` | You want a fast surface scan (secrets + SAST + PoC) on a plain folder. |
| `balanced` | You want a real audit but not the full deep pipeline — middle ground. |
| `deep` | You want the full multi-agent pipeline: highest signal, longest run. |
| `revisit` | You already have a complete `deep` result and want a second anti-anchored pass. |
| `reinvest` | You want cross-agent re-verification of existing CRIT/HIGH findings (claude ↔ codex). |
| `confirm` | You want findings exercised against a live or booted target. |
| `diff` | A small change landed; re-run only deep phases the diff affects. |
| `merge` | You ran archon-audit multiple times and want one normalized findings tree. |
| `longshot` | Architecture-anchored audits feel exhausted — bottom-up file-by-file hail-mary. |
| `refresh` | You don't want to pick: router resolves to `revisit` or fresh `deep`. |

Run `archon-audit list` for the live view — descriptions, phase counts, and
observed median runtime from your prior runs. Canonical phase definitions
live in [`src/content/command-defs/`](./src/content/command-defs/);
overriding or extending them (per-user or per-project) is documented in
[`CUSTOMIZATION.md`](./CUSTOMIZATION.md).

### `deep` mode phases

`deep` is a 12-phase pipeline where each phase feeds the next — intel first,
then static analysis, then adversarial review, then PoC and reporting. `D1`/`D2`
run in parallel; `D2` and `D3` are skipped on a no-git target.

| Phase | What it does |
|-------|--------------|
| `D1` Intelligence Pass (CVE) | Collect known CVEs/advisories for the project's stack and dependencies. |
| `D2` Intelligence Pass (History) | Mine git history for security-relevant commits, regressions, and risky changes. *(git only)* |
| `D3` Patch Audit | Inspect prior security fixes for incomplete patches or bypasses. *(git only)* |
| `D4` Threat Model | Build the attack surface and threat model from architecture and entry points. |
| `D5` Code Scan | Static (SAST-style) scan for vulnerable code patterns; enumerates cross-service edges. |
| `D6` Deep Probe | Targeted, manual-style investigation of the most suspicious areas. |
| `D7` Access Audit | Authn/authz and access-control review — broken access, IDOR, privilege escalation. |
| `D8` Review Panel | Adversarial review chamber: debates exploitability and kills false positives (also folds in taint reasoning + variant expansion). |
| `D9` Intent Reconciliation | Reconcile survivors against intended behavior to drop by-design "findings". |
| `D10` PoC Authoring | Write concrete proof-of-concept exploits for the surviving findings. |
| `D11` Finding Finalize | Normalize and finalize findings into the canonical `archon/findings/` tree. |
| `D12` Report Compose | Assemble the final audit report. |

### Output cleanup

Completed `deep`/`confirm` runs, including successful resumes of those modes, automatically prune
raw workspaces after success so the final `archon/` tree contains only durable
deliverables: state JSON, `file-state.json`, `attack-surface/`, finalized
`findings/` + `findings-theoretical/`, mode reports, and `confirm-workspace/`
for confirmation runs. Failed or aborted runs keep raw directories for resume
and debugging. Use `--strip-raw` or `archon-audit strip <path>` for modes that
do not auto-prune.

### Resuming an interrupted audit

If a run is killed mid-way (quota limit, SIGINT, `--max-cost` cap, crash),
the audit stays non-complete in `archon/audit-state.json`. Pick it up
where it left off — completed phases are skipped, stale `in_progress`
phases are quarantined and retried:

```bash
archon-audit resume ./repo                       # auto-detect mode + audit
archon-audit run --mode deep --resume            # explicit form
```

## Project Structure

```
archon/
├── src/
│   ├── cli/                # run / setup / verify / uninstall entry points
│   ├── engine/             # orchestrator, phase parser, state, harness, modes
│   ├── adapters/           # claude/codex CLI + SDK adapters, platform detect
│   ├── content/            # vendored audit methodology
│   │   ├── agent-defs/         # 31 specialist agent prompts (.md)
│   │   ├── command-defs/       # 9 mode workflows (lite/balanced/deep/…)
│   │   ├── skills/             # 20 standalone workflow skills
│   │   ├── harnesses/          # platform-specific frontmatter (claude, codex)
│   │   ├── sdk-variants/       # generated SDK-safe variants (gitignored)
│   │   └── skills-lock.json    # skill version locks
│   ├── content-bundle.json # build-time inlined content for the compiled binary
│   ├── content-loader.ts   # resolves vendored content + per-user overrides
│   └── index.ts            # CLI entry point
├── build/                  # release packaging (build.ts, install.sh)
├── scripts/                # transform-content.ts, sync helpers
└── tests/
    └── fixtures/           # sample runtime logs (`archon-runtime.log`, `archon-json-output.jsonl`) captured from real runs
```

Audit output lands in `archon/` inside the target repository (e.g. `archon/audit-state.json`, `archon/findings/`, `archon/final-audit-report.md`).

Per-user customization (overrides for agents, commands, skills) lives in `~/.config/archon/`. See [`CUSTOMIZATION.md`](./CUSTOMIZATION.md).

## Development

```bash
bun install
bun run dev -- run --mode lite --agent claude --target ./fixtures/tiny-vuln
bun test
bun run build           # current platform binary → build/dist/ + ~/.local/bin/archon-audit
bun run build:all       # all 4 targets (host platform also installed)
bun run npm-publish     # publish @vigolium/archon-audit (single bundled pkg) to npm
```

`bun run build` also copies the just-built binary to `~/.local/bin/archon-audit`
for fast local testing. Override the destination with `ARCHON_BIN_DIR=…` or
skip the copy with `ARCHON_BUILD_NO_INSTALL=1`.

## Releasing

`bun run release` mirrors the Go archon-audit's `make release` flow:
