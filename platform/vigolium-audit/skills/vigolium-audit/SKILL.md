---
name: vigolium-audit
description: Use when the user asks to run a security audit, find vulnerabilities in a repo, "audit this codebase", check for exploitable bugs, or otherwise drive `vigolium-audit` — the autonomous multi-agent security auditor. Covers install, mode selection (lite / balanced / deep / revisit / reinvest / confirm / diff / merge / longshot), resume, and machine-readable output.
---

# Vigolium-Audit

`vigolium-audit` is an autonomous multi-agent security auditor. It drives Claude Code or Codex through a fixed audit methodology (intel → SAST → adversarial review → PoC → report), eliminates false positives, and produces a finalized findings tree.

This skill teaches the agent how to install it, pick the right mode, and invoke it correctly.

## Install

```bash
# npm (recommended)
npm install -g @vigolium/vigolium-audit

# or curl
curl -fsSL https://cdn.vigolium.com/vigolium-audit/install.sh | bash
```

### Requirements

Vigolium-audit is a slim binary that drives either Claude Code or Codex. The user must have at least one of these on `PATH`, plus the corresponding auth (API key env var or ambient subscription on the CLI):

- [`claude`](https://www.npmjs.com/package/@anthropic-ai/claude-code) — used with `--agent claude`
- [`codex`](https://www.npmjs.com/package/@openai/codex) — used with `--agent codex`

Verify the install end-to-end (binary, auth, content, real message round-trip):

```bash
vigolium-audit verify claude
vigolium-audit verify codex
vigolium-audit verify codex --transport both
```

For headless runs, `--transport auto|sdk|cli` selects the adapter. Codex
`auto` prefers the Codex Agent SDK and can reuse ambient `codex login` auth;
use `--transport cli` for the native `codex exec` fallback. Interactive `-i`
always uses the native CLI.

## Audit modes

Each mode is a different phase graph — trading thoroughness against runtime/cost. Pick by intent:

| Mode | When to use | Notes |
|------|-------------|-------|
| `lite` | Fast surface scan: secrets + SAST + PoC | 3 phases, minutes, works on plain folders |
| `balanced` | Real audit, faster than `deep` | 9 phases, middle ground |
| `deep` | Full multi-agent pipeline, highest signal | 12 phases, hours — recommended default |
| `revisit` | Second anti-anchored pass on an existing `deep` result | Reuses KB, redoes reasoning phases |
| `reinvest` | Cross-agent re-verification of CRIT/HIGH findings | Run with the *other* agent (claude ↔ codex) |
| `confirm` | Exercise findings against a live or booted target | Boots app, runs PoCs, falls back to generated tests |
| `diff` | Re-audit only what a small change touched | Requires git history |
| `merge` | Normalize multiple `vigolium-results/` outputs into one tree | Post-process step |
| `longshot` | Bottom-up, file-by-file hail-mary | Use when architecture-anchored audits feel exhausted |
| `refresh` | "Just do the right thing" router | Resolves to `revisit` or fresh `deep` |

`vigolium-audit list` shows the live view including phase counts and observed median runtimes from prior runs on this machine.

## Example commands

```bash
# Fastest sanity scan
vigolium-audit run --mode lite --agent claude --target /path/to/repo

# Default recommendation — full deep audit, headless
vigolium-audit run --mode deep --agent claude --target /path/to/repo

# Deep audit interactively (auto-installs harness for the session, removes on exit)
vigolium-audit run --mode deep --agent claude -i

# Cap cost — abort if the run exceeds $20
vigolium-audit run --mode deep --agent codex --max-cost 20

# Explicit Codex Agent SDK run (this is also Codex's auto default)
vigolium-audit run --mode deep --agent codex --transport sdk

# Codex interactive mode auto-submits the canonical deep dispatch prompt
vigolium-audit run --mode deep --agent codex -i

# Cross-agent re-verification of an existing deep run's CRIT/HIGH findings
vigolium-audit run --mode reinvest --agent codex --target /path/to/repo

# Second anti-anchored pass on a completed deep audit
vigolium-audit run --mode revisit --agent claude --target /path/to/repo

# Re-audit only what changed since the last audited commit
vigolium-audit run --mode diff --agent claude --target /path/to/repo

# Boot the target and confirm existing findings against it
vigolium-audit run --mode confirm --agent claude --target /path/to/repo

# Resume an interrupted run (auto-detects mode + audit id)
vigolium-audit resume /path/to/repo
```

### One-shot auth overrides

These flags swap auth for the lifetime of a single run and restore the original state on exit (including SIGINT/SIGTERM):

```bash
vigolium-audit run --mode deep --agent claude --api-key sk-ant-...
vigolium-audit run --mode deep --agent claude --oauth-token sk-ant-oat01-...
vigolium-audit run --mode deep --agent codex --oauth-cred-file ./codex-auth.json
```

### Machine-readable output

Every command supports `--json`. Logs stay on stderr; structured JSON goes to stdout (single object for `verify`/`uninstall`, NDJSON event stream for `run`):

```bash
vigolium-audit verify claude --json | jq .ok
vigolium-audit run --mode lite --agent claude --json | jq -c 'select(.kind == "phaseEnd")'
```

## Picking a mode (decision tree)

1. **No prior audit on this repo?** → `deep` for the real thing, or `lite` for a 5-minute look.
2. **Have a completed `deep` audit and want more coverage?** → `revisit` (anti-anchored second pass) *or* `reinvest` with the other agent (cross-model verification of CRIT/HIGH).
3. **Code changed since the last audit?** → `diff`.
4. **Need to prove a finding is real against a running target?** → `confirm`.
5. **Architecture-anchored audits feel exhausted, suspect bugs hiding in unusual files?** → `longshot`.
6. **Have multiple `vigolium-results/` directories to combine?** → `merge`.

## Output

Audit artifacts land in `<targetDir>/vigolium-results/`:

- `audit-state.json` — phase graph state (resume baseline)
- `findings/<Severity><N>-<slug>/` — finalized findings
- `findings-draft/` — in-progress (watched live)
- `final-audit-report.md`, `confirmation-report.md`, `merge-report.md` (mode-dependent)

`deep` and `confirm` automatically prune raw workspaces on success. For other modes use `--strip-raw` or `vigolium-audit strip <path>`.

## Resume

Interrupted runs (quota, SIGINT, `--max-cost` cap, crash) stay non-complete in `audit-state.json`. Completed phases skip; stale in-progress phases are quarantined and retried:

```bash
vigolium-audit resume /path/to/repo            # auto-detect mode + audit
vigolium-audit run --mode deep --resume        # explicit form
```

## Customization

Per-user overrides live under `~/.config/vigolium-audit/{agents,commands,skills}/`. The engine resolves user overrides first, then SDK-safe variants, then the embedded copies — so dropping a same-named file under that path patches the methodology for the current user. See `CUSTOMIZATION.md` in the repo for the full layering rules.
