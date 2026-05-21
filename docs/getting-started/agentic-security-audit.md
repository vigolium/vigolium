# Agentic Security Audit

The **agentic security audit** is Vigolium's whitebox, source-code-driven
counterpart to the [agentic scan](agentic-scan.md). Where the agentic scan
sends traffic and probes responses, the audit reads the code: it walks the
git history, builds a threat model, runs SAST, hunts variants of confirmed
bugs, and puts each candidate finding through an adversarial debate before
admitting it to the report.

It is designed for **thorough** code review — pre-release audits, compliance
work, bounty-style deep dives — not just lint-style passes.

## Two harnesses, same output

Vigolium ships two audit harnesses that share an on-disk schema, a finding
format, and the database tags they apply. They differ only in **which model
family drives the audit**.

| Harness | Driver | Default agent | Standalone npm |
|---|---|---|---|
| `vigolium agent vigolium-audit` | embedded — no extra install | Claude (Opus family) | [`@vigolium/vigolium-audit`](https://www.npmjs.com/package/@vigolium/vigolium-audit) |
| `vigolium agent piolium` | Pi runtime + Pi extension | provider-agnostic (GPT, Gemini, Claude, …) | [`@vigolium/piolium`](https://www.npmjs.com/package/@vigolium/piolium) |

Both produce the same finding schema, both ingest into the Vigolium
database, and both can also be run **standalone outside of Vigolium** as
their own npm CLIs — useful when you don't have Vigolium installed but you
do have Node/Bun and an API key.

Rule of thumb:

- **Claude Opus access?** Use `vigolium-audit`. Its prompt orchestration was
  tuned against Opus and produces the highest-quality findings on that
  family.
- **OpenAI, Gemini, or anything non-Claude?** Use `piolium`. Pi's adapter
  layer abstracts the provider so the same audit pipeline works across
  model families.
- **Not sure / want both?** Use `vigolium agent audit` — the unified driver
  runs `vigolium-audit` first and falls back to `piolium` if it fails, or
  with `--driver both` runs them sequentially under one parent scan with
  project-wide dedup.

## What "thorough" means here

Both harnesses run a multi-phase pipeline. The deep mode looks like this:

| Phase | What it does |
|---|---|
| Commit Archaeology | Walk git history for silent security fixes and undisclosed CVEs |
| Patch Bypass | Test whether prior patches are actually complete |
| Knowledge Base | Build the architecture model, trust boundaries, attack surface |
| Static Analysis | CodeQL + Semgrep with project-tailored rules |
| Deep Probe | Multi-hypothesis exploration with specialised agents |
| Spec Gap Analysis | Find divergences between docs/RFCs and the implementation |
| Enrichment & Filtering | Reachability + data-flow over SAST findings |
| Adversarial Debate | Agents argue for and against each candidate finding |
| Cold Verification | Independent zero-context re-verification |
| Variant Hunting | Search for variants of confirmed bugs across the codebase |
| Report Assembly | PoC building and advisory-style final report |

Lighter modes (`lite`, `balanced`) run a subset for CI-friendly turnaround.
`deep` is the full pipeline; `confirm` re-validates an existing audit against
live behaviour; `longshot` (piolium-only) is a file-by-file hail-mary sweep.

## Prerequisites

- A configured LLM provider. See [Setting Up the Agent](setup-agent.md). The
  `vigolium-audit` driver speaks to Claude (via `claude` or Codex via
  `codex`); `piolium` speaks to whichever provider you've configured for
  `pi`.
- The source you want to audit — a local path or a git URL. Vigolium clones
  remote URLs into a temp directory.

For `piolium` specifically, you also need the Pi runtime and the piolium
extension installed once on the host:

```bash
bun install -g @earendil-works/pi-coding-agent
pi install git:git@github.com:vigolium/piolium.git
pi login
```

`vigolium-audit` is **embedded** — no extra install. Vigolium extracts the
harness on first run.

## 1. Quick run

```bash
# Embedded audit (Claude/Codex), balanced mode.
vigolium agent vigolium-audit --source ~/src/your-app

# Piolium (Pi-driven, provider-agnostic), default balanced mode.
vigolium agent piolium --source ~/src/your-app

# Unified — let Vigolium pick. Falls back from vigolium-audit to piolium on failure.
vigolium agent audit --source ~/src/your-app
```

Findings stream to the console and are ingested into the database tagged
with the driver that produced them. Query them like any other finding:

```bash
vigolium finding list --source vigolium-audit
vigolium finding list --source piolium
```

## 2. Pick a depth

The `--mode` flag selects which phase chain to run; `--intensity` is a
higher-level alias.

```bash
# Quick triage — minutes, CI-friendly.
vigolium agent vigolium-audit --source ./src --mode lite
vigolium agent piolium       --source ./src --intensity quick

# Default balanced — solid coverage in reasonable time.
vigolium agent vigolium-audit --source ./src --mode balanced

# Full thorough audit — hours, adversarial debate + cold verify.
vigolium agent vigolium-audit --source ./src --mode deep
vigolium agent piolium       --source ./src --intensity deep   # 17 phases
```

You can also chain modes back-to-back with `--modes a,b,c` — for example
`--modes deep,confirm` runs the full audit and then re-verifies findings.
`--intensity deep` expands to that chain automatically.

Piolium-only modes worth knowing about:

- `revisit` — re-walk a prior audit with fresh hypotheses.
- `longshot` — file-by-file hail-mary scan, useful after a full audit.
- `diff` — audit only changes since a base commit.

## 3. Pair an audit with a live scan

The audit ingests into the same database as the network scan, so you can
correlate code-level findings with traffic-level findings on the same
target. The easiest way is to let `swarm` or `autopilot` schedule the audit
for you:

```bash
# Swarm — AI plans a scan AND runs vigolium-audit in the background.
vigolium agent swarm \
  -t https://example.com \
  --source ./src \
  --audit deep \
  --triage

# Autopilot — vigolium-audit runs first, the agent uses its findings as context.
vigolium agent autopilot \
  -t https://example.com \
  --source ./src \
  --audit balanced
```

When `pi` + `piolium` are installed locally, Vigolium auto-picks piolium for
the in-pipeline audit; pass `--audit <mode>` to force `vigolium-audit`
instead.

## 4. Standalone CLIs (no Vigolium needed)

Both harnesses are published as standalone npm packages. They produce the
same finding format and on-disk schema as the embedded versions — useful
when you want to run an audit on a machine that doesn't have the Vigolium
binary, or pin a specific harness version in CI.

```bash
# Vigolium Audit — https://www.npmjs.com/package/@vigolium/vigolium-audit
npm install -g @vigolium/vigolium-audit
vigolium-audit --source ~/src/your-app --mode balanced

# Piolium — https://www.npmjs.com/package/@vigolium/piolium
npm install -g @vigolium/piolium
piolium --source ~/src/your-app --mode deep
```

Findings land in `<source>/vigolium-audit/` (or `<source>/piolium/`) as
markdown files. If you later want them in the Vigolium database, import
them:

```bash
vigolium import /path/to/audit-output/
```

> **Tip — don't dirty the working tree.** Audit findings are written under
> the source directory by design. For a clean repo, run against an
> out-of-tree checkout, or make sure `findings-draft/`, `longshot/`, and
> `attack-surface/` are in `.gitignore`.

## Where results go

Every audit produces:

- **Database findings** — `vigolium finding list --source vigolium-audit`,
  `vigolium finding list --source piolium`.
- **Session artifacts** under `~/.vigolium/agent-sessions/<uuid>/` —
  `audit-state.json`, per-finding markdown, the final report,
  CodeQL/Semgrep output, the adversarial debate transcripts, the raw agent
  log.
- **A final advisory-style report** suitable for sharing with the team that
  owns the code.

## Next steps

- [Setting Up the Agent](setup-agent.md) — provider setup, BYOK auth, sanity checks.
- [Agentic Scan](agentic-scan.md) — the network-side counterpart.
- [Vigolium Audit](../agentic-scan/vigolium-audit.md) — full reference for the embedded driver, modes, finding format.
- [Piolium Audit](../agentic-scan/piolium-audit.md) — full reference for the Pi-driven driver.
- [Audit BYOK matrix](../agentic-scan/audit-byok.md) — how `--provider` / `--agent` / API-key flags resolve.
