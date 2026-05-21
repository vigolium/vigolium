# Setting Up the Agent

Vigolium's AI features (autopilot, swarm, source-code audit, query) all run through one in-process runtime called **olium**. olium talks to a provider (Claude / OpenAI / a local model), and two specialised drivers — **audit** and **piolium** — run on top of it for source-code audits.

This page walks you through wiring each piece up. Pick the section that matches your setup; you don't need all of them.

| What | Section | When you need it |
|---|---|---|
| olium provider | [Olium agent](#1-olium-agent-the-engine-everything-runs-on) | Always — every agent command needs one provider. |
| Codex (OpenAI OAuth) | [Codex](#2-codex-cheapest-with-a-chatgpt-subscription) | You have a ChatGPT Plus/Pro/Team subscription. |
| Local model (Ollama, etc.) | [Local / OpenAI-compatible](#3-local-models-ollama-openrouter-lm-studio-) | You want to run agents offline or against OpenRouter / vLLM / LM Studio. |
| Claude | [Claude](#4-claude-anthropic) | You have an Anthropic API key, a Claude subscription, or the `claude` CLI installed (not recommended — see section). |
| Audit audit | [Audit audit](#5-vigolium-audit-source-code-driver) | You want a whitebox source-code audit with no extra install. |
| Piolium audit | [Piolium audit](#6-piolium-audit-pi-native-driver) | You want piolium's 17-phase Pi-native audit (separate install). |

All settings live in `~/.vigolium/vigolium-configs.yaml`. You can edit it directly, or use `vigolium config set <key> <value>`.

---

## 1. Olium agent — the engine everything runs on

olium is the in-process agent runtime (`pkg/olium/`) that backs every `vigolium agent …` subcommand. Setting it up means picking one provider and giving it credentials.

The supported providers:

| Provider | Auth | Default model | Notes |
|---|---|---|---|
| `openai-codex-oauth` *(default)* | `~/.codex/auth.json` (from `codex login`) | `gpt-5.5` | Cheapest with a ChatGPT sub. |
| `anthropic-api-key` | `$ANTHROPIC_API_KEY` | `claude-opus-4-7` | Direct Anthropic API billing. |
| `anthropic-oauth` | `claude setup-token` bearer | `claude-opus-4-7` | Uses your Claude Pro/Max plan. |
| `openai-api-key` | `$OPENAI_API_KEY` | `gpt-5.5` | Direct OpenAI API billing. |
| `anthropic-cli` | `claude` binary on `$PATH` | `claude-opus-4-7` | Shells out to Claude Code. |
| `anthropic-vertex` | GCP service-account JSON | `claude-opus-4-6` | Claude on Vertex AI. |
| `google-vertex` | GCP service-account JSON | `gemini-2.5-pro` | Gemini on Vertex AI. |
| `openai-compatible` | optional `api_key` | none — pick one | Ollama, OpenRouter, LM Studio, vLLM, … |

Verify any setup with:

```bash
vigolium ol -p 'what model are you running'
```

If that returns a model name, the provider is wired correctly. From there, `vigolium agent autopilot`, `vigolium agent swarm`, etc. all work.

---

## 2. Codex — cheapest with a ChatGPT subscription (Recommended)

If you already use OpenAI's **Codex CLI**, vigolium reuses the same OAuth credential file. No API key needed, refresh handled automatically.

```bash
# 1. Install Codex CLI (one-time) and log in.
codex login
codex exec 'hello'             # sanity check — should print a model name

# 2. Pin vigolium to it (defaults already match; this just makes it explicit).
vigolium config set agent.olium.provider openai-codex-oauth
vigolium config set agent.olium.oauth_cred_path ~/.codex/auth.json
vigolium config set agent.olium.model gpt-5.5

# 3. Verify.
vigolium ol -p 'what model are you running'
```

`~/.codex/auth.json` is read on every run; the JWT is auto-refreshed when it expires, so you don't have to re-login.

---

## 3. Local models (Ollama, OpenRouter, LM Studio, …)

The `openai-compatible` provider talks to any backend that speaks the OpenAI Chat Completions wire format. Configure it under `agent.olium.custom_provider`.

### Ollama (local, no key)

```bash
ollama pull gemma4:latest
ollama serve   # if not already running

vigolium config set agent.olium.provider openai-compatible
vigolium config set agent.olium.custom_provider.base_url http://localhost:11434/v1
vigolium config set agent.olium.custom_provider.model_id gemma4:latest

vigolium ol -p 'what model are you running'
```

Empty `api_key` means no `Authorization` header is sent — required for Ollama.

### OpenRouter

```bash
export OPENROUTER_API_KEY=sk-or-…

vigolium config set agent.olium.provider openai-compatible
vigolium config set agent.olium.custom_provider.base_url https://openrouter.ai/api/v1
vigolium config set agent.olium.custom_provider.model_id anthropic/claude-3.5-sonnet
vigolium config set agent.olium.custom_provider.api_key '${OPENROUTER_API_KEY}'
```

### LM Studio

```bash
vigolium config set agent.olium.provider openai-compatible
vigolium config set agent.olium.custom_provider.base_url http://localhost:1234/v1
vigolium config set agent.olium.custom_provider.model_id <model-id-from-lm-studio>
```

You can also pass these as one-shot overrides without touching the config:

```bash
vigolium ol \
  --provider openai-compatible \
  --base-url http://localhost:11434/v1 \
  --model gemma4:latest \
  -p 'hello'
```

> **Tool-calling caveat.** OpenAI-style function tools are part of the wire format but only some models actually emit them. `gemma4`, `qwen2.5-coder`, `llama3.1-instruct`, and `mistral-nemo` work well. Smaller models often ignore tool definitions and reply in prose — if the agent never calls tools, switch model.

---

## 4. Claude (Anthropic)

> **Not recommended for olium.** Anthropic's Pro/Max subscriptions aren't really designed for use outside the official Claude Code client — driving the same token from vigolium (or any third-party agent) lands you in rate-limit / overage territory almost immediately, and the API-key path bills per token at the highest rates of any provider listed here. Prefer Codex ([section 2](#2-codex--cheapest-with-a-chatgpt-subscription-recommended)) or a local model ([section 3](#3-local-models-ollama-openrouter-lm-studio-)) for day-to-day agent work. The Claude options below exist for parity and for users who already pay for the API anyway.

Three options, in order of preference:

### 4a. Claude OAuth (Claude Pro/Max subscribers)

`claude setup-token` mints an OAuth bearer token tied to your Claude subscription. No per-token billing.

```bash
# 1. Install Claude Code, then mint a token.
claude setup-token                                 # prints sk-ant-oat01-…
export ANTHROPIC_API_KEY=sk-ant-oat01-<your-token> # shell rc; survives reboots

# 2. Point vigolium at the OAuth provider.
vigolium config set agent.olium.provider anthropic-oauth
vigolium config set agent.olium.model claude-opus-4-7

# 3. Verify.
vigolium ol -p 'what model are you running'
```

`anthropic-oauth` reads `agent.olium.oauth_token` first, then falls back to `$ANTHROPIC_API_KEY`. The env var is the path of least resistance.

> **Heads-up — enable extra usage on your Claude account.** Pro/Max subscriptions ship with the OAuth token capped to the in-app Claude Code allowance. Driving the same token from vigolium (or any third-party client) hits the Messages API directly and is rejected with `429 rate_limit_error` until you turn on **extra usage / pay-as-you-go overage** in the Anthropic Console (Settings → Billing → Usage limits). Without that toggle the verify call above will fail even with a valid token.

### 4b. Anthropic API key

For users billing through the standard Anthropic API.

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-<your-key>

vigolium config set agent.olium.provider anthropic-api-key
vigolium config set agent.olium.model claude-opus-4-7

vigolium ol -p 'what model are you running'
```

### 4c. Anthropic CLI (`claude` shell-out)

If you'd rather have vigolium delegate to the `claude` binary on `$PATH` (so it uses whatever auth `claude` itself is configured with):

```bash
which claude   # must resolve

vigolium config set agent.olium.provider anthropic-cli
vigolium config set agent.olium.model claude-opus-4-7
```

This mode is slower than the API-key/OAuth paths (subprocess overhead) but useful when you want a single source of auth across `claude` and `vigolium`.

> **Note on permissions.** vigolium invokes `claude -p` with `--permission-mode bypassPermissions` so Bash / Read / WebFetch tool calls execute without interactive approval (the wrapper is non-interactive — there's no TTY for you to confirm prompts on). This is equivalent to running `claude --dangerously-skip-permissions` and applies for the duration of the subprocess only.

---

## 5. Audit audit — source-code driver

`vigolium agent audit` runs a whitebox source-code audit. The harness (agents, commands, skills) ships **embedded in the vigolium binary** — no extra install. It drives the `claude` CLI under the hood, so you need a working Claude setup from [section 4](#4-claude-anthropic).

```bash
# 1. Make sure `claude` is installed and authenticated.
claude --version
claude -p 'hello'   # sanity check

# 2. Run an audit.
vigolium agent audit --source ~/src/your-app

# 3. Or wire it into autopilot/swarm so it runs automatically when --source is set.
vigolium config set agent.audit.enable true
vigolium config set agent.audit.mode lite          # lite | balanced | deep
vigolium agent autopilot -t https://example.com --source ~/src/your-app
```

Audit modes: `lite` (3 phases, CI-friendly), `balanced` (6 phases, default for `--audit=balanced`), `deep` (11 phases, full audit). All produce findings under the same parser/schema as native scanner output and are ingested into the vigolium DB.

Findings land under `~/.vigolium/agent-sessions/<scan-uuid>/vigolium-results/`. See [`docs/agentic-scan/vigolium-audit.md`](../agentic-scan/vigolium-audit.md) for the full reference.

---

## 6. Piolium audit — Pi-native driver

`vigolium agent piolium` runs a separate, more thorough audit (17 phases at `deep`) via the **Pi coding-agent runtime**. Unlike audit, piolium is **not** embedded — you install it once and vigolium drives the `pi` binary.

```bash
# 1. Install Pi runtime.
bun install -g @earendil-works/pi-coding-agent
pi --version

# 2. Install the piolium extension.
pi install git:git@github.com:vigolium/piolium.git
pi list                                # verify "piolium" appears

# 3. Configure pi's default provider (the audit subprocess uses pi's own auth,
#    not vigolium's). Example with Anthropic:
pi login                               # or: pi /login

# 4. Run an audit.
vigolium agent piolium --source ~/src/your-app                            # balanced (default)
vigolium agent piolium --source ~/src/your-app --mode lite               # quick triage
vigolium agent piolium --source ~/src/your-app --intensity deep          # full 17-phase

# 5. Override pi's provider/model just for this run if you want.
vigolium agent piolium --source ~/src/your-app \
  --pi-provider vertex-anthropic --pi-model claude-opus-4-6
```

Vigolium runs a one-turn preflight against pi before the audit to catch auth/quota errors early. If preflight fails you'll see the upstream error (e.g. `No API key found for google-vertex. Use /login to log into a provider`) and the audit won't start.

By default vigolium uses pi's per-user install at `~/.pi/agent`. To use a system-wide install instead, export `PIOLIUM_HOME=/opt/piolium` (or any other path). See [`docs/agentic-scan/piolium-audit.md`](../agentic-scan/piolium-audit.md) for modes, intensity presets, and the full flag reference.

### audit vs piolium

| | Audit | Piolium |
|---|---|---|
| Install | Embedded — zero setup | Requires `pi` + `pi install …` |
| Driver | `claude` CLI | `pi --mode json -p /piolium-<mode>` |
| Modes | lite (3), balanced (6), deep (11) | lite (4), balanced (9), deep (17), revisit, confirm, merge, diff, longshot |
| Provider | Whatever `claude` is configured with | Whatever `pi` is configured with (separate from olium) |
| Best for | "I want a source audit, no extra setup" | "I want the most thorough audit available" |

You can also run both side-by-side with `vigolium agent audit --driver both --source …` — that dispatches audit then piolium under a single parent scan with project-wide deduplication.

---

## 7. Verifying the full stack

After whichever sections you set up, run these in order. Each one fails fast with a useful error if a piece is missing:

```bash
# Olium: one prompt, one provider call. No DB, no scan.
vigolium ol -p 'hello'

# Agent query: same path the engine takes for source-code review.
vigolium agent query -p 'list every route in this repo' --source .

# Autopilot smoke test (target-only, no source):
vigolium agent autopilot -t https://example.com --intensity quick --max-duration 5m

# Audit audit (requires claude installed):
vigolium agent audit --source . --mode lite

# Piolium audit (requires pi + piolium installed):
vigolium agent piolium --source . --mode lite
```

If any of these errors out, the message points at the missing piece — usually an unset env var, a wrong `agent.olium.provider`, or a missing binary.

---

## Where to go next

- [`docs/agentic-scan/olium-agent.md`](../agentic-scan/olium-agent.md) — what olium is and what its tools do.
- [`docs/agentic-scan/autopilot.md`](../agentic-scan/autopilot.md) — autonomous scanning.
- [`docs/agentic-scan/swarm.md`](../agentic-scan/swarm.md) — guided multi-phase scanning.
- [`docs/agentic-scan/vigolium-audit.md`](../agentic-scan/vigolium-audit.md) — audit reference.
- [`docs/agentic-scan/piolium-audit.md`](../agentic-scan/piolium-audit.md) — piolium reference.
- [`public/vigolium-configs.example.yaml`](../../public/vigolium-configs.example.yaml) — every config knob with inline docs.
