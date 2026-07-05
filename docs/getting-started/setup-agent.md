# Setting Up the Agent

Vigolium's AI features (autopilot, swarm, source-code audit, query) all run through one in-process runtime called **olium**. olium talks to a provider (Claude / OpenAI / a local model), and two specialised drivers — **audit** and **piolium** — run on top of it for source-code audits.

This page walks you through wiring each piece up. Pick the section that matches your setup; you don't need all of them.

| What | Section | When you need it |
|---|---|---|
| olium provider | [Olium agent](#1-olium-agent-the-engine-everything-runs-on) | Always — every agent command needs one provider. |
| Codex (OpenAI OAuth) | [Codex](#2-codex-cheapest-with-a-chatgpt-subscription) | You have a ChatGPT Plus/Pro/Team subscription. |
| Local model (Ollama, etc.) | [Local / OpenAI-compatible](#3-local-models-ollama-openrouter-lm-studio-) | You want to run agents offline or against OpenRouter / vLLM / LM Studio. |
| Claude | [Claude](#4-claude-anthropic) | You have an Anthropic API key, a Claude subscription, or the `claude` CLI installed (not recommended — see section). |
| Vigolium audit | [Vigolium audit](#5-vigolium-audit-source-code-driver) | You want a whitebox source-code audit with no extra install. |
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
| `anthropic-cli` | `claude` binary on `$PATH` | `claude-opus-4-7` | Shells out to Claude Code (alias: `anthropic-claude-cli`). |
| `anthropic-claude-sdk-bridge` | Claude Code subscription (no key) | bridge default | Claude Code via the Agent SDK (`vigolium-audit bridge` sidecar). |
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
# 1. Install Codex CLI (one-time) and log in via `codex login`
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
vigolium config set agent.olium.custom_provider.model_id anthropic/claude-sonnet-4.6
vigolium config set agent.olium.custom_provider.api_key '${OPENROUTER_API_KEY}'

# Optional: OpenRouter ranking signal (shows your app on the leaderboard).
vigolium config set agent.olium.custom_provider.extra_headers.add 'HTTP-Referer: https://your-site.example'
vigolium config set agent.olium.custom_provider.extra_headers.add 'X-Title: vigolium'
```

#### Provider routing (OpenRouter)

Pin or restrict the upstream provider via the typed `provider_routing` block:

```bash
vigolium config set agent.olium.custom_provider.provider_routing.order.add deepseek
vigolium config set agent.olium.custom_provider.provider_routing.allow_fallbacks false
vigolium config set agent.olium.custom_provider.provider_routing.sort throughput
```

Or as YAML:

```yaml
agent:
  olium:
    custom_provider:
      provider_routing:
        order: [deepseek]
        allow_fallbacks: false
        sort: throughput
```

Supported fields: `order`, `only`, `ignore`, `allow_fallbacks` (default `true` on OpenRouter), `sort` (`price` / `throughput` / `latency`), `quantizations`, `data_collection` (`allow` / `deny`), `require_parameters`, `zdr`. See [OpenRouter's provider routing docs](https://openrouter.ai/docs/features/provider-routing) for field semantics.

For fields the typed knob doesn't cover (`max_price`, `preferred_min_throughput`, `preferred_max_latency`) or other openai-compatible backend extensions, use `extra_body` (YAML-only — `config set` doesn't traverse arbitrary nested maps):

```yaml
agent:
  olium:
    custom_provider:
      extra_body:
        provider:
          max_price: { prompt: 0.0001, completion: 0.0002 }
        transforms: [middle-out]
```

The keys `model`, `messages`, `tools`, `stream`, `stream_options` are reserved and rejected at request time. Setting both `provider_routing` and `extra_body.provider` is also rejected.

### LM Studio

```bash
vigolium config set agent.olium.provider openai-compatible
vigolium config set agent.olium.custom_provider.base_url http://localhost:1234/v1
vigolium config set agent.olium.custom_provider.model_id <model-id-from-lm-studio>
```

### Custom headers (auth, routing, observability)

Some OpenAI-compatible backends need extra headers — non-`Bearer` auth schemes, tenant/routing signals, request tagging for cost analytics, etc. `extra_headers` takes a list of curl-style `"Key: Value"` entries that are applied **after** the standard headers, so they can override `Authorization` when needed.

```bash
# Clear, then add. Each .add appends one header to the list.
vigolium config set agent.olium.custom_provider.extra_headers.clear ""
vigolium config set agent.olium.custom_provider.extra_headers.add 'X-Custom-ID: your-cli'
vigolium config set agent.olium.custom_provider.extra_headers.add 'Authorization: Bearer custom-api-token'
```

Or edit `~/.vigolium/vigolium-configs.yaml` directly:

```yaml
agent:
  olium:
    custom_provider:
      extra_headers:
        - "X-Custom-ID: your-cli"
        - "Authorization: Bearer custom-api-token"   # overrides the default Bearer api_key
```

Notes:

- `${VAR}` references are expanded from the environment when the config is loaded, so credentials don't need to be checked into the file.
- On duplicate keys the **last** entry wins (matches `http.Header.Set` semantics).
- Malformed entries (no `:`) are logged at warn level and skipped — the agent keeps running.
- To replace the whole list, run `.clear ""` first, then `.add` each entry.

You can also pass these as one-shot overrides without touching the config:

```bash
vigolium ol \
  --provider openai-compatible \
  --base-url http://localhost:11434/v1 \
  --model gemma4:latest \
  -p 'hello'
```

> `extra_headers` has no CLI flag — set it once in YAML (or via `config set ... .add`) and it sticks across runs.

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

### 4d. Claude Code via the Agent SDK (`anthropic-claude-sdk-bridge`)

Drives Claude Code through the **Agent SDK** instead of the plain `claude -p` CLI, by shelling out to the `vigolium-audit bridge` sidecar. Like `anthropic-cli` it uses your logged-in Claude Code subscription (no key), but the run is a controlled, reproducible SDK invocation: it always loads the `vigolium-scanner` skill (so the agent knows the `vigolium` CLI) and does **not** pull in your personal `~/.claude` config or a project's `CLAUDE.md`.

```bash
claude            # be logged in once

vigolium config set agent.olium.provider anthropic-claude-sdk-bridge
vigolium config set agent.olium.model opus   # optional: opus | sonnet | a full id; omit for the bridge default

vigolium ol -p 'what model are you running'
```

The `vigolium-audit` binary that hosts the bridge is **embedded** in vigolium — no separate install. Override it with `vigolium config set agent.olium.bridge_binary /path/to/vigolium-audit` or the per-run `--bridge-bin` flag. If you have an API key or OAuth token in `agent.olium.llm_api_key` / `oauth_token`, it's forwarded to the bridge; otherwise the ambient subscription is used.

**When to pick this over `anthropic-cli`:** choose the bridge for a portable, self-contained run that behaves the same on any machine (CI, containers) and comes pre-wired with the vigolium scanner skill. Choose `anthropic-cli` when you want your full personal Claude Code environment — your `CLAUDE.md`, MCP servers, and installed skills — applied to the current project directory.

---

## 5. Vigolium Audit — source-code driver

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

Audit modes: `lite` (3 phases, CI-friendly), `balanced` (9 phases, default for `--audit=balanced`), `deep` (12 phases, full audit). All produce findings under the same parser/schema as native scanner output and are ingested into the vigolium DB.

Findings land under `~/.vigolium/agent-sessions/<scan-uuid>/vigolium-results/`. See [`docs/agentic-scan/vigolium-audit.md`](../agentic-scan/vigolium-audit.md) for the full reference.

---

## 6. Piolium audit — Pi-native driver

`vigolium agent audit --driver=piolium` runs a separate, more thorough audit (17 phases at `deep`) via the **Pi coding-agent runtime**. Unlike audit, piolium is **not** embedded — you install it once and vigolium drives the `pi` binary.

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
vigolium agent audit --driver=piolium --source ~/src/your-app                            # balanced (default)
vigolium agent audit --driver=piolium --source ~/src/your-app --mode lite               # quick triage
vigolium agent audit --driver=piolium --source ~/src/your-app --intensity deep          # full 17-phase

# 5. Override pi's provider/model just for this run if you want.
vigolium agent audit --driver=piolium --source ~/src/your-app \
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

# Vigolium audit (requires claude installed):
vigolium agent audit --source . --mode lite

# Piolium audit (requires pi + piolium installed):
vigolium agent audit --driver=piolium --source . --mode lite
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
