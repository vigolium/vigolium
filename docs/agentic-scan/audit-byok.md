# Audit BYOK (Bring Your Own Key)

`vigolium agent audit` and `POST /api/agent/run/audit` accept per-run credentials so a single Vigolium install can drive audits with each operator's own Anthropic / OpenAI keys, without baking them into `agent.olium.*` config. The override applies to whichever driver(s) actually run on the request — both **audit** and **piolium** consume the same flags / fields and route them to the right place internally.

## Table of Contents

- [When to Use It](#when-to-use-it)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [CLI](#cli)
  - [Flag reference](#flag-reference)
  - [Indirection: `$ENV` and `@path`](#indirection-env-and-path)
  - [Examples](#examples)
- [REST API](#rest-api)
  - [Request fields](#request-fields)
  - [Examples](#rest-examples)
- [Provider Selection](#provider-selection)
- [Driver-Specific Behavior](#driver-specific-behavior)
  - [Audit](#audit)
  - [Piolium](#piolium)
- [Validation Rules](#validation-rules)
- [Logging & Redaction](#logging--redaction)
- [Operational Caveats](#operational-caveats)

---

## When to Use It

- The Vigolium server is shared by multiple operators and you want each run billed to the right account.
- A CI pipeline supplies short-lived OAuth tokens that shouldn't outlive the job.
- You want to test an audit run against a different provider than what `agent.olium.provider` is pinned to, without editing config.
- You're auditing customer code under a contractual obligation that the credentials never sit on disk in the standard `agent.olium.llm_api_key` field.

If none of those apply, leave the new flags empty — the audit driver inherits credentials from `agent.olium.*` exactly as it did before BYOK existed.

---

## Quick Start

```bash
# Anthropic API key, claude side (default agent)
vigolium agent audit --source ./src --intensity balanced \
  --api-key '$ANTHROPIC_API_KEY'

# Claude OAuth token (produced by `claude setup-token`)
vigolium agent audit --source ./src --intensity balanced \
  --oauth-token '$CLAUDE_CODE_OAUTH_TOKEN'

# Codex with a one-shot cred file (~/.codex/auth.json shape)
vigolium agent audit --source ./src --intensity balanced \
  --provider openai-codex-oauth \
  --oauth-cred-file ./codex-auth.json
```

```bash
# Same call over REST (literal value — REST does not honor $ENV / @path)
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "intensity": "balanced",
    "api_key": "sk-ant-real-secret"
  }' | jq .
```

---

## How It Works

A single `AuthOverride` bundle (`api_key` **or** `oauth_token` **or** `oauth_cred_file`, plus a resolved `agent` of `claude`/`codex`) flows through the audit dispatcher and is consumed differently by each driver:

| Step | What happens |
|---|---|
| 1. Entry point | CLI flags or REST body fields populate the override. CLI resolves `$ENV` / `@path` indirection at this point — REST does not. |
| 2. Agent resolution | `claude` vs `codex` is picked, highest first, by `--agent` (CLI) / `agent` field (REST) > `--provider` (CLI) > `agent.audit.default_agent` config > `agent.olium.provider`-derived > claude. This selects the agent only; the auth is the override / provider-derived bundle. |
| 3. Validation | Centralized rules: at most one of the three credential fields; `--oauth-token` requires the claude side. The resolved agent is also checked against the auth, so a selector-driven flip (e.g. `default_agent: codex`) can't silently pair codex with a claude-only token. Failure stops the request before any subprocess work. |
| 4a. Audit path | The resolved override **replaces** the olium-derived audit auth and is passed to `audit` as `--api-key` / `--oauth-token` / `--oauth-cred-file` flags. |
| 4b. Piolium path | The override becomes env vars on the `pi` subprocess (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`) — `pi` itself has no equivalent CLI flags. For codex + `--oauth-cred-file`, Vigolium stages the file at `<pi-agent-dir>/auth.json` for the duration of the run with backup-and-restore. |
| 5. Cleanup | At process exit, the staged `auth.json` is removed and any pre-existing file is restored. Cleanup also fires if `cmd.Start()` fails. |

The live `cmd.Env` used to spawn the subprocess always carries the real values; the override is only redacted when it appears in logs or the printed cmdline (see [Logging & Redaction](#logging--redaction)).

### Agent selection vs. auth (`--agent` / `agent.audit.default_agent`)

The **auth** (which credential is forwarded) and the **agent** (claude vs codex) are resolved independently. BYOK only ever sets the auth; it never changes the agent. The audit-leg agent is resolved by, highest first: `--agent` flag > `--provider` flag > `agent.audit.default_agent` config > `agent.olium.provider`-derived > claude. `--agent` and `default_agent` are **pure agent selectors** — they flip the agent while keeping the resolved auth, exactly like the documented `--agent` contract. So your BYOK creds are forwarded identically whether or not `default_agent` is set.

Because the selector and the auth are independent, you can pin one and still BYOK the other: e.g. with `default_agent: codex`, `--api-key sk-ant-…` would forward an Anthropic key to codex (a mismatch). Vigolium catches the one combination it can prove impossible — a claude-only `--oauth-token` (or an `anthropic-oauth` provider) resolving to a codex agent — and rejects it up front with `audit agent/auth mismatch: …` before any subprocess starts (REST returns `400`). API keys are agent-agnostic at this layer, so a wrong-vendor key is surfaced by `vigolium-audit` itself.

---

## CLI

### Flag reference

| Flag | Description |
|---|---|
| `--api-key <value\|$ENV\|@path>` | API key for the run. Routes to `ANTHROPIC_API_KEY` (claude) or `OPENAI_API_KEY` (codex). |
| `--oauth-token <value\|$ENV\|@path>` | Anthropic OAuth bearer token. Claude only — produced by `claude setup-token`. |
| `--oauth-cred-file <path\|$ENV>` | OAuth credential file (codex `~/.codex/auth.json` shape, or any provider that reads from a JSON file). Staged under `<pi-agent-dir>/auth.json` for piolium runs. |

All three flags are optional, mutually exclusive, and apply to **whichever driver(s) actually run on the invocation** — there is no separate `--driver=audit --api-key …` form.

### Indirection: `$ENV` and `@path`

CLI flag values accept three forms:

| Form | Meaning |
|---|---|
| `sk-ant-…` | Literal value. Visible in shell history and `ps`. |
| `$ANTHROPIC_API_KEY` | Read from the named environment variable. Errors if the variable is unset or empty. |
| `@./key.txt` | Read from the file at the path. Trailing whitespace and newlines are stripped. Errors if the file is missing or empty. |

> Indirection is **CLI-only**. The REST endpoint treats request fields as literal — resolving `$ENV` server-side from a network-supplied string would let any caller probe the server's process environment.

### Examples

```bash
# Anthropic API key from environment — preferred form: avoids leaking the
# key into ps / shell history. Indirection happens before the audit
# subprocess is spawned, so the resolved value never sits on the argv.
vigolium agent audit --source ./src --intensity balanced \
  --api-key '$ANTHROPIC_API_KEY'

# Anthropic API key from a mode-0600 file
echo -n 'sk-ant-real-secret' > ~/.vigolium/keys/anthropic.txt
chmod 600 ~/.vigolium/keys/anthropic.txt
vigolium agent audit --source ./src \
  --api-key @~/.vigolium/keys/anthropic.txt

# Claude OAuth token (one-shot for this run only; doesn't touch
# agent.olium.oauth_token in vigolium-configs.yaml)
vigolium agent audit --source ./src --mode deep \
  --oauth-token '$CLAUDE_CODE_OAUTH_TOKEN'

# Codex run — pin the agent to codex and supply a cred file.
# For piolium, vigolium stages the file at <pi-agent-dir>/auth.json,
# backs up any existing file, and restores it after the run exits.
vigolium agent audit --source ./src --driver piolium \
  --provider openai-codex-oauth \
  --oauth-cred-file ./codex-auth.json

# Codex run — driver=both runs audit then piolium with the same cred
# file applied to both
vigolium agent audit --source ./src --driver both \
  --provider openai-codex-oauth \
  --oauth-cred-file ./codex-auth.json

# CI / pipeline: short-lived API key from an env var; use the harness's
# driver-specific diff mode.
vigolium agent audit --source . --driver audit \
  --mode diff \
  --api-key '$CI_PROVIDED_ANTHROPIC_KEY'
```

---

## REST API

`POST /api/agent/run/audit` accepts three optional fields. The unified driver dispatcher applies them to whichever driver(s) actually run.

### Request fields

| Field | Type | Description |
|---|---|---|
| `api_key` | string | API key for the run. Treated as a literal — no `$ENV` / `@path` resolution. |
| `oauth_token` | string | Anthropic OAuth bearer token. Claude side only. |
| `oauth_cred_file` | string | Path **on the server's filesystem** to a cred file (codex `auth.json` shape). The server reads the file when staging — relative paths are resolved against the server's working directory. |

`agent` (already part of the request body) selects claude vs codex when audit participates and decides which env-var flavor piolium gets when `api_key` / `oauth_token` is set. With `agent` empty, the server falls back to `agent.olium.provider`.

> **`oauth_cred_file` reads from the server's filesystem**, not the caller's. Pre-stage the file or upload it via your own mechanism before kicking off the audit. A future revision may accept inline JSON; for now this stays a path so the codex provider can mmap it like a local install would.

### REST examples

```bash
# Anthropic API key as a literal — REST does NOT honor $ENV / @path
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "intensity": "balanced",
    "api_key": "sk-ant-real-secret"
  }' | jq .

# Claude OAuth token — claude side only (validator rejects oauth_token
# with agent: "codex" before any subprocess is started).
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "mode": "deep",
    "agent": "claude",
    "oauth_token": "sk-ant-oat01-..."
  }' | jq .

# Codex with a server-side cred file. driver=piolium stages it at
# <pi-agent-dir>/auth.json with backup-and-restore.
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "driver": "piolium",
    "agent": "codex",
    "oauth_cred_file": "/etc/vigolium/secrets/codex-auth.json"
  }' | jq .

# driver=both — same override fans out to audit (--api-key flag) and
# piolium (ANTHROPIC_API_KEY env var on the pi subprocess)
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "git@github.com:org/repo.git",
    "intensity": "balanced",
    "driver": "both",
    "agent": "claude",
    "api_key": "sk-ant-real-secret"
  }' | jq .

# Per-project key with project_uuid scoping
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "intensity": "balanced",
    "project_uuid": "11111111-2222-3333-4444-555555555555",
    "api_key": "sk-ant-customer-specific"
  }' | jq .
```

---

## Provider Selection

The credential **type** (`api_key` vs `oauth_token` vs `oauth_cred_file`) does not, on its own, decide whether the run goes to claude or codex. That comes from the existing provider-selection field:

| Selector | CLI | REST |
|---|---|---|
| Per-run override | `--provider` | `agent` |
| Server fallback | `agent.olium.provider` in `vigolium-configs.yaml` | same |
| Default | `claude` (matches audit's own default) | same |

| Provider override → resolved agent | Examples |
|---|---|
| `anthropic-*` | `claude` |
| `google-*` (`google-vertex`, etc.) | `claude` |
| `openai-*` | `codex` |
| empty | inherit `agent.olium.provider`, then claude default |

The same resolution drives both audit's `--agent` flag and which env var piolium gets (`ANTHROPIC_API_KEY` vs `OPENAI_API_KEY`).

---

## Driver-Specific Behavior

### Audit

- The override is folded into audit's invocation **wholesale**, replacing whatever auth the resolver derived from `agent.olium.*` (a stale config value from a different auth flow can't accidentally cross-wire onto an override-driven run).
- audit-ts receives `--api-key` / `--oauth-token` / `--oauth-cred-file` directly. The flag value is visible in the live argv for the lifetime of the audit process — see [Operational Caveats](#operational-caveats).
- No staging or env-var injection. The cred file path on `--oauth-cred-file` is read by audit itself as it would for any local invocation.

### Piolium

`pi` doesn't accept auth flags. Vigolium translates the override into env-var injection on the pi subprocess:

| Override | Resolved agent | Env injected on `pi` |
|---|---|---|
| `api_key` | claude | `ANTHROPIC_API_KEY=…` |
| `api_key` | codex | `OPENAI_API_KEY=…` |
| `oauth_token` | claude | `CLAUDE_CODE_OAUTH_TOKEN=…` |
| `oauth_cred_file` | codex | (file staged at `<pi-agent-dir>/auth.json`; no env var) |

For codex `oauth_cred_file`, Vigolium:

1. Acquires an exclusive lock at `<pi-agent-dir>/.vigolium-auth.lock` (returns a clean error on contention, instead of letting two BYOK runs interleave a swap).
2. If `<pi-agent-dir>/auth.json` exists, renames it to `auth.json.vigolium-bak-<run-uuid>`.
3. Copies the supplied cred file into `<pi-agent-dir>/auth.json` (mode `0600`).
4. Runs the audit. `pi`'s codex provider reads `auth.json` from `PI_CODING_AGENT_DIR` exactly as in a standalone install.
5. Removes the staged file, restores the backup (if any), and releases the lock — even when `cmd.Start()` fails or the subprocess crashes.

`<pi-agent-dir>` is the directory Vigolium passes to `pi` as `PI_CODING_AGENT_DIR`. With `$PIOLIUM_HOME=/opt/piolium` (the documented system layout) that's `/opt/piolium/agent`. With a per-user pin (`$PIOLIUM_HOME=~/.piolium`) it's `~/.piolium/agent`. The user-default `~/.piolium/` is **not** auto-probed — see [piolium-audit.md](piolium-audit.md) for the resolution chain.

### Driver = both

`vigolium agent audit --driver both` runs audit then piolium under one parent AgenticScan. The same `AuthOverride` is applied to both — audit as flags, piolium as env / staged file — so a single `--api-key` covers the full run.

---

## Validation Rules

Both CLI and REST enforce:

| Rule | Error |
|---|---|
| At most one of `api_key` / `oauth_token` / `oauth_cred_file` may be set. | `auth override: at most one of api-key / oauth-token / oauth-cred-file may be set` |
| `oauth_token` requires the claude side. | `auth override: --oauth-token is only valid for the claude agent (got "codex"); codex uses --oauth-cred-file` |
| CLI: `$VAR` must be set and non-empty. | `<flag>: $VAR is unset or empty` |
| CLI: `@path` must exist and not be empty after trim. | `<flag>: read <path>: …` / `<flag>: <path> is empty` |

Validation runs **before any subprocess is launched**. CLI errors return non-zero exit and a single-line message; REST errors return `400 Bad Request` with the message in the JSON body.

---

## Logging & Redaction

The values supplied via BYOK are sensitive. Vigolium redacts them in logs and the printed cmdline, while the live `cmd.Env` and argv handed to the subprocess always carry the real values.

| Surface | Redaction |
|---|---|
| `injected_env` zap debug log | Values for `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `OPENAI_OAUTH_CRED_PATH`, `GOOGLE_APPLICATION_CREDENTIALS` are replaced with `<redacted>`. |
| Printed cmdline (`starting background audit cmd=…`) | Values following `--api-key`, `--oauth-token`, `--oauth-cred-file` are replaced with `<redacted>`. |
| Session bundle (`runtime.log`, `audit-stream.jsonl`) | Inherits the same redactions because they tee from the streams above. **audit-ts's own logs are not redacted by Vigolium** — if audit prints the key value to its stdout, it will land in `runtime.log` as-is. |
| AgenticScan DB row | Auth fields are not persisted. |

If you grep your logs for a credential and don't find it, that's the redactor working. The literal string `<redacted>` is searchable so you can confirm redaction fired on a given run.

---

## Operational Caveats

- **Process listing leak (CLI audit).** `--api-key sk-…` shows up in `ps` for the lifetime of the audit child. Mitigate with `--api-key '$ANTHROPIC_API_KEY'` or `@/secure/path` so the literal value isn't on the argv. audit doesn't accept pipe-based hand-off today.
- **REST has no `$ENV` / `@path` indirection.** Resolving either against a network-supplied string would let a caller probe the server's process env or filesystem. Use a secrets manager or pre-stage the file (for `oauth_cred_file`) before issuing the request.
- **Concurrent codex+piolium BYOK.** The lock at `<pi-agent-dir>/.vigolium-auth.lock` serializes runs that share the same pi-agent-dir. The second run errors out with a clear message instead of clobbering the first run's `auth.json`. If a vigolium process crashes mid-run the lock and backup file remain — remove the lock manually and check `auth.json.vigolium-bak-<run-uuid>` before re-running.
- **audit's own log surface.** audit-ts is a separate binary and may surface auth values in its NDJSON `result` event or in error messages on stderr. Vigolium redacts only the streams it owns; if you're shipping `runtime.log` off-box, treat it as if it could contain a key until your environment proves otherwise.
- **No on-disk persistence of the override.** The override never lands in `vigolium-configs.yaml`, the AgenticScan DB row, or the session config snapshot. Re-running the same audit later requires re-supplying the BYOK flags / fields.
