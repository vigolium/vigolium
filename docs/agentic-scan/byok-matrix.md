# BYOK reference matrix

Bring-Your-Own-Key (BYOK) lets an operator supply per-run LLM credentials so a
server-wide `agent.olium.*` config doesn't have to hold every tenant's key.
This page is the canonical map: which endpoints accept which fields, which
flag/header surfaces map to which provider, and what gets redacted where.

For end-to-end walkthroughs of the audit-driver BYOK path, see
[`audit-byok.md`](./audit-byok.md).

## Endpoint × field matrix

All agent endpoints accept the BYOK fields described in the schema section.
"Driver" tells you whether the credentials land in a subprocess (archon /
piolium) or in the in-process olium engine.

| Endpoint                          | Driver               | BYOK body fields | Bearer header | Per-driver overrides |
| --------------------------------- | -------------------- | ---------------- | ------------- | -------------------- |
| `POST /api/agent/run/query`       | in-process olium     | yes              | no            | n/a                  |
| `POST /api/agent/run/autopilot`   | in-process olium     | yes              | no            | n/a                  |
| `POST /api/agent/run/swarm`       | in-process olium     | yes              | no            | n/a                  |
| `POST /api/agent/run/archon`      | subprocess (archon)  | yes              | no            | n/a                  |
| `POST /api/agent/run/audit`       | subprocess (archon + piolium) | yes     | no            | `archon_auth`, `piolium_auth` |
| `POST /api/agent/chat/completions`| in-process olium     | yes              | yes (no-auth mode only) | n/a                  |

The autopilot endpoint can also kick off a background archon-audit when a
source path is provided; that background audit inherits the same BYOK
overlay as the in-process operator agent.

## Schema

```jsonc
{
  // exactly one of the four must be non-empty
  "api_key":         "sk-ant-…  or  sk-…",
  "oauth_token":     "sk-ant-oat01-…",            // Claude Code OAuth, claude-only
  "oauth_cred_file": "/var/lib/.../codex.json",   // DEPRECATED — see oauth_cred_json
  "oauth_cred_json": "{\"tokens\":{\"id_token\":…,\"access_token\":…,\"refresh_token\":…,\"account_id\":…}, \"auth_mode\":\"codex\"}",

  // Audit endpoint only — override the inherited fields per driver. Each
  // sub-object accepts the same four fields above. Only valid with
  // driver=both; single-driver runs reject these.
  "archon_auth":     { "api_key": "..." },
  "piolium_auth":    { "oauth_cred_json": "..." }
}
```

## Provider auto-detection

The in-process olium path picks a provider from the credential shape so the
caller does not have to send a `provider` field:

| Field set       | Pattern                | Resolved provider          |
| --------------- | ---------------------- | -------------------------- |
| `oauth_cred_json` / `oauth_cred_file` | (Codex JSON)         | `openai-codex-oauth` (`OAuthCredPath`) |
| `oauth_token`   | `sk-ant-oat01-…`       | `anthropic-oauth` (`OAuthToken`)       |
| `api_key`       | `sk-ant-*`             | `anthropic-api-key` (`LLMAPIKey`)      |
| `api_key`       | anything else          | `openai-api-key` (`LLMAPIKey`)         |

The provider switch is validated against the key shape:

- `openai-api-key` rejects keys starting with `sk-ant-` (Anthropic shape).
- `anthropic-api-key` rejects keys starting with `sk-ant-oat` (OAuth shape).
- `anthropic-oauth` rejects keys starting with `sk-ant-api` (API-key shape).
- Any field still containing an unexpanded `${VAR}` after YAML load fails
  fast with a "set the env var in your shell" hint.

The subprocess (archon / piolium) path uses the explicit `agent` field
(`claude` / `codex`) instead and validates that `oauth_token` is only used
on the claude side.

## Indirection: CLI vs REST

| Source           | `$ENV` expansion  | `@/path` file read |
| ---------------- | ----------------- | ------------------ |
| YAML (load time) | yes (`ExpandEnvVars`) | no               |
| CLI flag         | yes (CLI-only)    | yes (CLI-only)     |
| REST body field  | **literal only**  | **literal only**   |

REST stays literal-only by design — resolving `$ENV` or filesystem paths on
behalf of a network caller would let an unauthenticated client probe the
server's environment or filesystem.

## Header BYOK (chat/completions only)

`POST /api/agent/chat/completions` honors an `Authorization: Bearer <key>`
header — what every OpenAI SDK sends. The bearer is promoted into
`api_key` and routed through the same overlay path, but **only** when:

1. The server is running with `--no-auth`. With auth on, the bearer is the
   operator's user token, not a BYOK key.
2. The request body does not already carry BYOK fields. Body fields win.

For all other endpoints, BYOK must come from the JSON body.

## Per-driver overrides (`driver=both` only)

`POST /api/agent/run/audit` with `driver: "both"` accepts `archon_auth`
and `piolium_auth` sub-objects that override the top-level BYOK for one
driver only. Use this to run a single audit with two tenants' credentials —
e.g. one operator's Claude OAuth on the archon side and another operator's
Codex auth.json on the piolium side. Each sub-override is staged and
cleaned up independently.

Single-driver runs (`driver=archon` / `driver=piolium`) reject
`archon_auth` / `piolium_auth` with a 400 — pass the top-level fields
instead.

## Lifecycle and on-disk staging

| Field            | Where it lives at runtime                                | Cleanup |
| ---------------- | -------------------------------------------------------- | ------- |
| `api_key`        | provider struct field (wrapped in formatter-safe `secret`) | engine teardown |
| `oauth_token`    | provider struct field (wrapped in formatter-safe `secret`) | engine teardown |
| `oauth_cred_file` | argv flag (archon) / staged file (piolium) | per-run cleanup |
| `oauth_cred_json` | 0600 file under `<sessions_dir>/byok-creds/byok-<uuid>.json` | per-run cleanup |

The piolium codex BYOK additionally swaps `<pi-agent-dir>/auth.json` and
its lock file (`.vigolium-auth.lock`). Archon-ts does the same dance with
`.archon-auth.lock`. Both lock files carry a JSON breadcrumb
(`run`, `pid`, `started_at`) so an operator can attribute a stale lock.

If vigolium SIGKILLs mid-run, the next audit boot runs a sweep:

- Go side (`SweepStalePioliumAuth`) — restores the matching
  `auth.json.vigolium-bak-<uuid>` if the holder PID is dead.
- TS side (`sweepStaleAuthBackups`) — same for `.archon-backup-<uuid>`.

Operators see one log line per swept entry.

## Redaction

The redaction stack runs at five layers — all of them must miss for a
secret to leak:

| Layer                          | What it scrubs                                                                 |
| ------------------------------ | ------------------------------------------------------------------------------ |
| `DebugRequestMiddleware`       | JSON body fields (`api_key`, `oauth_token`, `oauth_cred_file`, `oauth_cred_json`, `llm_api_key`, `password`, `secret`, env-shaped keys); sensitive headers (`Authorization`, `Cookie`, `X-API-Key`, `X-Anthropic-Key`, `X-OpenAI-Key`, `Proxy-Authorization`) |
| `pkg/agent/audit_redact.go`    | argv tokens following `--api-key` / `--oauth-token` / `--oauth-cred-file`; env vars by name (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, etc.) |
| `pkg/olium/provider/debug.go`  | `VIGOLIUM_OLIUM_DEBUG=1` stderr dumps — regex-scrubs `sk-ant-…`, `sk-…`, `Bearer …`, `AIza…`, `gh[pousr]_…` |
| `pkg/olium/provider/secret`    | `%v`, `%+v`, `%#v`, `%s`, `%q` on a `Secret`-wrapped key prints `<redacted>` |
| `internal/config/flatconfig.go`| `vigolium config ls` masks entries whose key matches a sensitive suffix (`api_key`, `bot_token`, `webhook_url`, `password`) or contains a sensitive word (`key`, `token`, `secret`, `authorization`); also masks `*.webhook.*.url` paths to catch tokenized hook URLs |

Webhook URLs are additionally scrubbed in `*url.Error` chains via
`redactURL` so a tokenized Slack/Discord/Teams URL doesn't leak through
a wrapped network error.

## Quotas

Heavy agent runs (autopilot, swarm, audit) are gated by two semaphores:

- `agent_heavy_max` (default 5) — cluster-wide.
- `agent_heavy_per_project` (default 2) — per project. Set negative to
  disable; setting 0 falls back to the default.

A request that exceeds the per-project cap fails fast with a 429
(`project X already has N heavy agent runs in flight`). A request that
passes the per-project gate but blocks on the cluster gate uses the
configured `agent_queue_timeout` before its own 429.

Light runs (query, chat/completions) share `agent_light_max` (default 10)
with no per-project cap — they're cheap and short-lived.

## Examples

Inline Codex JSON for one audit run:

```bash
curl -X POST $HOST/api/agent/run/audit \
  -H 'X-Project-UUID: 11111111-1111-1111-1111-111111111111' \
  -H 'Authorization: Bearer $SERVER_TOKEN' \
  -d @- <<'EOF'
{
  "source":  "git@github.com:acme/widget.git",
  "agent":   "codex",
  "oauth_cred_json": "{\"auth_mode\":\"codex\",\"tokens\":{\"id_token\":\"...\",\"access_token\":\"...\",\"refresh_token\":\"...\",\"account_id\":\"...\"}}"
}
EOF
```

Two-tenant `driver=both`:

```json
{
  "source": "/repo",
  "driver": "both",
  "archon_auth":  { "oauth_token":    "sk-ant-oat01-tenant-A-..." },
  "piolium_auth": { "oauth_cred_json": "{\"tokens\":{...tenant B...}}" }
}
```

OpenAI-SDK-style chat completion in no-auth mode:

```bash
curl -X POST $HOST/api/agent/chat/completions \
  -H 'Authorization: Bearer sk-ant-api03-...' \
  -d '{"model":"any","messages":[{"role":"user","content":"hi"}]}'
```
