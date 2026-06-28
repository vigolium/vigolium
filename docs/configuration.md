# Configuration Reference

Vigolium uses a layered configuration system that merges settings from multiple sources. This document covers the config file format, environment variables, and every configurable section.

## Config File Location

The main config file is `~/.vigolium/vigolium-configs.yaml`. It is created automatically on first run with sensible defaults.

Vigolium searches for configuration in this order:

1. Path specified via the `--config` flag (error if not found)
2. `~/.vigolium/vigolium-configs.yaml`
3. `./vigolium-configs.yaml` (current working directory)

If no config file is found, built-in defaults are used.

## Config Precedence

Settings are resolved from highest to lowest precedence:

1. **CLI flags** -- e.g. `--concurrency 100`, `--rate-limit 50`
2. **Environment variables** -- e.g. `VIGOLIUM_API_KEY`, `VIGOLIUM_PROJECT`
3. **Scanning profile** -- loaded via `--scanning-profile <name>` (from `~/.vigolium/profiles/`)
4. **Project-level config** -- per-project overlay at `~/.vigolium/projects/<uuid>/config.yaml`
5. **Main config file** -- `~/.vigolium/vigolium-configs.yaml`
6. **Built-in defaults** -- hardcoded in the Go source

Higher-precedence sources override lower ones. Within the config file, environment variables can be referenced using `${VAR}` or `$VAR` syntax and are expanded at load time.

## Environment Variables

| Variable | Purpose |
|---|---|
| `VIGOLIUM_API_KEY` | API key for the REST server and ingestor client authentication |
| `VIGOLIUM_PROJECT` | Default project UUID for CLI operations (equivalent to `--project`) |
| `VIGOLIUM_PROXY` | HTTP/SOCKS proxy URL, used when `--proxy` is not set |
| `VIGOLIUM_HOME` | Base directory for Vigolium data (used by the installer; defaults to `~/.vigolium`) |
| `VIGOLIUM_DISABLE_UPDATE_CHECK` | Set truthy to disable the periodic "new version available" check entirely |
| `VIGOLIUM_AUTO_UPDATE` | Set truthy to silently run `vigolium update` and re-exec the new binary when a newer release is detected |

### Update check

On startup Vigolium compares the running version against the latest `@vigolium/vigolium` release on the npm registry (cached to at most once per 24 h in `~/.vigolium/update-check.json`). When a newer version exists it prints a one-line notice at the end of the run:

```
▼ A new vigolium version is available: v0.1.41-beta → v0.1.42-beta
  Run `vigolium update` to upgrade.
```

The check is automatically skipped for `--json`, CI (`--ci-output-format`), and non-interactive (piped) output, and for the `version`, `update`, and `init` commands. Set `VIGOLIUM_DISABLE_UPDATE_CHECK=1` to turn it off, or `VIGOLIUM_AUTO_UPDATE=1` to have Vigolium silently update and re-exec the freshly installed binary to continue the current command.

Any environment variable can also be interpolated inside `vigolium-configs.yaml`:

```yaml
database:
  postgres:
    password: ${VIGOLIUM_DB_PASSWORD}
```

## CLI Config Overrides

Use `vigolium config set` to update individual config values using dot-notation keys:

```bash
vigolium config set scanning_pace.concurrency 100
vigolium config set database.driver postgres
vigolium config set notify.enabled true
vigolium config set notify.severities high,critical
vigolium config set server.service_port 8080
vigolium config set scanning_strategy.http.user_agent "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)"
```

These commands modify the main config file directly. For one-off overrides during a scan, use CLI flags instead.

## Config Sections

### `scanning_strategy`

Controls which scan phases run for each strategy preset.

```yaml
scanning_strategy:
  default_strategy: balanced    # lite | balanced | deep
  heuristics_check: basic
  scanning_profile: ""          # name of a profile to auto-load
  profiles_dir: ~/.vigolium/profiles/

  session:
    session_dir: ~/.vigolium/sessions/
    use_in_discovery: true       # apply session headers during discovery/spidering
    compare_enabled: true        # cross-session IDOR/BOLA replay in dynamic-assessment
    reauth_interval: ""          # e.g. "15m" to refresh tokens periodically
    reauth_on_status: []         # e.g. [401, 403]
    validate_url: ""             # URL to GET after login to verify credentials

  http:
    user_agent: ""               # empty = built-in Chrome string; {version} is expanded

  # Phase toggles per strategy:
  balanced:
    discovery: true
    spidering: true
    known_issue_scan: true
    dynamic-assessment: true
    external_harvesting: false
```

Available strategies and their default phases:

| Phase | lite | balanced | deep |
|---|---|---|---|
| external_harvesting | - | - | yes |
| discovery | - | yes | yes |
| spidering | - | yes | yes |
| known_issue_scan | - | yes | yes |
| dynamic-assessment | yes | yes | yes |

**`http.user_agent`** — overrides the `User-Agent` header on every outgoing
scanner request across all HTTP phases (dynamic-assessment, content discovery,
404 fingerprinting, Wayback harvesting). Empty (the default) keeps the built-in
Chrome-like string, which is best for WAF-bypass realism. The literal
`{version}` is replaced with the running binary version, so a pinned identifier
stays correct across upgrades:

```bash
vigolium config set scanning_strategy.http.user_agent "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)"
```

Precedence: an explicit `-H 'User-Agent: ...'` CLI flag still overrides this for
the dynamic-assessment phase. The browser-driven spidering phase (`--spider`)
uses its native Chromium User-Agent and is not affected by this setting.

### `scanning_pace`

Centralized speed control. Common values serve as baselines; per-phase subsections override them.

```yaml
scanning_pace:
  concurrency: 50          # global worker count
  rate_limit: 100          # max requests/sec across all hosts
  max_per_host: 10         # max concurrent requests per host
  max_duration: 2h         # per-phase base duration (each phase scales it by its duration_factor)

  # Per-phase overrides (zero = inherit from common):
  discovery:
    concurrency: 0
    rate_limit: 0
    concurrency_factor: 0  # multiplier on common concurrency
    duration_factor: 0     # multiplier on common max_duration
  spidering:
    duration_factor: 0.15  # e.g. 2h * 0.15 = 18m
  known_issue_scan:
    duration_factor: 3.0
  external_harvester:
    duration_factor: 0.2
  dynamic-assessment:
    duration_factor: 1.0
    parallel_passive: true         # run passive modules in parallel
    feedback_drain_timeout: 500ms  # wait for feedback loop items
```

> **Total scan cap (CLI):** `max_duration` above is only the per-phase base — on its
> own it does not bound total scan time, so back-to-back phases can sum well past it.
> The `--scanning-max-duration` CLI flag additionally caps the **total** wall-clock
> time of the whole scan at the value you pass: the per-phase `duration_factor`s then
> distribute that budget across phases (and remaining phases are skipped once it
> elapses) instead of each phase getting the full value sequentially. A single-phase
> run (e.g. `vigolium run known-issue-scan`) therefore matches the value exactly.

### `discovery`

Content discovery (directory/file brute-forcing).

```yaml
discovery:
  mode: files_and_dirs         # files_and_dirs | files_only | dirs_only
  scope_mode: subdomain        # any | subdomain | exact
  save_response_body: true
  enable_malformed_path_probe: false
  enrich_targets: false        # feed paths from spidering/harvest into discovery

  recursion:
    enabled: true
    max_depth: 5

  wordlists:
    short_file_path: ""        # custom wordlist paths
    long_file_path: ""
    short_dir_path: ""
    long_dir_path: ""
    fuzz_wordlist_path: ""
    use_observed_names: true
    use_observed_paths: true
    use_observed_files: true
    enable_numeric_fuzzing: false

  extensions:
    test_custom: true
    custom_list: []
    test_observed: true
    test_backup_extensions: true
    backup_extensions: []
    test_no_extension: true

  engine:
    case_sensitivity: auto_detect  # auto_detect | sensitive | insensitive
    timeout: 10s                   # per-request timeout (1s-300s)
    custom_headers: {}
    enable_cookie_jar: false
    max_consecutive_errors: 0
    max_consecutive_waf_blocks: 0
    observed_max_items: 4000
    disable_kingfisher: false
```

### `spidering`

Browser-based crawling.

```yaml
spidering:
  max_depth: 0               # 0 = unlimited
  max_states: 0              # 0 = unlimited
  max_duration: 30m
  max_consecutive_fails: 100
  headless: true
  browser_count: 1
  strategy: adaptive         # normal | random | oldest_first | shallow_first | adaptive
  include_response_body: true
  browser_engine: chromium   # chromium | ungoogled | fingerprint
  no_cdp: false              # disable CDP event listener detection
  no_forms: false            # disable automatic form filling
```

### `dynamic-assessment`

Controls which scanner modules run and JavaScript extension settings.

```yaml
dynamic-assessment:
  enabled_modules:
    active_modules: ["all"]    # ["all"] or list of module IDs
    passive_modules: ["all"]

  extensions:
    enabled: false
    extension_dir: ~/.vigolium/extensions/
    custom_dir: []              # additional script paths
    variables: {}               # key-value pairs passed to scripts
    allow_exec: false           # enable exec() and setEnv() in scripts
    sandbox_dir: ""             # base path for file ops (empty = cwd)
    limits:
      timeout: 30s
      max_memory_mb: 128
```

### `scope`

Defines what is in scope for scanning. Exclude rules take priority over include rules.

```yaml
scope:
  applied_on_ingest: false       # enforce scope during ingestion (not just scanning)
  cli_origin_mode: relaxed       # relaxed | all | balanced | strict
  ignore_static_file: true       # skip images, fonts, video, audio, etc.
  max_request_body_size: 1048576     # 1 MB
  max_response_body_size: 524288000  # 500 MB
  body_size_exceeded_action: truncate  # truncate | drop | skip-scan

  host:
    include: ["*"]
    exclude: []
  path:
    include: ["*"]
    exclude: []
  status_code:
    include: ["*"]
    exclude: []
  request_content_type:
    include: ["*"]
    exclude: []
  response_content_type:
    include: ["*"]
    exclude: []
  request_string:
    include: []
    exclude: []
  response_string:
    include: []
    exclude: []
```

### `server`

REST API server settings.

```yaml
server:
  auth_api_key: ""                 # auto-generated if empty; also set via VIGOLIUM_API_KEY
  users_file: ~/.vigolium/users.json
  service_port: 9002
  ingest_proxy_port: 0             # 0 = disabled
  cors_allowed_origins: reflect-origin
  enable_metrics: true
```

### `agent`

AI agent integration. Every agent invocation is routed through the in-process
**olium** runtime — there are no external subprocess backends. Pick a provider
below and olium handles the rest.

```yaml
agent:
  default_agent: olium
  templates_dir: ~/.vigolium/prompts/
  sessions_dir: ~/.vigolium/agent-sessions/
  stream: true                     # real-time output streaming

  # olium — the in-process agent runtime used by query, autopilot, swarm, and
  # the JS extension agent API. Credential fields are provider-specific:
  #   openai-codex-oauth        → oauth_cred_path
  #   anthropic-api-key  → llm_api_key or $ANTHROPIC_API_KEY
  #   openai-api-key     → llm_api_key or $OPENAI_API_KEY
  #   anthropic-cli    → `claude` binary in PATH (no key here)
  olium:
    provider: openai-codex-oauth
    model: gpt-5.5                 # empty = provider default
    oauth_cred_path: ~/.codex/auth.json
    llm_api_key: ""                # supports ${ENV_VAR}
    reasoning_effort: medium       # minimal | low | medium | high | xhigh
    system_prompt: ""              # empty = built-in olium prompt
    max_tokens: 1000000
    temperature: 0.0
    max_turns: 32
    cache_size: 1024               # 0 disables

  # Deprecated / ignored: the JS extension agent API (vigolium.agent.*) now
  # dispatches through the olium engine configured above (agent.olium).
  # This `llm:` block is retained only for backward compatibility.
  llm:
    provider: anthropic            # anthropic | openai
    model: claude-sonnet-4-6
    api_key: ""                    # inline key (prefer api_key_env)
    api_key_env: ""                # env var name (default: ANTHROPIC_API_KEY or OPENAI_API_KEY)
    base_url: ""                   # custom endpoint for OpenAI-compatible providers
    max_tokens: 4096
    temperature: 0.0
    cache_size: 256                # LRU entries (0 = disabled)
    cache_ttl: 300                 # seconds

  # Context enrichment limits:
  context_limits:
    max_findings: 50
    max_endpoints: 100
    max_high_risk: 20
    min_risk_score: 50

  # Autopilot guardrails:
  guardrails:
    log_commands: false
    max_turns: 0                   # 0 = auto (MaxCommands * 3)
    disallowed_tools: []
```

Override the provider per run with `--provider openai-codex-oauth | anthropic-api-key | openai-api-key | anthropic-cli`
(autopilot) or via `agent.olium.provider` in config. Model overrides use `--model`
on `agent autopilot` and `agent olium`.

### `database`

Storage backend. SQLite is the default; PostgreSQL is supported for multi-user deployments.

```yaml
database:
  enabled: true
  driver: sqlite                   # sqlite | postgres

  sqlite:
    path: ~/.vigolium/database-vgnm.sqlite
    busy_timeout: 15000
    journal_mode: WAL              # DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
    synchronous: NORMAL            # OFF | NORMAL | FULL | EXTRA
    cache_size: 10000

  postgres:
    host: localhost
    port: 5432
    user: vigolium
    password: ""
    database: vigolium
    sslmode: disable
    max_open_conns: 25
    max_idle_conns: 5
    conn_max_lifetime: 5m
```

### `known_issue_scan`

Known-issue scanning powered by the Nuclei template engine.

```yaml
known_issue_scan:
  tags: []                         # nuclei template tags (empty = all)
  exclude_tags: [dos]
  severities: []                   # filter: critical, high, medium, low, info
  templates_dir: ""                # custom templates path
  enrich_targets: true             # feed discovered paths into known-issue scan
  severity_overrides:              # remap recorded severity by template ID (case-insensitive)
    config-json-exposure-fuzz: medium
```

> **Right-sizing template severities:** `severity_overrides` remaps the severity a
> finding is recorded with, keyed by nuclei template ID, applied before output and
> persistence so the stored finding, console output, and severity counts all agree.
> Use it for noisy or context-dependent templates (an exposed `config.json` often
> ships only public base URLs / feature flags) instead of forking the upstream
> template, which reverts on `nuclei -update-templates`. Set an entry back to the
> template's own severity to undo a default remap.

> **Single-phase runs sweep all severities:** the balanced default narrows
> `severities` to `critical,high`. When known-issue-scan is the **only** phase
> requested (`vigolium run known-issue-scan` or `--only known-issue-scan`), Vigolium
> treats it as a focused full scan and widens `severities` to all levels for that
> run, printing a one-line notice. Pass `--known-issue-scan-severities` to override.

### `mutation_strategy`

Controls how parameter values are mutated during active scanning.

```yaml
mutation_strategy:
  default_modes: [append]

  value_aware:
    enabled: true
    max_per_intent: 5
    default_intents: [neighbor, boundary, escalation]
    enum_mappings: {}              # custom enum escalation pairs
    param_synonyms: {}             # custom param name synonyms

  field_type_defaults:
    email: ["test@example.com", "user@test.org"]
    uuid: ["550e8400-e29b-41d4-a716-446655440000"]
    integer: ["1", "100", "999"]
    # ... (all standard types have built-in defaults)
```

### `external_harvester`

Pre-scan intelligence gathering from public data sources.

```yaml
external_harvester:
  sources: [wayback, commoncrawl, alienvault]
  # Additional sources: urlscan, virustotal (require API keys)

  api_keys:
    urlscan: ""
    virustotal: ""
```

### `oast`

Out-of-Band Application Security Testing via interactsh callbacks.

```yaml
oast:
  enabled: true
  server_url: oast.pro
  token: ""                        # optional auth token
  poll_interval: 5                 # seconds
  grace_period: 10                 # seconds after scan for late callbacks
  oast_url: ""                     # fixed callback URL (empty = auto-generate)
  blind_xss_src: ""                # JS script src for blind XSS payloads
  enabled_blind_xss: false
```

### `notify`

Vigolium ships three notification channels:

| Channel  | Lifecycle                | Severity-filtered? | Best for |
|----------|--------------------------|--------------------|----------|
| telegram | Per-finding              | Yes                | Live alerts on critical/high findings |
| discord  | Per-finding              | Yes                | Live alerts on critical/high findings |
| webhook  | One POST per scan        | No                 | Programmatic integrations, CI/CD, dashboards |

The **`provider`** field picks which channel is active:

| `provider` value | Effect |
|------------------|--------|
| `webhook`        | Only the scan-completion webhook fires |
| `telegram`       | Only per-finding telegram messages fire |
| `discord`        | Only per-finding discord messages fire |
| `""` (empty)     | All configured channels fire (legacy default) |

```yaml
notify:
  enabled: false
  provider: ""        # webhook | telegram | discord | "" for all
  severities: [high, critical, medium]

  telegram:
    bot_token: ""
    chat_id: ""

  discord:
    webhook_url: ""

  webhook:
    url: ""
    authorization: ""
    timeout_sec: 10
```

#### Webhook on scan completion

Fires a single `POST` once when a native or agentic scan reaches a terminal
state (`completed` or `failed`). One request per scan, JSON body, retried up
to 5 times on 5xx and network errors with exponential backoff (1s, 2s, 4s,
8s, 16s). 4xx responses are not retried. Delivery is fire-and-forget — the
scan does not block waiting for the response.

The webhook is best configured **per project** so each project can post to
its own endpoint. Set it via project config overlay:

```bash
# scope the value to the active project
vigolium project config set notify.enabled true
vigolium project config set notify.provider webhook
vigolium project config set notify.webhook.url "https://my-endpoint.example/scan-complete"
vigolium project config set notify.webhook.authorization "Bearer ${MY_WEBHOOK_TOKEN}"
```

Or edit `~/.vigolium/projects/<project-uuid>/config.yaml` directly:

```yaml
notify:
  enabled: true
  provider: webhook
  webhook:
    url: https://my-endpoint.example/scan-complete
    authorization: "Bearer ${MY_WEBHOOK_TOKEN}"
    timeout_sec: 10
```

**Headers:** `Content-Type: application/json` and (when set)
`Authorization: <raw value from config>` — vigolium passes the value through
verbatim, so any scheme works (Bearer, Basic, custom).

**Payload (`application/json`):**

```json
{
  "event": "scan.completed",
  "project_uuid": "8f2a...",
  "scan_uuid": "ab12...",
  "scan_type": "native",
  "target": "https://example.com",
  "status": "completed",
  "started_at": "2026-05-10T10:00:00Z",
  "finished_at": "2026-05-10T10:15:30Z",
  "findings": {
    "total": 12,
    "by_severity": { "critical": 1, "high": 3, "medium": 5, "low": 3, "info": 0 }
  },
  "result_url": "gs://8f2a.../native-scans/ab12.../results.tar.gz"
}
```

Field notes:
- `event` is always `"scan.completed"`. The `status` field distinguishes
  successful from failed runs.
- `scan_type` is `"native"` for module-driven scans; for agentic scans it is
  the run mode (`autopilot`, `swarm`, `audit`, `piolium`, `audit`,
  `query`).
- `result_url` is the [storage](storage.md) `gs://` URL for the result
  bundle. Empty when storage is disabled or the run did not request
  `--upload-results`.

## Scanning Profiles

Scanning profiles are YAML files stored in `~/.vigolium/profiles/` that override subsets of the main config. They can tune any combination of: `scanning_strategy`, `scanning_pace`, `discovery`, `spidering`, `known_issue_scan`, `dynamic-assessment`, `external_harvester`, `mutation_strategy`, `scope`, and `agent`.

Apply a profile with:

```bash
vigolium scan --scanning-profile aggressive
```

This loads `~/.vigolium/profiles/aggressive.yaml` and overlays it onto the active config. Only non-zero fields in the profile override the base config; unspecified fields are left unchanged.

Built-in profiles are bundled in `public/presets/profiles/`. See [native-scan/scanning-modes-overview.md](native-scan/scanning-modes-overview.md) for details.

## Project-Level Config

Each project can have its own config overlay at `~/.vigolium/projects/<uuid>/config.yaml`. This uses the same format as scanning profiles and is automatically applied when the project is active.

Manage project configs with:

```bash
vigolium project config set scanning_pace.concurrency 200
vigolium project config show
```

See [projects.md](projects.md) for full project management documentation.
