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
```

These commands modify the main config file directly. For one-off overrides during a scan, use CLI flags instead.

## Config Sections

### `scanning_strategy`

Controls which scan phases run for each strategy preset.

```yaml
scanning_strategy:
  default_strategy: balanced    # lite | balanced | deep | whitebox
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

  # Phase toggles per strategy:
  balanced:
    discovery: true
    spidering: true
    known_issue_scan: true
    dynamic-assessment: true
    external_harvesting: false
    source_aware: false
```

Available strategies and their default phases:

| Phase | lite | balanced | deep | whitebox |
|---|---|---|---|---|
| external_harvesting | - | - | yes | - |
| discovery | - | yes | yes | yes |
| spidering | - | yes | yes | - |
| known_issue_scan | - | yes | yes | yes |
| dynamic-assessment | yes | yes | yes | yes |
| source_aware | - | - | - | yes |

### `scanning_pace`

Centralized speed control. Common values serve as baselines; per-phase subsections override them.

```yaml
scanning_pace:
  concurrency: 50          # global worker count
  rate_limit: 100          # max requests/sec across all hosts
  max_per_host: 10         # max concurrent requests per host
  max_duration: 2h         # global time cap for a scan phase

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

AI agent integration for agentic scan modes.

```yaml
agent:
  default_agent: claude
  templates_dir: ~/.vigolium/prompts/
  sessions_dir: ~/.vigolium/agent-sessions/
  stream: true                     # real-time output streaming
  mcp_enabled: false               # MCP server passthrough

  # LLM config for JS extension agent API:
  llm:
    provider: anthropic            # anthropic | openai
    model: claude-sonnet-4-20250514
    api_key: ""                    # inline key (prefer api_key_env)
    api_key_env: ""                # env var name (default: ANTHROPIC_API_KEY or OPENAI_API_KEY)
    base_url: ""                   # custom endpoint for OpenAI-compatible providers
    max_tokens: 4096
    temperature: 0.0
    cache_size: 256                # LRU entries (0 = disabled)
    cache_ttl: 300                 # seconds

  # Warm session pooling for subprocess reuse:
  warm_session:
    enable: false
    idle_timeout: 300              # seconds
    max_sessions: 2

  # Swarm terminal capabilities:
  swarm_terminal:
    slash_commands: []
    custom_agents: []
    max_commands: 50

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

  # Agent backends (built-in defaults shown):
  backends:
    claude:
      command: claude
      description: "Anthropic Claude Code (SDK protocol)"
      protocol: sdk
    codex:
      command: codex
      protocol: codex-sdk
    opencode:
      command: opencode
      protocol: opencode-sdk
```

Valid protocols: `pipe`, `sdk`, `codex-sdk`, `opencode-sdk`.

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
```

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

### `source_aware`

Source code integration for whitebox scanning (SAST, route extraction).

```yaml
source_aware:
  storage_path: ~/.vigolium/source-aware/
  clone_depth: 1

  ast_grep:
    enabled: true
    rules_dir: ~/.vigolium/sast-rules/astgrep/
    timeout: 5m

  third_party_integration:
    enabled: true
    timeout: 10m
    tools:
      semgrep:
        enabled: true
        command: semgrep
        args: ["scan", "--sarif", "--quiet", "--sarif-output={{output}}"]
      osv-scanner:
        enabled: true
        command: osv-scanner
        args: ["scan", "--format", "sarif", "--output={{output}}"]
      codeql:
        enabled: false
        command: codeql
        language: auto

  agent_sast:
    enabled: false
    prompt_templates: [security-code-review]
    custom_prompts: []
    agent: ""                      # backend override (empty = default_agent)
    timeout: 15m
```

### `notify`

Real-time finding notifications via Telegram or Discord.

```yaml
notify:
  enabled: false
  severities: [high, critical, medium]

  telegram:
    bot_token: ""
    chat_id: ""

  discord:
    webhook_url: ""
```

## Scanning Profiles

Scanning profiles are YAML files stored in `~/.vigolium/profiles/` that override subsets of the main config. They can tune any combination of: `scanning_strategy`, `scanning_pace`, `discovery`, `spidering`, `known_issue_scan`, `dynamic-assessment`, `external_harvester`, `mutation_strategy`, and `scope`.

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
