# Complete Flag Index

Alphabetical index of all vigolium CLI flags across all commands.

## Table of Contents

- [Global Flags (all commands)](#global-flags)
- [Scan Flags](#scan-flags)
- [Scan-URL Flags](#scan-url-flags)
- [Scan-Request Flags](#scan-request-flags)
- [Server Flags](#server-flags)
- [Ingest Flags](#ingest-flags)
- [Agent Flags](#agent-flags)
- [Agent Query Flags](#agent-query-flags)
- [Agent Autopilot Flags](#agent-autopilot-flags)
- [Agent Swarm Flags](#agent-swarm-flags)
- [Agent Olium Flags](#agent-olium-flags)
- [Agent Piolium Flags](#agent-piolium-flags)
- [Agent Audit Flags](#agent-audit-flags)
- [Agent Session Flags](#agent-session-flags)
- [Olium Provider Override Flags (shared)](#olium-provider-override-flags-shared)
- [Log Flags](#log-flags)
- [Import Flags](#import-flags)
- [Finding Flags](#finding-flags)
- [Traffic Flags](#traffic-flags)
- [Replay Flags](#replay-flags)
- [DB Flags](#db-flags)
- [Storage Flags](#storage-flags)
- [Export Flags](#export-flags)
- [Module Flags](#module-flags)
- [Extensions Flags](#extensions-flags)
- [JS Flags](#js-flags)
- [Source Add Flags](#source-add-flags)

---

## Global Flags

Persistent flags available on every command.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--concurrency` | `-c` | int | `50` | Concurrent scan workers |
| `--config` | — | string | `~/.vigolium/vigolium-configs.yaml` | Config file path |
| `--db` | — | string | `~/.vigolium/database-vgnm.sqlite` | SQLite database path |
| `--debug` | — | bool | `false` | Dump raw HTTP request and response traffic |
| `--disable-fetch-response` | — | bool | `false` | Store requests without fetching responses during ingestion |
| `--dump-traffic` | — | bool | `false` | Print every HTTP pair to stderr |
| `--ext` | — | []string | — | Load JavaScript extension script (repeatable) |
| `--ext-dir` | — | string | — | Override extension scripts directory |
| `--force` | `-F` | bool | `false` | Skip confirmation prompts |
| `--format` | — | string | `console` | Output format (comma-separated for multiple): console, jsonl, html, `sqlite` (needs `-S`), `fs` (flat traffic/finding tree) |
| `--full-example` | — | bool | `false` | Show full example commands |
| `--heuristics-check` | — | string | `basic` | Pre-scan heuristics level: none, basic, advanced |
| `--input` | `-i` | string | `-` | Input file path or spec (use - for stdin) |
| `--input-mode` | `-I` | string | `urls` | Input format: urls, openapi, swagger, burp, curl, nuclei, har |
| `--input-read-timeout` | — | duration | `3m` | Timeout for reading input |
| `--json` | `-j` | bool | `false` | On `scan`: JSONL findings. On `finding`/`traffic`/`db`: a single compact, token-aware agent JSON object (bodies preview-capped, findings get a `response_evidence` snippet) |
| `--soft-fail` | — | bool | `false` | Always exit 0, even when a command fails (error still printed to stderr); overrides `--fail-on` |
| `--ci-output-format` | — | bool | `false` | CI-friendly output: JSONL findings only, no color, no banners |
| `--list-input-mode` | — | bool | `false` | List supported input modes |
| `--list-modules` | `-M` | bool | `false` | List scanner modules |
| `--log-file` | — | string | — | Write logs to file (JSON format) |
| `--max-host-error` | — | int | `30` | Skip host after N consecutive errors |
| `--max-per-host` | — | int | `30` | Max concurrent requests per host |
| `--max-findings-per-module` | — | int | `10` | Stop reporting after N findings per module (0 = unlimited) |
| `--intensity` | — | string | — | Scan intensity preset: `quick`, `balanced`, or `deep` (maps to scanning profile + strategy) |
| `--full-native-scan-on-receive` | — | bool | `false` | Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records |
| `--module-tag` | — | []string | — | Filter modules by tag (OR condition, repeatable) |
| `--modules` | `-m` | []string | `all` | Scanner modules to enable |
| `--no-clustering` | — | bool | `false` | Disable deduplication of identical concurrent HTTP requests |
| `--only` | — | string | — | Run only this phase |
| `--project-id` | — | string | — | Project UUID to scope all operations |
| `--project-name` | — | string | — | Project name to scope all operations (must match exactly one) |
| `--proxy` | — | string | — | Route all requests through this proxy (HTTP/SOCKS5 URL) |
| `--rate-limit` | `-r` | int | `100` | Maximum HTTP requests per second |
| `--scan-id` | — | string | — | Scan session label |
| `--scan-on-receive` | `-S` | bool | `false` | Continuously scan new HTTP records as they arrive in the database |
| `--scanning-max-duration` | — | duration | `0` | Maximum total scan duration (overrides config, e.g. 1h, 30m) |
| `--scanning-profile` | — | string | — | Scanning profile name or YAML file path |
| `--scope-origin` | — | string | — | Host scope strictness: all, relaxed, balanced, strict |
| `--silent` | — | bool | `false` | Suppress output except findings |
| `--skip` | — | []string | — | Skip phases |
| `--skip-heuristics` | — | bool | `false` | Disable pre-scan heuristics (equivalent to --heuristics-check=none) |
| `--source` | — | string | — | Source code path |
| `--source-url` | — | string | — | Git URL to clone for source-aware scanning |
| `--spec-default` | — | string | `1` | Fallback value for required OpenAPI parameters that lack examples |
| `--spec-header` | — | []string | — | Add HTTP header to OpenAPI-generated requests (repeatable) |
| `--spec-url` | — | bool | `false` | Use base URLs from the OpenAPI spec's servers field |
| `--spec-var` | — | []string | — | Set OpenAPI parameter value as key=value (repeatable) |
| `--strategy` | — | string | — | Scanning strategy preset |
| `--target` | `-t` | []string | — | Target URL (repeatable) |
| `--target-file` | `-T` | string | — | File containing target URLs (one per line) |
| `--timeout` | — | duration | `15s` | HTTP request timeout |
| `--verbose` | `-v` | bool | `false` | Verbose logging |
| `--watch` | — | string | — | Re-run on interval (e.g. 10s, 1m, 5m) |
| `--width` | — | int | `70` | Max column width for tables |

---

## Scan Flags

Flags specific to `vigolium scan` and `vigolium run`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--advanced-options` | `-a` | stringToString | — | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--auth-file` | — | strings | — | Path to auth file (YAML/JSON, single session or `sessions:` bundle), or bare name resolved against session_dir. Repeatable. |
| `--auth` | — | strings | — | Inline session in `name:Header:value` format. Repeatable. |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine |
| `--browsers` | `-b` | int | `1` | Number of parallel browser instances for spidering |
| `--discover` | — | bool | `false` | Enable content discovery phase before scanning |
| `--discover-max-time` | — | duration | `1h` | Discovery timeout per target |
| `--external-harvest` | — | bool | `false` | Enable external intelligence gathering phase (Wayback, CT logs, etc.) |
| `--fail-on` | — | string | — | Exit non-zero when a finding at/above this severity is present (`info`,`suspect`,`low`,`medium`,`high`,`critical`); output written first, `--soft-fail` overrides, per-child under `-P` |
| `--header` | `-H` | []string | — | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token') |
| `--headless` | — | bool | `true` | Headless browser mode |
| `--include-response` | — | bool | `false` | Include full HTTP response body in output |
| `--known-issue-scan-exclude-tags` | — | []string | — | Nuclei template tags to exclude (comma-separated) |
| `--known-issue-scan-severities` | — | []string | — | Filter Nuclei templates by severity (critical,high,medium,low,info) |
| `--known-issue-scan-tags` | — | []string | — | Nuclei template tags to include (comma-separated) |
| `--known-issue-scan-templates-dir` | — | string | — | Custom Nuclei templates directory |
| `--no-cdp` | — | bool | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-forms` | — | bool | `false` | Disable automatic form detection and filling during spidering |
| `--oast-url` | — | string | — | Fixed out-of-band callback URL (overrides auto-generated interactsh URL) |
| `--omit-response` | — | bool | `false` | Omit raw HTTP request/response bytes from the output file (keeps metadata, smaller files) |
| `--output` | `-o` | string | — | Output file path |
| `--required-only` | — | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--retries` | — | int | `1` | Number of retry attempts for failed requests |
| `--rule` | — | string | — | Filter SAST rules by fuzzy name match (e.g. 'gin', 'route') |
| `--sast-adhoc` | — | string | — | Local path or git URL for ad-hoc SAST scan (auto-detected, results not saved to database) |
| `--skip-format-validation` | — | bool | `false` | Skip validation of input file format |
| `--spider` | — | bool | `false` | Enable browser-based spidering phase before scanning |
| `--spider-max-time` | — | duration | `30m` | Spidering timeout |
| `--split-by-host` | — | bool | `false` | In stateless multi-target mode (`-S -T file`), write a separate per-host output file (`base-<host>.<ext>`); required for `-P > 1` fan-out; no-op for `--format fs` |
| `--stateless` | — | bool | `false` | Use a temporary database, export results to --output, then discard |
| `--stats` | — | bool | `false` | Show live progress stats during scanning |
| `--stream` | — | bool | `false` | Process targets as a stream without buffering or deduplication |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |
| `--fuzz-wordlist` | — | string | — | Custom fuzz wordlist path (enables fuzzing during discovery) |
| `--no-prefix-breaker` | — | bool | `false` | Disable per-prefix circuit breaker that stops trap-directory recursion |

---

## Scan-URL Flags

Flags specific to `vigolium scan-url`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--body` | — | string | — | Request body |
| `--discover` | — | bool | `false` | Run content discovery before scanning |
| `--external-harvest` | — | bool | `false` | Run external intelligence harvesting before scanning |
| `--fail-on` | — | string | — | Exit non-zero when a finding at/above this severity is present (`info`,`suspect`,`low`,`medium`,`high`,`critical`); `--soft-fail` overrides |
| `--header` | `-H` | []string | — | Custom header (repeatable) |
| `--known-issue-scan` | — | bool | `false` | Run known issue scan (Nuclei/Kingfisher) |
| `--method` | — | string | `GET` | HTTP method |
| `--no-insertion-points` | — | bool | `false` | Skip insertion point testing |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--spider` | — | bool | `false` | Run browser-based spidering before scanning |

---

## Scan-Request Flags

Flags specific to `vigolium scan-request`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--discover` | — | bool | `false` | Run content discovery before scanning |
| `--external-harvest` | — | bool | `false` | Run external intelligence harvesting before scanning |
| `--fail-on` | — | string | — | Exit non-zero when a finding at/above this severity is present (`info`,`suspect`,`low`,`medium`,`high`,`critical`); `--soft-fail` overrides |
| `--input` | `-i` | string | `-` | Input file or - for stdin |
| `--known-issue-scan` | — | bool | `false` | Run known issue scan |
| `--no-insertion-points` | — | bool | `false` | Skip insertion point testing |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--spider` | — | bool | `false` | Run browser-based spidering before scanning |
| `--target` | — | string | — | Override target URL (scheme://host) |

---

## Server Flags

Flags specific to `vigolium server`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--alternative-ingest-key` | — | []string | — | Additional API key for ingestion endpoints (repeatable) |
| `--catchup-threads` | — | int | `4` | Workers for background scanning of unscanned records |
| `--disable-catchup` | — | bool | `false` | Disable automatic background scanning of unscanned records |
| `--disable-warm-session` | — | bool | `false` | Disable agent warm session pooling |
| `--host` | — | string | `0.0.0.0` | Bind address for the API server |
| `--ingest-proxy-port` | — | int | `0` | Transparent HTTP proxy port for recording traffic (0 = disabled) |
| `--mem-buffer` | — | int | `10000` | In-memory queue capacity before spilling to disk |
| `--mirror-fs` | — | string | — | Mirror ingested traffic + findings to a live flat file tree under this dir (`<dir>/traffic`, `<dir>/findings`), in addition to the DB (config `server.mirror_fs_path`) |
| `--no-agent` | — | bool | `false` | Disable all agent endpoints and warm session pooling |
| `--no-auth` | `-A` | bool | `false` | Run server without API key authentication |
| `--output` | `-o` | string | — | Write findings to specified output file |
| `--service-port` | — | int | `9002` | Port for the REST API server |
| `--view-only` | — | bool | `false` | Run server in read-only mode (disables scanning, ingestion, agent, and all write endpoints) |

---

## Ingest Flags

Flags specific to `vigolium ingest`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--server` | `-s` | string | — | Remote server URL |

---

## Agent Flags

Flags specific to `vigolium agent` (parent command supports `--list-templates` and `--list-agents` only — all execution requires a subcommand).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--list-agents` | bool | `false` | List agent backends |
| `--list-templates` | bool | `false` | List templates |

---

## Agent Query Flags

Flags specific to `vigolium agent query`. Also accepts the [shared olium provider override flags](#olium-provider-override-flags-shared).

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent-label` | — | string | — | Label recorded on the AgenticScan DB row (deprecated alias `--agent`) |
| `--max-duration` | — | duration | `5m` | Maximum time for agent execution (deprecated alias `--agent-timeout`) |
| `--append` | — | string | — | Append extra text to the rendered prompt |
| `--dry-run` | — | bool | `false` | Print the rendered prompt without executing |
| `--files` | — | []string | — | Specific files to include (relative to `--source`) |
| `--instruction` | — | string | — | Custom instruction to guide the agent |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--output` | — | string | — | Write agent output to this file |
| `--prompt` | `-p` | string | — | Prompt text to send to the agent |
| `--prompt-file` | — | string | — | Path to a prompt template file |
| `--prompt-template` | — | string | — | Prompt template ID |
| `--show-prompt` | — | bool | `false` | Print rendered prompt to stderr before executing |
| `--source` | — | string | — | Path to source code repository |
| `--source-label` | — | string | — | Label for records ingested from agent output |
| `--stdin` | — | bool | `false` | Read prompt from stdin |
| `--upload-results` | — | bool | `false` | Upload session bundle to cloud storage after completion |

---

## Agent Autopilot Flags

Flags specific to `vigolium agent autopilot`. Also accepts a positional natural-language prompt and the [shared olium provider override flags](#olium-provider-override-flags-shared).

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (derived from `--input` if not set) |
| `--input` | — | string | — | Raw input (curl, raw HTTP, Burp XML, URL, base64). Reads from stdin if piped |
| `--record-uuid` | — | string | — | Use an HTTP record from the database as the seed input |
| `--source` | — | string | — | Path to application source code |
| `--files` | — | []string | — | Specific files to include (relative to `--source`) |
| `--focus` | — | string | — | Focus area hint |
| `--focus-routes` | — | []string | — | Protected or browser-focused routes to prioritize after auth |
| `--audit` | — | string | `lite` | vigolium-audit mode run before the operator: `lite` (3-phase), `balanced` (9-phase), `deep` (12-phase), `mock`, or `off`. Default: `lite` when `--source` is set |
| `--piolium` | — | string | — | Piolium audit mode: `lite`, `balanced`, `deep`, `longshot`, etc. Empty triggers auto-pick (piolium when `pi` is installed, else vigolium-audit). Setting `--piolium` explicitly forces piolium and turns `--audit` off |
| `--diff` | — | string | — | Focus on changed code: PR URL, git ref range, or `HEAD~N` |
| `--last-commits` | — | int | `0` | Focus on last N commits (shorthand for `--diff HEAD~N`) |
| `--max-duration` | — | duration | `6h` | Maximum wall-clock duration for the autopilot session |
| `--intensity` | — | string | `balanced` | Scan intensity preset: `quick`, `balanced`, or `deep` (sets max-command budget, audit mode, browser, pre-scan strategy) |
| `--triage` | — | bool | `false` | After the scan completes, run an AI triage pass over the findings (confirm real issues vs false positives) |
| `--no-prescan` | — | bool | `false` | Skip the native pre-scan that seeds http_records before the operator agent (target-only runs; no-op when `--source` is set) |
| `--no-preflight-discovery` | — | bool | `false` | Skip the pre-flight discovery + OpenAPI/Swagger ingestion pass that seeds http_records |
| `--no-post-halt-verify` | — | bool | `false` | Skip the post-halt coverage verification re-entry (operator halts → coverage probe → re-prompt when new routes appear) |
| `--post-halt-gap-threshold` | — | int | `0` | Min new (method, URL) routes the post-halt probe must find before re-entering the agent (0 = built-in default 5) |
| `--plan-file` | — | string | — | Path to a plan file mixing free-text guidance and raw HTTP request(s); owns the instruction + seed input (mutually exclusive with `--input`/`--instruction`/`--instruction-file`) |
| `--instruction` | — | string | — | Custom instruction to guide the agent |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--browser` | — | bool | `false` | Enable agent-browser for browser-based interactions |
| `--headed` | — | bool | `false` | Show the browser window during probes (requires `--browser`; sets `VIGOLIUM_BROWSER_HEADED=1`) |
| `--credentials` | — | string | — | Credentials for auth preflight |
| `--auth-required` | — | bool | `false` | Require auth/session preparation before the autonomous operator starts |
| `--requires-browser` | — | bool | `false` | Require browser-assisted auth/setup instead of HTTP-only preflight |
| `--browser-start-url` | — | string | — | Explicit browser/login start URL for auth preflight |
| `--dry-run` | — | bool | `false` | Render the system prompt without launching the agent |
| `--show-prompt` | — | bool | `false` | Print rendered prompt to stderr before executing |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage after completion |
| `--disable-guardrail` | — | bool | `false` | Skip the prompt-safety classifier on the natural-language prompt |

---

## Agent Swarm Flags

Flags specific to `vigolium agent swarm`. Also accepts a positional natural-language prompt and the [shared olium provider override flags](#olium-provider-override-flags-shared).

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (required when `--source` is used) |
| `--input` | — | string | — | Raw input (curl, raw HTTP, Burp XML, URL) |
| `--record-uuid` | — | []string | — | HTTP record UUID from database (repeatable, or comma-separated) |
| `--all-records` | — | bool | `false` | Use every HTTP record in the active project as input |
| `--records-from` | — | string | — | Filter ingested HTTP records by spec (e.g. `host=example.com,status=200,method=GET,path=/api,since=2026-04-01`) |
| `--source` | — | string | — | Path to application source code |
| `--files` | — | []string | — | Specific source files to include |
| `--vuln-type` | — | string | — | Vulnerability type focus |
| `--focus` | — | string | — | Focus area hint for the agent |
| `--modules` | `-m` | []string | — | Explicit module names to include |
| `--max-iterations` | — | int | `3` | Maximum triage-rescan iterations (alias `--max-rescan-rounds`) |
| `--agent-label` | — | string | — | Label recorded on the AgenticScan DB row (deprecated alias `--agent`) |
| `--dry-run` | — | bool | `false` | Render prompts without executing |
| `--show-prompt` | — | bool | `false` | Print rendered prompts to stderr |
| `--source-analysis-only` | — | bool | `false` | Run only the source analysis phase and exit |
| `--max-duration` | — | duration | `12h` | Maximum swarm duration (0 = unlimited; deprecated alias `--swarm-duration`) |
| `--profile` | — | string | — | Scanning profile to use |
| `--only` | — | string | — | Run only this scanning phase |
| `--skip` | — | []string | — | Skip specific phases |
| `--start-from` | — | string | — | Resume from a specific phase |
| `--instruction` | — | string | — | Custom instruction to guide the agent |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--discover` | — | bool | `false` | Run discovery+spidering before master agent planning |
| `--code-audit` | — | bool | auto | Enable AI security code audit phase (on by default when `--source` is set) |
| `--triage` | — | bool | `false` | Enable AI triage and rescan phases |
| `--with-extensions` | — | bool | `false` | Force the extension agent to run even when the planner picks built-in modules |
| `--batch-concurrency` | — | int | `0` | Max parallel master agent batches (0 = auto) |
| `--max-master-retries` | — | int | `3` | Max master agent retries on parse failure |
| `--sub-agent-concurrency` | — | int | `3` | Max parallel source analysis sub-agents |
| `--max-plan-records` | — | int | `10` | Max records sent to plan agent (0 = no limit) |
| `--master-batch-size` | — | int | `0` | Max records per master agent batch (0 = default 5) |
| `--probe-concurrency` | — | int | `0` | Max parallel probe requests (0 = default 10) |
| `--probe-timeout` | — | duration | `0` | Per-request probe timeout (0 = default 10s) |
| `--max-probe-body` | — | int | `0` | Max response body size in bytes during probing (0 = default 2MB) |
| `--browser` | — | bool | `false` | Enable agent-browser for browser-based auth capture |
| `--browser-auth` | — | bool | `false` | Run browser-based auth phase before discovery (requires `--browser`) |
| `--credentials` | — | string | — | Credentials for browser auth phase |
| `--audit` | — | string | — | Run background vigolium-audit in parallel: `lite` (default if bare), `balanced`, `deep`. Requires `--source` |
| `--piolium` | — | string | — | Run background piolium audit (Pi runtime): `lite`, `balanced`, `deep`, `longshot`, etc. Requires `--source`. Empty triggers auto-pick when `--audit` is also empty (piolium when `pi` is installed, else nothing) |
| `--diff` | — | string | — | Focus on changed code: PR URL, git ref range, or `HEAD~N` |
| `--last-commits` | — | int | `0` | Focus on last N commits |
| `--intensity` | — | string | `balanced` | Scan intensity preset: `quick`, `balanced`, or `deep` |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage |
| `--disable-guardrail` | — | bool | `false` | Skip the prompt-safety classifier on the natural-language prompt |

---

## Agent Olium Flags

Flags specific to `vigolium agent olium` (and the top-level `vigolium olium` / `ol` alias). These are also the canonical names for the [shared olium provider override flags](#olium-provider-override-flags-shared) on every other agent subcommand.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--provider` | — | string | from config | Provider: `openai-codex-oauth` \| `anthropic-api-key` \| `anthropic-oauth` \| `openai-api-key` \| `anthropic-cli` \| `google-vertex` |
| `--model` | — | string | provider default | Model id |
| `--oauth-cred` | — | string | from config | OAuth/SA credential file (openai-codex-oauth: `~/.codex/auth.json`; google-vertex: SA JSON or `$GOOGLE_APPLICATION_CREDENTIALS`) |
| `--oauth-token` | — | string | from config | Claude Code OAuth bearer token (`anthropic-oauth`; falls back to `agent.olium.oauth_token` or `$ANTHROPIC_API_KEY`) |
| `--llm-api-key` | — | string | from config | API key for key-based providers |
| `--claude-bin` | — | string | `claude` | Path to the `claude` binary (anthropic-cli provider) |
| `--gcp-project` | — | string | — | GCP project for `google-vertex` |
| `--gcp-location` | — | string | — | GCP region for `google-vertex` |
| `--system` | — | string | — | Override system prompt |
| `--prompt` | `-p` | string | — | Run one prompt non-interactively and stream to stdout (skips TUI). Pass `-` to read from stdin |
| `--stdin` | — | bool | `false` | Force reading prompt from stdin |

---

## Agent Piolium Flags

Flags specific to `vigolium agent audit --driver=piolium`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--intensity` | — | string | `balanced` | Audit intensity preset: `quick`, `balanced`, `deep`. Explicit `--mode` / `--commit-depth` override |
| `--mode` | — | string | (from intensity) | Audit mode: `lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge`, `diff`, `longshot`, `status`, `smoke` |
| `--source` | — | string | `.` | Local directory, git URL, `gs://<project>/<key>` archive, or local archive |
| `--commit-depth` | — | int | `1` | `git clone --depth` value when `--source` is a git URL (0 = full history) |
| `--no-stream` | — | bool | `false` | Don't echo agent output to the console (still written to `{session}/runtime.log`) |
| `--upload-results` | — | bool | `false` | Upload session bundle to cloud storage after completion |
| `--pi-provider` | — | string | — | Override pi's `defaultProvider` for this run (e.g. `vertex-anthropic`, `google-vertex`) |
| `--pi-model` | — | string | — | Override pi's `defaultModel` for this run (e.g. `claude-opus-4-6`, `gemini-3.1-pro`) |
| `--no-preflight` | — | bool | `false` | Skip the pre-audit pi roundtrip check |
| `--preflight-timeout` | — | duration | `30s` | Pi preflight timeout |
| `--plm-scan-limit` | — | int | `0` | [piolium] Cap commit-history scan to N commits (0 = piolium default) |
| `--plm-scan-since` | — | string | — | [piolium] Cap commit-history scan to a `git --since` window (e.g. `"60 days ago"`) |
| `--plm-phase-retries` | — | int | `0` | [piolium] Per-phase retry count |
| `--plm-command-retries` | — | int | `0` | [piolium] Per-command retry count |
| `--plm-longshot-limit` | — | int | `0` | [piolium] Max files hunted in `longshot` mode |
| `--plm-longshot-timeout` | — | int | `0` | [piolium] Per-file kill timer in `longshot` mode (ms) |
| `--plm-longshot-langs` | — | string | — | [piolium] Longshot language allowlist (comma-separated) |

---

## Agent Audit Flags

Flags specific to `vigolium agent audit` — the unified driver dispatcher that drives the embedded **vigolium-audit** harness and/or **piolium** under one parent AgenticScan. (There is no separate `agent archon` command; the vigolium-audit leg is reached with `--driver=audit`.)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--driver` | — | string | `auto` | Audit driver: `auto` (run audit; fall back to piolium only when the claude/codex CLI is missing), `both` (audit then piolium, unconditional), `audit`, or `piolium` |
| `--intensity` | — | string | `balanced` | Audit intensity preset: `quick` (→ `lite`), `balanced` (→ `balanced`), `deep` (→ chain `deep,confirm`) |
| `--mode` | — | string | (from intensity) | Single mode override. Shared (allowed under `auto`/`both`): `lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge`. Driver-specific (require `--driver=audit\|piolium`): audit = `reinvest`/`refresh`/`mock`/`diff`/`status`, piolium = `longshot`/`smoke`/`diff`/`status` |
| `--modes` | — | string | — | Run a chain of modes back-to-back, comma-separated (e.g. `deep,refresh,confirm`). Overrides `--mode`/`--intensity`; stops on the first non-complete mode. Per-driver, modes a driver can't run are skipped on that leg |
| `--list-modes` | — | bool | `false` | Print the audit mode graph (phases, time estimates, descriptions) and exit |
| `--source` | — | string | `.` | Local directory, git URL, `gs://<project>/<key>` archive, or local archive |
| `--interactive` | `-i` | bool | `false` | Drop into the coding agent with the audit harness installed and drive it yourself (audit-only). Skips streaming, the AgenticScan row, and findings import — results land in `<source>/vigolium-results/`; import them afterward with `vigolium import`. Not valid with `--driver=piolium` |
| `--commit-depth` | — | int | `1` | `git clone --depth` value when `--source` is a git URL (0 = full history) |
| `--no-stream` | — | bool | `false` | Don't echo agent output (still written to `{session}/<driver>/runtime.log`) |
| `--show-thinking` | — | bool | `false` | Render the agent's internal thinking blocks in the live stream (audit; verbose, off by default) |
| `--keep-raw` | — | bool | `false` | [audit] Keep raw scanner output / draft findings under `<source>/vigolium-results/` (overrides deep/confirm auto-prune). No effect on the piolium leg |
| `--upload-results` | — | bool | `false` | Upload parent session bundle (only when **all** participating drivers succeed) |
| `--no-dedup` | — | bool | `false` | Skip the post-pass project-wide findings dedup |
| `--provider` | — | string | — | [audit] Olium provider hint that selects the audit leg's agent: `anthropic-*` → claude, `openai-*` → codex (also forwards that provider's BYOK auth). Empty inherits `agent.olium.provider` |
| `--agent` | — | string | — | [audit] Coding agent for the audit leg: `claude` or `codex`. Overrides the agent implied by `--provider` while keeping its auth (warns under `--driver=piolium`) |
| `--api-key` | — | string | — | BYOK API key for the run (literal, `$ENV_NAME`, or `@path`). claude→`ANTHROPIC_API_KEY`, codex→`OPENAI_API_KEY`. Mutually exclusive with `--oauth-token`/`--oauth-cred-file` |
| `--oauth-token` | — | string | — | BYOK Anthropic OAuth bearer token (claude only; from `claude setup-token`). Mutually exclusive with `--api-key`/`--oauth-cred-file` |
| `--oauth-cred-file` | — | string | — | BYOK OAuth credential file path (codex `~/.codex/auth.json` shape). Mutually exclusive with `--api-key`/`--oauth-token` |
| `--pi-provider` | — | string | — | [piolium] Override pi's `defaultProvider` |
| `--pi-model` | — | string | — | [piolium] Override pi's `defaultModel` |
| `--no-preflight` | — | bool | `false` | Skip the pre-audit roundtrip checks for both drivers |
| `--preflight-timeout` | — | duration | `30s` | Per-driver preflight timeout |
| `--plm-*` | — | various | — | [piolium] passthroughs — same set as [Agent Piolium Flags](#agent-piolium-flags). Ignored when `--driver=audit` |

---

## Agent Session Flags

Flags specific to `vigolium agent session`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--limit` | `-n` | int | `50` | Maximum number of records to display |
| `--mode` | — | string | — | Filter by mode (query, autopilot, swarm, audit, piolium) |
| `--offset` | `-o` | int | `0` | Number of records to skip |
| `--tail` | — | int | `50` | Number of raw output lines to show in detail view (0 = none, -1 = all) |
| `--full` | — | bool | `false` | Show full raw output (shortcut for `--tail -1`) |
| `--tui` / `--no-tui` | — | bool | — | Enable / force-disable interactive TUI picker |

---

## Olium Provider Override Flags (shared)

Per-run overrides accepted on `agent query`, `agent autopilot`, `agent swarm`, and `agent olium` (and the top-level `vigolium olium` / `ol`). Each falls back to the matching `agent.olium.*` config field, then to the documented env var.

| Flag | Type | Falls back to | Description |
|------|------|---------------|-------------|
| `--provider` | string | `agent.olium.provider` (default `openai-compatible`) | Olium provider: `openai-compatible` \| `openai-codex-oauth` \| `anthropic-api-key` \| `anthropic-oauth` \| `openai-api-key` \| `anthropic-cli` \| `anthropic-vertex` \| `google-vertex` |
| `--model` | string | `agent.olium.model` (default `gemma4:latest`) | Model id |
| `--oauth-cred` | string | `agent.olium.oauth_cred_path` or `$GOOGLE_APPLICATION_CREDENTIALS` | OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex) |
| `--oauth-token` | string | `agent.olium.oauth_token` or `$ANTHROPIC_API_KEY` | Claude Code OAuth bearer token (`anthropic-oauth`) |
| `--llm-api-key` | string | `agent.olium.llm_api_key` or provider env var (`$ANTHROPIC_API_KEY`/`$OPENAI_API_KEY`) | API key for key-based providers |
| `--gcp-project` | string | `$GOOGLE_CLOUD_PROJECT` > `agent.olium.google_cloud_project` > SA file's `project_id` | GCP project for `anthropic-vertex` / `google-vertex` |
| `--gcp-location` | string | `$GOOGLE_CLOUD_LOCATION` > `agent.olium.google_cloud_location` > `us-central1` | GCP region for `anthropic-vertex` / `google-vertex` |
| `--system-prompt` | string | — | Replace the built-in system prompt with this value (autopilot only) |
| `--system-prompt-file` | string | — | Path to a file whose contents replace the built-in system prompt; takes precedence over `--system-prompt` (autopilot only) |
| `--system` | string | — | Replace the system prompt (`agent olium` TUI only) |

---

## Log Flags

Flags specific to `vigolium log` and `vigolium log ls`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--tail` | `-n` | int | `200` | Show the last N lines (0 = none, -1 = all) |
| `--full` | — | bool | `false` | Show the full log (shortcut for `--tail -1`) |
| `--follow` | `-f` | bool | `false` | Follow log output as it is written. Auto-enabled when the session is still running unless `--follow=false` is set |
| `--strip-ansi` | — | bool | `false` | Strip ANSI color codes from output |
| `--tui` / `--no-tui` | — | bool | — | Enable / force-disable the interactive picker |

---

## Import Flags

`vigolium import <path>` has no additional flags beyond the global project/JSON flags. Path may be an audit output folder (a `vigolium-results/` directory with `audit-state.json` + `findings-draft/`) or a JSONL export (file).

---

## Finding Flags

Flags specific to `vigolium finding` (aliases: `findings`).

### Finding filter flags (persistent)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--host` | — | string | — | Filter by hostname pattern |
| `--method` | — | []string | — | Filter by HTTP method (repeatable) |
| `--status` | — | []int | — | Filter by HTTP status code (repeatable) |
| `--path` | — | string | — | Filter by URL path pattern |
| `--from` | — | string | — | Show findings after date |
| `--to` | — | string | — | Show findings before date |
| `--search` | — | string | — | Search across descriptions, module IDs, and matched_at |
| `--header` | — | string | — | Search within HTTP header names and values |
| `--body` | — | string | — | Search within HTTP request/response body content |
| `--source` | — | string | — | Filter by record source |
| `--sort` | — | string | `found_at` | Sort by: found_at, created_at, severity, module, confidence |
| `--asc` | — | bool | `false` | Sort ascending |
| `--limit` | `-n` | int | `100` | Maximum findings to display |
| `--offset` | `-o` | int | `0` | Number of findings to skip |
| `--severity` | — | string | — | Filter by severity (comma-separated: critical,high,medium,low,info) |
| `--scan-id` | — | string | — | Filter by scan session ID |
| `--module-type` | — | string | — | Filter by module type (active, passive, nuclei, secret-scan, agent, source-tools, oast, extension) |
| `--finding-source` | — | string | — | Filter by finding source (audit, spa, agent, oast, source-tools, extension) |
| `--id` | — | int | `0` | Filter by finding ID |
| `--min-severity` | — | string | — | Show findings at/above this severity (`info`,`suspect`,`low`,`medium`,`high`,`critical`); ignored when `--severity` is set |
| `--agentic-scan` | — | string | — | Findings from an agent run; one root UUID expands to the whole run tree (audit driver legs / swarm sub-runs) |

### Finding display flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--raw` | bool | `false` | Show full raw HTTP request and response for each finding |
| `--burp` | bool | `false` | Display in Burp Suite-style format (colored request/response) |
| `--columns` | []string | — | Columns to show (comma-separated, e.g. ID,SEVERITY,MODULE) |
| `--exclude-columns` | []string | — | Columns to hide (comma-separated) |

### Agent JSON flags (shared by `finding`, `traffic`, `db ls`)

With `-j`/`--json`, the read commands emit **one compact, token-aware object** (not the bulk export stream). These shape it:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--json` | `-j` | bool | `false` | Emit the single compact object instead of a table |
| `--compact` | — | bool | `false` | Metadata only — drop request/response bodies and evidence snippets |
| `--fields` | — | []string | — | Project only these top-level JSON keys (comma-separated) |
| `--full-body` | — | bool | `false` | Complete bodies — no preview caps, no binary/static stubbing, no hashing |
| `--with-records` | — | bool | `false` | **finding only** — embed each finding's linked HTTP records as a `records:[…]` triage bundle |

`db stats -j` is the exception — it emits its raw stats struct, not the compact view, and does not accept these shaping flags.

### Finding available columns

ID, SEVERITY, CONFIDENCE, MODULE, MODULE_ID, SHORT_DESC, DESCRIPTION, TYPE, SOURCE, MATCHED_AT, FOUND_AT, SCAN_UUID, TAGS

Default columns: ID, SEVERITY, MODULE, SHORT_DESC, TYPE, SOURCE, MATCHED_AT

---

## Traffic Flags

Filter flags (shared with the `--replay` mode via PersistentFlags).

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--asc` | — | bool | `false` | Sort in ascending order (default: descending) |
| `--body` | — | string | — | Search within HTTP request/response body content |
| `--from` | — | string | — | Show records after this date |
| `--header` | — | string | — | Search within HTTP header names and values |
| `--host` | — | string | — | Filter by hostname pattern |
| `--limit` | `-n` | int | `100` | Maximum records to display |
| `--method` | — | []string | — | Filter by HTTP method (repeatable) |
| `--offset` | `-o` | int | `0` | Number of records to skip |
| `--path` | — | string | — | Filter by URL path pattern |
| `--search` | — | string | — | Fuzzy search across URLs, paths, and hostnames |
| `--sort` | — | string | `created_at` | Sort by: uuid, created_at, sent_at, method, status, time |
| `--source` | — | string | — | Filter by record source |
| `--status` | — | []int | — | Filter by HTTP status code (repeatable) |
| `--to` | — | string | — | Show records before this date |

Display-only flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--burp` | bool | `false` | Burp-style format |
| `--columns` | []string | — | Columns to show (comma-separated, e.g. HOST,METHOD,PATH,STATUS) |
| `--exclude-columns` | []string | — | Columns to hide (comma-separated) |
| `--raw` | bool | `false` | Raw HTTP output |
| `--tree` | bool | `false` | Display as host/path hierarchy tree |

Traffic also accepts the shared [Agent JSON flags](#agent-json-flags-shared-by-finding-traffic-db-ls) with `-j`/`--json`: `--compact`, `--fields a,b,c`, `--full-body`.

Traffic replay flag.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--in-replace` | bool | `false` | Replace stored response |

---

## Replay Flags

Flags for the top-level `vigolium replay` command (mutate a stored/supplied
request and diff baseline vs replay; the CLI surface of the in-process
`replay_request` tool). See also `traffic --replay` for verbatim bulk replay.

Source (exactly one, or a bulk selector below):

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--record-uuid` | `-u` | string | — | Stored HTTP record UUID to use as baseline |
| `--finding-id` | — | int | — | Replay the finding's linked record (or its stored evidence) |
| `--input` | `-i` | string | — | Raw input: curl, raw HTTP, Burp XML, base64, URL, or `-` for stdin |
| `--input-file` | — | string | — | Read `--input` value from a file |

Mutation / request override:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--mutate` | `-m` | []string | — | Insertion-point mutation `name=...,payload=...` or `name:type:payload` (repeatable) |
| `--raw-request` | — | string | — | Full raw HTTP request override (mutually exclusive with `--mutate`) |
| `--raw-request-file` | — | string | — | Read `--raw-request` from a file |
| `--header` | `-H` | []string | — | Extra request header `Name: value` (repeatable, overrides baseline) |
| `--auth-session` | — | string | — | Auth session name to merge headers from (`vigolium auth list`) |

Session / network:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--session-id` | — | string | — | Persist cookies across calls under `~/.vigolium/replay-jars/<id>.json` |
| `--no-cookies` | — | bool | `false` | Don't carry cookies (overrides `--session-id`) |
| `--no-redirects` | — | bool | `false` | Don't follow 30x redirects |
| `--target` | `-t` | string | — | Override scheme/host/port (e.g. `https://staging.example.com`) |
| `--timeout` | — | duration | `30s` | Per-request timeout |

Result handling:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--in-replace` | — | bool | `false` | When the source is a stored record, update its stored response with the replay |
| `--output` | `-o` | string | — | Write JSON result to this file (default: stdout) |
| `--pretty` | — | bool | `false` | Human-readable summary instead of JSON |

Bulk selection — setting `--all` or any of these switches replay into "iterate
the matching stored records" mode (mutually exclusive with the single-source
flags above). Results stream as JSONL, one object per record; `--mutate` is
applied to every record that has that insertion point. Pair with `-S/--stateless`
+ `--db` to replay a standalone `.sqlite`/`.jsonl` export (project scoping off).

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all` | `-a` | bool | `false` | Replay every matched stored record (lifts the `-n/--limit` cap) |
| `--host` | — | string | — | Filter records by hostname pattern (wildcard supported) |
| `--method` | — | []string | — | Filter records by HTTP method (repeatable) |
| `--status` | — | []int | — | Filter records by stored status code (repeatable) |
| `--path` | — | string | — | Filter records by URL path pattern |
| `--source` | — | string | — | Filter records by source (scanner, ingest-cli, ingest-proxy, seed, ...) |
| `--search` | — | string | — | Fuzzy-search records across URLs, paths, and hostnames |
| `--body` | — | string | — | Filter records whose request/response body contains this text |
| `--limit` | `-n` | int | `100` | Max records to replay (use `--all` to lift the cap) |
| `--concurrency` | `-c` | int | `10` | Concurrent replays; keep low to avoid overwhelming an intercepting proxy like Burp |
| `--stateless` | `-S` | bool | `false` | Read records from `--db` (a `.jsonl` export or standalone `.sqlite`) with project scoping off |

---

## DB Flags

Shared across db subcommands.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--table` | string | — | Table name |
| `--search` | string | — | Quick search |

DB list flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--asc` | — | bool | `false` | Sort in ascending order |
| `--body` | — | string | — | Search within request or response body content |
| `--columns` | — | []string | — | Columns to include |
| `--exclude-columns` | — | []string | — | Columns to exclude |
| `--finding-source` | — | string | — | Filter findings by source |
| `--from` | — | string | — | Show records created after this date |
| `--header` | — | string | — | Search within HTTP header names and values |
| `--host` | — | string | — | Filter records by hostname pattern |
| `--limit` | `-n` | int | `100` | Maximum number of records to display |
| `--list-columns` | — | bool | `false` | List column names for the current table |
| `--list-tables` | — | bool | `false` | List all database table names |
| `--method` | — | []string | — | Filter records by HTTP method |
| `--min-risk` | — | int | `0` | Show only records with risk score at or above this value |
| `--module-type` | — | string | — | Filter findings by module type |
| `--offset` | `-o` | int | `0` | Number of records to skip |
| `--path` | — | string | — | Filter records by URL path pattern |
| `--raw` | — | bool | `false` | Show full raw HTTP request and response |
| `--remark` | — | string | — | Filter records containing this text in remarks |
| `--scan-id` | — | string | — | Filter records by scan session ID |
| `--severity` | — | string | — | Filter findings by severity |
| `--sort` | — | string | `created_at` | Sort results by field |
| `--status` | — | []int | — | Filter records by HTTP status code |
| `--to` | — | string | — | Show records created before this date |
| `--tree` | — | bool | `false` | Display results in hierarchical tree format |

`db ls` also accepts the shared [Agent JSON flags](#agent-json-flags-shared-by-finding-traffic-db-ls) with `-j`/`--json`: `--compact`, `--fields a,b,c`, `--full-body` (all tables except `db stats`).

DB export flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | string | `jsonl` | Export format: jsonl, json, raw, csv, markdown, markdown-table, `fs` (flat traffic/finding tree) |
| `--from` | — | string | — | Export records created after this date |
| `--host` | — | string | — | Filter records by hostname pattern |
| `--limit` | — | int | `0` | Maximum number of records to export (0 = unlimited) |
| `--method` | — | []string | — | Filter records by HTTP method |
| `--offset` | — | int | `0` | Number of records to skip |
| `--output` | `-o` | string | — | Output file path |
| `--path` | — | string | — | Filter records by URL path pattern |
| `--request-only` | — | bool | `false` | Export only HTTP requests (raw format only) |
| `--scan-id` | — | string | — | Filter records by scan session ID |
| `--severity` | — | string | — | Filter findings by severity level |
| `--status` | — | []int | — | Filter records by HTTP status code |
| `--to` | — | string | — | Export records created before this date |
| `--uuid` | — | string | — | Export a single record by its UUID |

DB clean flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Delete all records (requires --force) |
| `--before` | string | — | Delete records created before this date |
| `--dry-run` | bool | `false` | Show what would be deleted without deleting |
| `--findings-only` | bool | `false` | Delete findings only, keep HTTP records |
| `--host` | string | — | Delete records matching the specified hostname |
| `--orphans` | bool | `false` | Delete findings with no matching HTTP record |
| `--scan-id` | string | — | Delete records belonging to the specified scan session |
| `--severity` | string | — | Delete findings matching the specified severity level |
| `--status` | []int | — | Delete records with matching HTTP status codes |
| `--vacuum` | bool | `false` | Reclaim disk space after deletion (SQLite) |

DB stats flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--detailed` | bool | `false` | Show per-host and per-module breakdown |
| `--host` | string | — | Filter hostname |
| `--scan-id` | string | — | Filter scan ID |

---

## Storage Flags

Flags for the `vigolium storage <subcommand>` family. All require `storage.enabled: true` in `vigolium-configs.yaml` (or `VIGOLIUM_STORAGE_ENABLED=true`) plus driver/bucket/access-key/secret-key configured. Operations are scoped to the active project.

### storage ls

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--prefix` | string | — | Limit results to keys under this prefix |
| `--tree` | bool | `false` | Render objects as a directory tree |
| `--json` | bool | `false` | Output as JSON |

### storage upload

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--key` | string | `ugc/<basename>` | Object key |
| `--content-type` | string | — | Content-Type to set on the object |

### storage download

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | — | Write to this file instead of stdout |

### storage results

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | `results-<uuid>.tar.gz` | Write to this file |

### storage presign

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--key` | string | — | Object key (required) |
| `--method` | string | `GET` | HTTP method: `GET` or `PUT` |
| `--expiry` | duration | `1h` | URL validity duration |
| `--json` | bool | `false` | Output as JSON `{url, key, method, expiry_seconds}` |

### storage rm

Takes one or more `<key>` positional args. Honors the global `--force` / `-F` to skip the typed-`yes` confirmation.

---

## Export Flags

Top-level `vigolium export` flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | — | string | `jsonl` | Format: jsonl, html, `fs` (flat traffic/finding tree) |
| `--limit` | — | int | `0` | Max records per table |
| `--omit-response` | — | bool | `false` | Omit raw HTTP request/response bytes (keeps metadata, smaller files) |
| `--only` | — | []string | all | Export only these tables (repeatable: http, findings, scans, modules, oast, source-repos, scopes) |
| `--output` | `-o` | string | — | Output file |
| `--search` | — | string | — | Fuzzy search filter |

---

## Module Flags

Module enable/disable flag.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--id` | bool | `false` | Exact ID match (enable/disable) |

Module ls flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--list-enabled` | — | bool | `false` | Show only enabled modules |
| `--tags` | — | bool | `false` | Show only unique module tags |
| `--type` | — | string | `all` | Filter modules by type: all, active, or passive |
| `--verbose` | `-v` | bool | `false` | Show long description and confirmation criteria |

---

## Extensions Flags

Subcommands: `docs`, `eval`, `lint`, `ls`, `preset`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--example` | bool | `false` | Show code examples (docs) |
| `--ext-file` | string | — | JS file to evaluate (eval) |
| `--stdin` | bool | `false` | Read from stdin (eval) |
| `--type` | string | `all` | Filter type (ls) |

---

## JS Flags

Flags specific to `vigolium js`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--code` | string | — | Inline JavaScript code to execute |
| `--code-file` | string | — | Path to JavaScript/TypeScript file (auto-transpiles `.ts`) |
| `--target` | string | — | Set TARGET variable in JS scope (URL string) |
| `--timeout` | duration | `30s` | Execution timeout (e.g., `60s`, `2m`) |
| `--format` | string | `json` | Output format: `json` or `text` |

---

## Source Add Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--framework` | `-f` | string | — | Framework |
| `--git` | `-g` | string | — | Git URL to clone |
| `--hostname` | `-H` | string | — | Target hostname (required) |
| `--language` | `-l` | string | — | Primary language |
| `--name` | `-n` | string | dir basename | Display name |
| `--path` | `-p` | string | — | Source path |
| `--repo-type` | — | string | auto | Type: git, folder, archive |
| `--scan-uuid` | — | string | — | Link to scan UUID |
| `--tag` | — | []string | — | Tags (repeatable) |
