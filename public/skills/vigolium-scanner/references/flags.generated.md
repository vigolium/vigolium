# Flag Reference (generated)

<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Regenerate with `make skill-flags` (or `vigolium skills gen-flags`).
     Every row below is read straight off the cobra command tree, so it
     always matches the binary that produced it. -->

Every flag on every command, grouped by the command that owns it.
**Global flags are listed once** and are available everywhere; each command
section lists only the flags that command adds.

This file is for lookup — grep it for a flag name rather than reading it
top to bottom. For the authoritative help of the version you have installed,
run `vigolium <command> -h`.

## Contents

- [Global Flags](#global-flags)
- [vigolium agent](#vigolium-agent)
- [vigolium agent audit](#vigolium-agent-audit)
- [vigolium agent autopilot](#vigolium-agent-autopilot)
- [vigolium agent olium](#vigolium-agent-olium)
- [vigolium agent query](#vigolium-agent-query)
- [vigolium agent session](#vigolium-agent-session)
- [vigolium agent swarm](#vigolium-agent-swarm)
- [vigolium agent triage](#vigolium-agent-triage)
- [vigolium arjun](#vigolium-arjun)
- [vigolium audit](#vigolium-audit)
- [vigolium auth](#vigolium-auth)
- [vigolium auth check](#vigolium-auth-check)
- [vigolium auth lint](#vigolium-auth-lint)
- [vigolium auth list](#vigolium-auth-list)
- [vigolium auth load](#vigolium-auth-load)
- [vigolium auth totp](#vigolium-auth-totp)
- [vigolium config](#vigolium-config)
- [vigolium config clean](#vigolium-config-clean)
- [vigolium config ls](#vigolium-config-ls)
- [vigolium config set](#vigolium-config-set)
- [vigolium config validate](#vigolium-config-validate)
- [vigolium db](#vigolium-db)
- [vigolium db clean](#vigolium-db-clean)
- [vigolium db compact](#vigolium-db-compact)
- [vigolium db export](#vigolium-db-export)
- [vigolium db list](#vigolium-db-list)
- [vigolium db migrate](#vigolium-db-migrate)
- [vigolium db reset](#vigolium-db-reset)
- [vigolium db seed](#vigolium-db-seed)
- [vigolium db stats](#vigolium-db-stats)
- [vigolium dig](#vigolium-dig)
- [vigolium dns](#vigolium-dns)
- [vigolium doctor](#vigolium-doctor)
- [vigolium endpoints](#vigolium-endpoints)
- [vigolium export](#vigolium-export)
- [vigolium extensions](#vigolium-extensions)
- [vigolium extensions docs](#vigolium-extensions-docs)
- [vigolium extensions eval](#vigolium-extensions-eval)
- [vigolium extensions example](#vigolium-extensions-example)
- [vigolium extensions lint](#vigolium-extensions-lint)
- [vigolium extensions ls](#vigolium-extensions-ls)
- [vigolium extensions preset](#vigolium-extensions-preset)
- [vigolium extensions run](#vigolium-extensions-run)
- [vigolium extensions test](#vigolium-extensions-test)
- [vigolium extensions types](#vigolium-extensions-types)
- [vigolium ffuf](#vigolium-ffuf)
- [vigolium finding](#vigolium-finding)
- [vigolium finding load](#vigolium-finding-load)
- [vigolium finding mark](#vigolium-finding-mark)
- [vigolium finding verify](#vigolium-finding-verify)
- [vigolium fingerprint](#vigolium-fingerprint)
- [vigolium fuzz](#vigolium-fuzz)
- [vigolium gau](#vigolium-gau)
- [vigolium host](#vigolium-host)
- [vigolium hosts](#vigolium-hosts)
- [vigolium import](#vigolium-import)
- [vigolium ingest](#vigolium-ingest)
- [vigolium init](#vigolium-init)
- [vigolium js](#vigolium-js)
- [vigolium katana](#vigolium-katana)
- [vigolium kit](#vigolium-kit)
- [vigolium kit harvest](#vigolium-kit-harvest)
- [vigolium kit js-beautify](#vigolium-kit-js-beautify)
- [vigolium kit jwt-crack](#vigolium-kit-jwt-crack)
- [vigolium kit oast](#vigolium-kit-oast)
- [vigolium kit oast new](#vigolium-kit-oast-new)
- [vigolium kit oast poll](#vigolium-kit-oast-poll)
- [vigolium kit param-mine](#vigolium-kit-param-mine)
- [vigolium kit payload](#vigolium-kit-payload)
- [vigolium kit secret-scan](#vigolium-kit-secret-scan)
- [vigolium kit tmp-clean](#vigolium-kit-tmp-clean)
- [vigolium kit wordlist](#vigolium-kit-wordlist)
- [vigolium log](#vigolium-log)
- [vigolium log ls](#vigolium-log-ls)
- [vigolium match-not-found](#vigolium-match-not-found)
- [vigolium module](#vigolium-module)
- [vigolium module disable](#vigolium-module-disable)
- [vigolium module enable](#vigolium-module-enable)
- [vigolium module ls](#vigolium-module-ls)
- [vigolium nuclei](#vigolium-nuclei)
- [vigolium oast](#vigolium-oast)
- [vigolium oast ingest](#vigolium-oast-ingest)
- [vigolium oast poll](#vigolium-oast-poll)
- [vigolium olium](#vigolium-olium)
- [vigolium params](#vigolium-params)
- [vigolium project](#vigolium-project)
- [vigolium project config](#vigolium-project-config)
- [vigolium project create](#vigolium-project-create)
- [vigolium project delete](#vigolium-project-delete)
- [vigolium project list](#vigolium-project-list)
- [vigolium project use](#vigolium-project-use)
- [vigolium replay](#vigolium-replay)
- [vigolium run](#vigolium-run)
- [vigolium scan](#vigolium-scan)
- [vigolium scan diff](#vigolium-scan-diff)
- [vigolium scan status](#vigolium-scan-status)
- [vigolium scan wait](#vigolium-scan-wait)
- [vigolium scan-request](#vigolium-scan-request)
- [vigolium scan-url](#vigolium-scan-url)
- [vigolium schema](#vigolium-schema)
- [vigolium schema all](#vigolium-schema-all)
- [vigolium schema command](#vigolium-schema-command)
- [vigolium schema error](#vigolium-schema-error)
- [vigolium schema event](#vigolium-schema-event)
- [vigolium schema flags](#vigolium-schema-flags)
- [vigolium schema list](#vigolium-schema-list)
- [vigolium schema plan](#vigolium-schema-plan)
- [vigolium schema storage](#vigolium-schema-storage)
- [vigolium scope](#vigolium-scope)
- [vigolium scope set](#vigolium-scope-set)
- [vigolium scope view](#vigolium-scope-view)
- [vigolium server](#vigolium-server)
- [vigolium server ca](#vigolium-server-ca)
- [vigolium server ca install](#vigolium-server-ca-install)
- [vigolium server ca path](#vigolium-server-ca-path)
- [vigolium server ca print](#vigolium-server-ca-print)
- [vigolium server ca uninstall](#vigolium-server-ca-uninstall)
- [vigolium skills](#vigolium-skills)
- [vigolium skills get](#vigolium-skills-get)
- [vigolium skills install](#vigolium-skills-install)
- [vigolium skills list](#vigolium-skills-list)
- [vigolium storage](#vigolium-storage)
- [vigolium storage download](#vigolium-storage-download)
- [vigolium storage ls](#vigolium-storage-ls)
- [vigolium storage presign](#vigolium-storage-presign)
- [vigolium storage results](#vigolium-storage-results)
- [vigolium storage rm](#vigolium-storage-rm)
- [vigolium storage upload](#vigolium-storage-upload)
- [vigolium strategy](#vigolium-strategy)
- [vigolium traffic](#vigolium-traffic)
- [vigolium traffic body](#vigolium-traffic-body)
- [vigolium traffic headers](#vigolium-traffic-headers)
- [vigolium update](#vigolium-update)
- [vigolium version](#vigolium-version)

---

## Global Flags

Persistent flags available on every command.

A command section below may redefine one of these names with a different
type, default, or set of accepted values. Such a row is marked **overrides**
and wins for that command — read it instead of the row here.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--ci-output-format` | - | bool | `false` | CI-friendly output: JSONL findings only, no color, no banners |
| `--color` | - | string | `auto` | Color ANSI output: auto (only when stdout and stderr are both terminals), always, or never. --no-color is never; NO_COLOR, FORCE_COLOR and CLICOLOR_FORCE are honored under auto. -j, --events and --ci-output-format force never |
| `--config` | - | string | - | Path to config file (default "~/.vigolium/vigolium-configs.yaml") |
| `--db` | - | string | - | Path to SQLite database file (default "~/.vigolium/database-vgnm.sqlite"). Also honors $VIGOLIUM_DB_PATH, which additionally reads that file with project scoping off |
| `--debug` | - | bool | `false` | Enable debug-level logging (includes outgoing HTTP request lines) |
| `--dump-traffic` | - | bool | `false` | Print every HTTP request/response pair to stderr (Burp-style, bypasses logger) |
| `--ext` | - | stringArray | - | Load JavaScript extension script (repeatable) |
| `--ext-allow-failures` | - | bool | `false` | Scan even when an extension named with --ext fails to load (default: abort before any traffic, exit 2 extension_load_failed) |
| `--ext-dir` | - | string | - | Override extension scripts directory |
| `--force` | - | bool | `false` | Skip confirmation prompts |
| `--format` | - | string | `console` | Output format (comma-separated for multiple): console, jsonl, html, report, pdf (headless Chrome), markdown (alias: md), sarif (SARIF 2.1.0), csv, junit (failures at/above --fail-on), github (workflow commands; stdout without -o), sqlite (alias: sqlite3, db; needs -S), fs (alias: file-system; flat traffic/finding tree) |
| `--full-example` | - | bool | `false` | Show full example commands organized by section |
| `--json` | `-j` | bool | `false` | Emit machine-readable JSON for agent/programmatic use (compact bodies; pair with --fields/--compact/--full-body on finding/traffic/db). For the bulk {type,data} stream use --format jsonl / export. |
| `--list-input-mode` | - | bool | `false` | List all supported input modes with examples |
| `--list-modules` | `-M` | bool | `false` | List all available scanner modules |
| `--log-file` | - | string | - | Write all log output to this file (JSON format) |
| `--mem-limit` | - | string | - | Soft heap ceiling (GOMEMLIMIT) for scans: empty = auto (1/3 of RAM, scaled down by -P/--parallel so all children stay under ⅔ of RAM), 'off' to disable, or an explicit size/percent like 6GiB or 50%. An existing GOMEMLIMIT env var overrides this. |
| `--no-color` | - | bool | `false` | Disable ANSI color in all output (same as --color=never; also honored via the NO_COLOR env var) |
| `--offline` | - | bool | `false` | Keep off every network path that is not the target: no OAST callbacks, third-party lookups (npm registry), nuclei template clone/update, browser download or update check (also settings key offline) |
| `--pretty` | - | bool | `false` | Indent -j/--json output for reading (default: compact, one line). Also $VIGOLIUM_JSON_PRETTY=1. --watch stays one compact document per line |
| `--project-name` | - | string | - | Project name to scope all operations to (must match exactly one project). Also honors $VIGOLIUM_PROJECT_NAME |
| `--project-uuid` | - | string | - | Project UUID to scope all operations to (defaults to the default project). Also honors $VIGOLIUM_PROJECT_UUID |
| `--proxy` | - | string | - | Route all requests through this proxy (HTTP/SOCKS5 URL) |
| `--read-only` | - | bool | `false` | Open the database without modifying it (no directory creation, no journal-mode change, no WAL checkpoint). Read commands only; use it when the source file is evidence |
| `--scan-uuid` | - | string | - | Pin scan UUID for this session (use to sync results across nodes; defaults to a freshly-minted UUID) |
| `--silent` | - | bool | `false` | Suppress all output except findings |
| `--skip-dependency-check` | - | bool | `false` | Skip the first-run dependency check and stamp ~/.vigolium/initialized (the check only prints a notice; chromium and nuclei templates are fetched by the phase that needs them) |
| `--soft-fail` | - | bool | `false` | Always exit 0, even when a command fails (error is still printed to stderr; keeps wrapping scripts/CI from being interrupted) |
| `--usage` | - | bool | `false` | Print this command's flags, one line each, and exit (-j: the 'schema flags' document) |
| `--verbose` | `-v` | bool | `false` | Enable verbose logging output |
| `--width` | - | int | `70` | Maximum column width for table output |

## vigolium agent

Run an agentic scan — AI-driven scanning with native scan support

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--list-agents` | - | bool | `false` | List the olium providers available for agent runs |
| `--list-templates` | - | bool | `false` | List available prompt templates |

## vigolium agent audit

Run audit and/or piolium back-to-back as a unified security audit

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | - | string | - | [audit] Coding agent for the audit leg: claude or codex. Overrides the agent implied by --provider while keeping its resolved auth. No effect on the piolium leg. |
| `--api-key` | - | string | - | BYOK API key for the run (literal, $ENV_NAME, or @path). claude→ANTHROPIC_API_KEY, codex→OPENAI_API_KEY. Empty inherits agent.olium.* config. Mutually exclusive with --oauth-token / --oauth-cred-file. |
| `--clean-raw` | - | bool | `false` | [audit] Remove <source>/vigolium-results/ from the source tree after the run (the session copy is always kept). Inverts the default --keep-raw retention of the source-folder copy. No effect on the piolium leg. |
| `--commit-depth` | - | int | `1` | git clone --depth value when --source is a git URL (default 1; use 0 for full history; overrides --intensity) |
| `--driver` | - | string | `auto` | Audit driver: auto (run audit; fall back to piolium only when audit cannot start - claude/codex CLI missing, binary not embedded, or no audit-supported mode in the chain), both (audit then piolium), audit, or piolium (default auto) |
| `--intensity` | - | string | `balanced` | Audit intensity preset: quick, balanced, or deep |
| `--interactive` | `-i` | bool | `false` | Drop into the coding agent with the audit harness installed and drive the audit yourself (audit-only; the embedded vigolium-audit binary's -i). Skips NDJSON streaming, the AgenticScan row, and findings auto-import — results land in <source>/vigolium-results/; import them afterward with 'vigolium import'. Not valid with --driver=piolium. |
| `--keep-raw` | - | bool | `true` | [audit] Keep raw scanner output, draft findings, and intermediate workspaces under <source>/vigolium-results/ for manual review (overrides audit's deep/confirm auto-prune). On by default; the source-folder copy is also retained. Pass --clean-raw to remove it from the source tree. No effect on the piolium leg. |
| `--list-modes` | - | bool | `false` | List the available audit modes (audit's mode graph: phases, time estimate, descriptions) and exit |
| `--mode` | - | string | - | Audit mode override (overrides --intensity). Shared modes: lite, balanced, deep, revisit, confirm, merge. Driver-specific: piolium=longshot/smoke/diff/status, audit=reinvest/refresh/mock/diff/status |
| `--modes` | - | string | - | Run a chain of modes back-to-back (comma-separated, e.g. deep,refresh,confirm). Overrides --mode/--intensity. Stops on the first non-complete mode. audit runs the chain natively (--modes); piolium chains via sequential runs collapsed into one row; with driver=auto/both, modes a driver can't run are skipped on that driver's leg. |
| `--no-dedup` | - | bool | `false` | Skip the post-pass project-wide findings dedup that runs after the audit completes |
| `--no-preflight` | - | bool | `false` | Skip the pre-audit roundtrip checks for both drivers (pi+claude auth/model availability) |
| `--no-stream` | - | bool | `false` | Don't echo agent output to the console (still written to {session}/<driver>/runtime.log) |
| `--oauth-cred-file` | - | string | - | BYOK OAuth credential file path (literal or $ENV_NAME). Codex ('~/.codex/auth.json' shape). Staged under <pi-agent-dir>/auth.json with backup-and-restore for piolium runs. Mutually exclusive with --api-key / --oauth-token. |
| `--oauth-token` | - | string | - | BYOK Anthropic OAuth bearer token (literal, $ENV_NAME, or @path). Claude only — produced by 'claude setup-token'. Mutually exclusive with --api-key / --oauth-cred-file. |
| `--output` | `-o` | string | - | HTML report path for --stateless runs (default vigolium-result/vigolium-audit-report.html; supports gs://<project>/<key> and {ts}). Only applies with -S/--stateless. |
| `--output-dir` | - | string | - | Bundle directory for --stateless runs: collects the HTML report (as vigolium-audit-report.html) AND a copy of the raw vigolium-results/ output into one folder. A relative -o/--output is nested under it; an absolute path or gs:// URL wins. The source-tree copy is left in place. Supports {ts}/{project-uuid}. Only applies with -S/--stateless. |
| `--pi-model` | - | string | - | [piolium] Override pi's defaultModel (e.g. claude-opus-5, gemini-3.1-pro) |
| `--pi-provider` | - | string | - | [piolium] Override pi's defaultProvider (e.g. vertex-anthropic, google-vertex) |
| `--plm-command-retries` | - | int | `0` | [piolium] Per-command retry count (0=piolium default) |
| `--plm-longshot-langs` | - | string | - | [piolium] Longshot language allowlist (comma-separated, e.g. python,go) |
| `--plm-longshot-limit` | - | int | `0` | [piolium] Max files hunted in longshot mode (0=piolium default) |
| `--plm-longshot-timeout` | - | int | `0` | [piolium] Per-file kill timer in longshot mode in ms (0=piolium default) |
| `--plm-phase-retries` | - | int | `0` | [piolium] Per-phase retry count (0=piolium default) |
| `--plm-scan-limit` | - | int | `0` | [piolium] Cap commit-history scan to N commits (0=piolium default) |
| `--plm-scan-since` | - | string | - | [piolium] Cap commit-history scan to a git --since window (e.g. "60 days ago") |
| `--preflight-timeout` | - | duration | `30s` | Per-driver preflight timeout (e.g. 30s, 1m); applies to both pi and claude |
| `--provider` | - | string | - | [audit] Olium provider hint to drive audit's --agent: anthropic-* → claude, openai-* → codex (also forwards that provider's BYOK auth). Empty inherits agent.olium.provider. For a pure agent switch without changing auth, prefer --agent. |
| `--show-thinking` | - | bool | `false` | Render the agent's internal thinking blocks (audit NDJSON 'thinking' events) in the live stream. Off by default — thinking is verbose and produces many lines per phase. |
| `--source` | - | string | - | Source to audit (required): local directory (pass --source . for the current directory), git URL, gs://<project>/<key> archive, or local .zip/.tar.gz |
| `--stateless` | `-S` | bool | `false` | Run the audit into a throwaway temporary database (the main DB is left untouched) and auto-write a self-contained HTML report. Mirrors 'vigolium scan -S'. Not valid with --interactive. |
| `--upload-results` | - | bool | `false` | Upload session bundle to cloud storage after completion (requires storage config) |

## vigolium agent autopilot

Usage: `vigolium agent autopilot [prompt]`

Agentic scan: autonomous AI-driven vulnerability scanning

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--audit` | - | string | `off` | Nested vigolium-audit harness (runs a claude/codex CLI before the operator; needs --source): lite (3-phase), balanced (9-phase), deep (12-phase), mock (sample output), or off. Default off: the intensity preset never turns it on |
| `--auth-file` | - | stringArray | - | Native session file, as 'vigolium scan --auth-file' takes (YAML/JSON, single session or sessions: bundle; login flows, steps, OAuth2, check/reauth), or a bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal. The sessions log in before the run, the pre-scan uses them, and they are stored for the target so the operator's list_auth_sessions/replay_request can use them. |
| `--burp-bridge-url` | `-B` | string | - | Pull live Burp/Caido proxy history into the project DB before the run (e.g. http://127.0.0.1:9009), so the pre-scan and operator can mine it alongside prior traffic. Also honors $VIGOLIUM_BURP_BRIDGE_URL (alias: --caido-bridge-url) |
| `--db-isolate` | - | bool | `false` | Run into a private temporary database, then merge results into --db (or the default DB) at the end — lets parallel runs share one --db without write contention (SQLite only) |
| `--diff` | - | string | - | Focus on changed code: PR URL (github.com/.../pull/123), git ref range (main...branch), or HEAD~N |
| `--disable-guardrail` | - | bool | `false` | Skip the prompt-safety classifier on the natural-language prompt (use only when refusing a known-good prompt) |
| `--dry-run` | - | bool | `false` | Render the system prompt and first turn without launching the agent: no request to the target and no provider call (a natural-language prompt is not parsed) |
| `--files` | - | stringSlice | - | Specific files to include (relative to --source) |
| `--input` | - | string | - | Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped |
| `--intensity` | - | string | `balanced` | Scan intensity preset: quick, balanced, or deep |
| `--knowledge-base` | - | string | - | Path to a file or directory describing the app. Prose docs (markdown/txt/rst/…) are LLM-distilled into a compact brief + document index front-loaded into the operator (full docs stay on disk, read on demand). HTTP-traffic exports in the same path (HAR, Burp XML, curl, OpenAPI/Swagger, Postman, URL lists, raw HTTP) are auto-detected, parsed, and ingested into the project DB as normal traffic (source=knowledge-base) with a sample folded into the brief — disable with --knowledge-base-no-traffic. Works blackbox and whitebox. |
| `--knowledge-base-no-traffic` | - | bool | `false` | Do not parse HTTP-traffic-format files (HAR, Burp XML, curl, OpenAPI/Swagger, Postman, URL lists, raw HTTP) found in --knowledge-base into normal traffic; treat every file as prose docs instead. By default such files are parsed and ingested into the project DB (source=knowledge-base). No-op without --knowledge-base. |
| `--knowledge-base-raw` | - | bool | `false` | Skip the LLM distillation of --knowledge-base: front-load a deterministic document index only (offline / reproducible). No-op without --knowledge-base. |
| `--last-commits` | - | int | `0` | Focus on last N commits (shorthand for --diff HEAD~N) |
| `--llm-api-key` | - | string | - | Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var) |
| `--max-commands` | - | int | `0` | Tool-call budget for the operator (0 = the --intensity preset: quick 150, balanced 750, deep 3000). Hitting it stops the run: status budget_exhausted, exit 5 |
| `--max-cost-usd` | - | float64 | `0` | Cap on the operator's estimated spend in USD, priced per turn from provider usage (0 = no cap). Hitting it stops the run: status budget_exhausted, exit 5 |
| `--max-duration` | - | duration | `6h0m0s` | Maximum wall-clock duration for the autopilot session (e.g. 1h, 6h) |
| `--model` | - | string | - | Olium model id override (falls back to agent.olium.model) |
| `--no-post-halt-verify` | - | bool | `false` | Skip the post-halt coverage verification re-entry (operator halts → coverage probe → re-prompt agent when new routes turn up) |
| `--no-preflight` | - | bool | `false` | Skip the provider preflight ping (a missing or broken provider then fails on the first real call) |
| `--no-preflight-discovery` | - | bool | `false` | Skip the pre-flight discovery + OpenAPI/Swagger ingestion pass that seeds http_records before the operator agent starts |
| `--no-prescan` | - | bool | `false` | Skip the native pre-scan that seeds http_records before the operator agent (target-only runs; no-op when --source is set) |
| `--no-skill-filter` | - | bool | `false` | Load the full skill set; skip the pre-flight skill selection |
| `--oauth-cred` | - | string | - | Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS) |
| `--oauth-token` | - | string | - | Olium Anthropic OAuth bearer token (anthropic-oauth provider; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY) |
| `--output` | `-o` | string | - | Output base path for the --stateless export; each --format appends its own extension (report.html, report.sqlite). Defaults to vigolium-result/vigolium-autopilot. Only applies with -S/--stateless. |
| `--piolium` | - | string | - | Nested piolium audit harness (needs --source): lite, balanced, deep, longshot, etc. Default empty = off; set explicitly to run piolium instead of --audit |
| `--plan-file` | - | string | - | Path to a plan file mixing free-text guidance and raw HTTP request(s). Owns the instruction + seed input; cannot be combined with --input or a prompt (--prompt / positional) |
| `--post-halt-gap-threshold` | - | int | `0` | Minimum new (method, URL) routes the post-halt probe must turn up before the agent is re-entered. 0 = built-in default (5) |
| `--preflight-timeout` | - | duration | `0s` | Deadline of the provider preflight ping (0 = agent.olium.preflight_timeout, default 15s; 60s for a local Ollama/LM Studio endpoint) |
| `--prior-context` | - | string | `auto` | Front-load a bounded summary of the traffic + findings already in the project DB so the operator mines them instead of starting from scratch: auto (default; the bounded table when prior data exists), summary (one-line pointer), off |
| `--prompt` | - | string | - | Free-text task guidance for the agent (same as the positional [prompt]; use --plan-file for a whole plan with seed HTTP requests) |
| `--prompt-file` | - | string | - | Read task guidance from a file (same channel as --prompt — its contents flow through credential extraction, so role-tagged accounts become primary/compare sessions). Convenient for long/complex prompts; mutually exclusive with --prompt, the positional [prompt], and --plan-file |
| `--provider` | - | string | - | Olium provider override: openai-codex-oauth \| openai-api-key \| openai-responses \| anthropic-api-key \| anthropic-oauth \| anthropic-cli \| anthropic-claude-sdk-bridge \| anthropic-vertex \| google-vertex \| openai-compatible \| anthropic-compatible (default: agent.olium.provider; auto-detected when unset) |
| `--record-uuid` | - | string | - | Use an HTTP record from the database as the seed input (UUID or unique 8+ char prefix) |
| `--resume` | - | string | - | Resume a previous durable-autopilot run by its agentic-scan UUID: reuses its session dir, project, target, and durable scratchpad/candidates; skips pre-scan and audit re-prep (requires agent.olium.autopilot_mode != legacy) |
| `--session-dir` | - | string | - | Explicit session directory for this run's debug artifacts (transcript.jsonl, runtime.log, scratchpad, tool-results). Default: <agent.sessions_dir>/<run-uuid>. Pin it to know exactly where to look when debugging (e.g. alongside -S/--stateless scans). |
| `--show-prompt` | - | bool | `false` | Print rendered prompt to stderr before executing |
| `--skill` | - | stringSlice | - | Force-load these skills by name, bypassing the pre-flight selection (repeatable or comma-separated) |
| `--skill-tag` | - | stringSlice | - | Force-load every skill carrying one of these tags (e.g. xss,idor) |
| `--source` | - | string | - | Path to application source code for source-aware scanning |
| `--stateless` | `-S` | bool | `false` | Run the whole autopilot into a throwaway temporary database (your project DB is left untouched), then materialize --format outputs from it. Mirrors 'vigolium scan -S'. Not valid with --db or --resume; --db-isolate is ignored alongside it. |
| `--system-prompt` | - | string | - | Replace the built-in autopilot system prompt with this value (full replace; browser section is not auto-appended) |
| `--system-prompt-file` | - | string | - | Path to a file whose contents replace the built-in autopilot system prompt (takes precedence over --system-prompt) |
| `--target` | `-t` | string | - | Target URL (derived from --input if not set) |
| `--token-budget` | - | int64 | `0` | Cap on the operator's cumulative input+output tokens (0 = no cap). Hitting it stops the run: status budget_exhausted, exit 5 |
| `--transcript` | - | string | - | After the run, also copy the session's transcript.jsonl to this path. The in-session copy is always kept; this is a convenience for debugging (e.g. keep the transcript when the DB is throwaway). |
| `--triage` | - | bool | `false` | After the scan completes, run an AI triage pass over the findings (confirm real issues vs false positives, written back to finding status) |
| `--upload-results` | - | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |
| `--verbose` | `-v` | bool | `false` | **(overrides the global `--verbose`)** Show a per-tool head/tail preview of each tool result alongside the standard one-liner |

## vigolium agent olium

Usage: `vigolium agent olium [prompt...]`

Launch vigolium — interactive TUI agent (olium engine)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--base-url` | - | string | - | Endpoint URL for openai-compatible provider (e.g. http://localhost:11434/v1 for Ollama); falls back to agent.olium.custom_provider.base_url |
| `--bridge-bin` | - | string | - | Path to the 'vigolium-audit' binary hosting the SDK bridge (anthropic-claude-sdk-bridge provider; default: embedded blob, then PATH) |
| `--claude-bin` | - | string | - | Path to the 'claude' binary (anthropic-cli provider) |
| `--gcp-location` | - | string | - | GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1) |
| `--gcp-project` | - | string | - | GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id) |
| `--llm-api-key` | - | string | - | API key for key-based providers (anthropic-api-key, openai-api-key); else uses ANTHROPIC_API_KEY / OPENAI_API_KEY env |
| `--model` | - | string | - | Model id (provider-specific default if empty) |
| `--oauth-cred` | - | string | - | Path to OAuth/SA credential file (openai-codex-oauth: ~/.codex/auth.json; anthropic-vertex/google-vertex: SA JSON or $GOOGLE_APPLICATION_CREDENTIALS) |
| `--oauth-token` | - | string | - | Anthropic OAuth bearer token (anthropic-oauth; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY) |
| `--prompt` | `-p` | string | - | Run one prompt non-interactively and stream to stdout (skips the TUI). Pass '-' to read the prompt from stdin |
| `--provider` | - | string | - | Olium provider override: openai-codex-oauth \| openai-api-key \| openai-responses \| anthropic-api-key \| anthropic-oauth \| anthropic-cli \| anthropic-claude-sdk-bridge \| anthropic-vertex \| google-vertex \| openai-compatible \| anthropic-compatible (default: agent.olium.provider; auto-detected when unset); default openai-compatible |
| `--stdin` | - | bool | `false` | Force reading prompt from stdin |
| `--system` | - | string | - | Override system prompt |

## vigolium agent query

Usage: `vigolium agent query [prompt]`

Send a prompt to an AI agent and get a response

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent-label` | - | string | - | Label recorded on the AgenticScan DB row; agent dispatch always uses olium |
| `--append` | - | string | - | Append extra text to the rendered prompt |
| `--base-url` | - | string | - | Endpoint URL for openai-compatible provider (e.g. http://localhost:11434/v1); falls back to agent.olium.custom_provider.base_url |
| `--dry-run` | - | bool | `false` | Print the rendered prompt without executing |
| `--files` | - | stringSlice | - | Specific files to include (relative to --source) |
| `--gcp-location` | - | string | - | GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1) |
| `--gcp-project` | - | string | - | GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id) |
| `--instruction` | - | string | - | Custom instruction to guide the agent (appended to prompt) |
| `--instruction-file` | - | string | - | Path to a file containing custom instructions |
| `--llm-api-key` | - | string | - | Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var) |
| `--max-duration` | - | duration | `5m0s` | Maximum wall-clock time for agent execution (0 = no limit) |
| `--model` | - | string | - | Olium model id override (falls back to agent.olium.model) |
| `--no-preflight` | - | bool | `false` | Skip the provider preflight ping (a missing or broken provider then fails on the first real call) |
| `--oauth-cred` | - | string | - | Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS) |
| `--oauth-token` | - | string | - | Olium Anthropic OAuth bearer token (anthropic-oauth provider; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY) |
| `--output` | - | string | - | Write agent output to this file |
| `--preflight-timeout` | - | duration | `0s` | Deadline of the provider preflight ping (0 = agent.olium.preflight_timeout, default 15s; 60s for a local Ollama/LM Studio endpoint) |
| `--prompt` | `-p` | string | - | Prompt text to send to the agent |
| `--prompt-file` | - | string | - | Path to a prompt template file |
| `--prompt-template` | - | string | - | Prompt template ID (e.g. security-code-review) |
| `--provider` | - | string | - | Olium provider override: openai-codex-oauth \| openai-api-key \| openai-responses \| anthropic-api-key \| anthropic-oauth \| anthropic-cli \| anthropic-claude-sdk-bridge \| anthropic-vertex \| google-vertex \| openai-compatible \| anthropic-compatible (default: agent.olium.provider; auto-detected when unset) |
| `--show-prompt` | - | bool | `false` | Print rendered prompt to stderr before executing |
| `--source` | - | string | - | Path to source code repository |
| `--source-label` | - | string | - | Label for records ingested from agent output (e.g. 'agent-review') |
| `--stdin` | - | bool | `false` | Read prompt from stdin |
| `--upload-results` | - | bool | `false` | Upload session bundle to cloud storage after completion (requires storage config) |
| `--verbose` | `-v` | bool | `false` | **(overrides the global `--verbose`)** Show a per-tool head/tail preview of each tool result alongside the standard one-liner |

## vigolium agent session

Usage: `vigolium agent session [uuid]`

Aliases: `sessions`, `sess`

List agent run sessions or show session details

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--full` | - | bool | `false` | Show full raw output (shortcut for --tail -1) |
| `--limit` | `-n` | int | `50` | Maximum number of records to display |
| `--mode` | - | string | - | Filter by mode (query, autopilot, pipeline, swarm) |
| `--no-tui` | - | bool | `false` | Force TUI off (escape hatch if TUI ever becomes default) |
| `--offset` | - | int | `0` | Number of records to skip |
| `--tail` | - | int | `50` | Number of raw output lines to show (0=none, -1=all) |
| `--tui` | - | bool | `false` | Open interactive TUI (arrow keys to navigate, enter to view details, c to copy id) |

## vigolium agent swarm

Usage: `vigolium agent swarm [prompt]`

Agentic scan: AI-guided targeted vulnerability swarm

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent-label` | - | string | - | Label recorded on the AgenticScan DB row; agent dispatch always uses olium |
| `--all-records` | - | bool | `false` | Use every HTTP record in the active project as input |
| `--audit` | - | string | `off` | Nested vigolium-audit harness run alongside the swarm (launches a claude/codex CLI; needs --source): lite (3-phase, bare --audit), balanced (9-phase), deep (12-phase), or off. Default off: the intensity preset never turns it on |
| `--auth-config` | - | string | - | Path to an existing agent-format auth-config.yaml (a native session file is detected and loaded as --auth-file). Skips both browser auth and --cookie/--header/--login-curl synthesis. Mutually exclusive with --auth-file. |
| `--auth-file` | - | stringArray | - | Native session file, as 'vigolium scan --auth-file' takes (YAML/JSON, single session or sessions: bundle; login flows, steps, OAuth2, check/reauth), or a bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal. Skips both browser auth and --cookie/--header/--login-curl synthesis. Mutually exclusive with --auth-config. |
| `--base-url` | - | string | - | Endpoint URL for openai-compatible / anthropic-compatible provider (e.g. http://localhost:11434/v1); falls back to agent.olium.custom_provider.base_url |
| `--batch-concurrency` | - | int | `0` | Max parallel master agent batches (0 = auto, scales with CPU count) |
| `--browser-auth` | - | bool | `false` | Run the browser-based auth phase before discovery |
| `--code-audit` | - | bool | `false` | Enable AI security code audit phase (on by default when --source is provided, use --code-audit=false to disable) |
| `--cookie` | - | stringArray | - | Session cookie name=value pair (repeatable; e.g. --cookie 'session=abc123'). Injected into recon, discovery, and scan as Cookie: header. Commas are literal. |
| `--db-isolate` | - | bool | `false` | Run into a private temporary database, then merge results into --db (or the default DB) at the end — lets parallel runs share one --db without write contention (SQLite only) |
| `--diff` | - | string | - | Focus on changed code: PR URL (github.com/.../pull/123), git ref range (main...branch), or HEAD~N |
| `--disable-guardrail` | - | bool | `false` | Skip the prompt-safety classifier on the natural-language prompt (use only when refusing a known-good prompt) |
| `--discover` | - | bool | `false` | Run discovery+spidering before master agent planning to expand attack surface |
| `--dry-run` | - | bool | `false` | Render prompts without executing: no request to the target (no probe, discovery, recon or scan) and no provider call (a natural-language prompt is not parsed) |
| `--files` | - | stringSlice | - | Specific source files to include (relative to --source) |
| `--gcp-location` | - | string | - | GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1) |
| `--gcp-project` | - | string | - | GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id) |
| `--header` | `-H` | stringArray | - | Inject HTTP header into recon, discovery, and scan (repeatable; e.g. -H 'Authorization: Bearer xxx'). Commas are literal. |
| `--input` | - | string | - | Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped |
| `--intensity` | - | string | `balanced` | Scan intensity preset: quick, balanced, or deep |
| `--last-commits` | - | int | `0` | Focus on last N commits (shorthand for --diff HEAD~N) |
| `--llm-api-key` | - | string | - | Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var) |
| `--login-curl` | - | string | - | Curl command for login flow; replayed by the auth runtime to capture a fresh session. Cookies/headers from a successful response are reused for the scan. |
| `--master-batch-size` | - | int | `0` | Max records per master agent batch (0 = default 5) |
| `--max-commands` | - | int | `0` | Tool-call budget across every agent call of the run (0 = no cap). Hitting it stops the run: status budget_exhausted, exit 5 |
| `--max-cost-usd` | - | float64 | `0` | Cap on the run's estimated spend in USD across every agent call (0 = no cap). Hitting it stops the run: status budget_exhausted, exit 5 |
| `--max-duration` | - | duration | `12h0m0s` | Maximum swarm duration (0 = unlimited; e.g. 6h, 24h) |
| `--max-iterations` | - | int | `3` | Maximum triage-rescan iterations |
| `--max-master-retries` | - | int | `3` | Max master agent retries on parse failure |
| `--max-plan-records` | - | int | `25` | Max records sent to plan agent (selects most interesting with one slot per URL prefix; 0 = no limit). Defaults are overridden by --intensity: quick=10, balanced=25, deep=50. |
| `--max-probe-body` | - | int | `0` | Max response body size in bytes during probing (0 = default 2MB) |
| `--model` | - | string | - | Olium model id override (falls back to agent.olium.model) |
| `--modules` | `-m` | stringSlice | - | Explicit module names to include |
| `--no-preflight` | - | bool | `false` | Skip the provider preflight ping (a missing or broken provider then fails on the first real call) |
| `--no-skill-filter` | - | bool | `false` | Load the full skill set into triage; ignore planner selection |
| `--oauth-cred` | - | string | - | Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS) |
| `--oauth-token` | - | string | - | Olium Anthropic OAuth bearer token (anthropic-oauth; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY) |
| `--only` | - | string | - | Run only this scanning phase (discovery, spidering, spa, dynamic-assessment, external-harvest) |
| `--piolium` | - | string | - | Nested piolium audit harness (Pi runtime; launches a pi CLI; needs --source): lite, balanced, deep, longshot, etc. Default empty = off; an installed pi is never picked automatically |
| `--plan-file` | - | string | - | Path to a plan file mixing free-text guidance and raw HTTP request(s). Every request block becomes a seed input; cannot be combined with --input or a prompt (--prompt / positional) |
| `--preflight-timeout` | - | duration | `0s` | Deadline of the provider preflight ping (0 = agent.olium.preflight_timeout, default 15s; 60s for a local Ollama/LM Studio endpoint) |
| `--probe-concurrency` | - | int | `0` | Max parallel probe requests (0 = default 10) |
| `--probe-timeout` | - | duration | `0s` | Per-request probe timeout (0 = default 10s) |
| `--profile` | - | string | - | Scanning profile to use |
| `--prompt` | - | string | - | Free-text task guidance for the agent (same as the positional [prompt]; use --plan-file for a whole plan with seed HTTP requests) |
| `--prompt-file` | - | string | - | Read task guidance from a file (same channel as --prompt). Convenient for long/complex prompts; mutually exclusive with --prompt, the positional [prompt], and --plan-file |
| `--provider` | - | string | - | Olium provider override: openai-codex-oauth \| openai-api-key \| openai-responses \| anthropic-api-key \| anthropic-oauth \| anthropic-cli \| anthropic-claude-sdk-bridge \| anthropic-vertex \| google-vertex \| openai-compatible \| anthropic-compatible (default: agent.olium.provider; auto-detected when unset) |
| `--record-uuid` | - | stringSlice | - | HTTP record UUID or unique 8+ char prefix from the database (repeatable, or comma-separated) |
| `--records-from` | - | string | - | Filter ingested HTTP records by spec (e.g. "host=example.com,status=200,method=GET,path=/api,since=2026-04-01") |
| `--show-prompt` | - | bool | `false` | Print rendered prompts to stderr before executing |
| `--skill` | - | stringSlice | - | Force-load these skills by name into triage, bypassing planner selection (repeatable or comma-separated) |
| `--skill-tag` | - | stringSlice | - | Force-load every skill carrying one of these tags into triage (e.g. xss,idor) |
| `--skip` | - | stringSlice | - | Skip specific phases (recon, discovery, spidering, spa, dynamic-assessment, external-harvest, triage, rescan) |
| `--source` | - | string | - | Path to application source code for route discovery |
| `--source-analysis-only` | - | bool | `false` | Run only the source analysis phase and exit |
| `--start-from` | - | string | - | Resume from a specific phase (native-normalize, source-analysis, code-audit, native-discover, native-recon, plan, native-extension, native-scan, triage) |
| `--sub-agent-concurrency` | - | int | `3` | Max parallel source analysis sub-agents (routes, auth, extensions) |
| `--target` | `-t` | string | - | Target URL (required when --source is used) |
| `--token-budget` | - | int64 | `0` | Cap on the run's cumulative input+output tokens across every agent call (0 = no cap). Hitting it stops the run: status budget_exhausted, exit 5 |
| `--triage` | - | bool | `false` | Enable AI triage and rescan phases. Intensity preset overrides this: balanced/deep enable triage by default; quick disables it. Use --triage=false to force-disable on balanced/deep. |
| `--upload-results` | - | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |
| `--verbose` | `-v` | bool | `false` | **(overrides the global `--verbose`)** Show a per-tool head/tail preview of each tool result alongside the standard one-liner |
| `--vuln-type` | - | string | - | Vulnerability type focus (e.g. sqli, xss, ssrf) |
| `--with-extensions` | - | bool | `false` | Force the extension agent to run even when the planner decides built-in modules are sufficient (no effect with --dry-run) |

## vigolium agent triage

Usage: `vigolium agent triage [finding-id]`

Confirm a single finding with an AI triager: confirmed, false_positive or inconclusive

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--base-url` | - | string | - | Endpoint URL for openai-compatible / anthropic-compatible provider (e.g. http://localhost:11434/v1); falls back to agent.olium.custom_provider.base_url |
| `--dry-run` | - | bool | `false` | Render the triage prompt and exit without calling the agent or writing to DB |
| `--gcp-location` | - | string | - | GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1) |
| `--gcp-project` | - | string | - | GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id) |
| `--llm-api-key` | - | string | - | Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var) |
| `--max-duration` | - | duration | `5m0s` | Maximum wall-clock time for the triage run (0 = no limit) |
| `--model` | - | string | - | Olium model id override (falls back to agent.olium.model) |
| `--no-preflight` | - | bool | `false` | Skip the provider preflight ping (a missing or broken provider then fails on the first real call) |
| `--no-probe` | - | bool | `false` | Do not contact the target: the agent gets no HTTP, browser or shell tools and decides from the captured traffic (inconclusive when that cannot settle it) |
| `--no-write` | - | bool | `false` | Report the verdict without writing it to the finding (no status, description or history change) |
| `--oauth-cred` | - | string | - | Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS) |
| `--oauth-token` | - | string | - | Olium Anthropic OAuth bearer token (anthropic-oauth; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY) |
| `--preflight-timeout` | - | duration | `0s` | Deadline of the provider preflight ping (0 = agent.olium.preflight_timeout, default 15s; 60s for a local Ollama/LM Studio endpoint) |
| `--provider` | - | string | - | Olium provider override: openai-codex-oauth \| openai-api-key \| openai-responses \| anthropic-api-key \| anthropic-oauth \| anthropic-cli \| anthropic-claude-sdk-bridge \| anthropic-vertex \| google-vertex \| openai-compatible \| anthropic-compatible (default: agent.olium.provider; auto-detected when unset) |
| `--report-only` | - | bool | `false` | Alias for --no-write |
| `--show-prompt` | - | bool | `false` | Print rendered prompt to stderr before executing |
| `--verbose` | `-v` | bool | `false` | **(overrides the global `--verbose`)** Show a per-tool head/tail preview of each tool result |

## vigolium arjun

Usage: `vigolium arjun [vigolium globals] [--] [arjun flags]`

Discover parameters using arjun's argv (routed to `vigolium fuzz --fuzz new-param`)

**Compatibility shim.** This command parses another tool's argv itself rather than through cobra, so it accepts that tool's flags, not the ones listed here. It is a subset: run it with `-h` for what is actually translated.

_No command-specific flags._

## vigolium audit

Run a unified security audit (alias for `vigolium agent audit`)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | - | string | - | [audit] Coding agent for the audit leg: claude or codex. Overrides the agent implied by --provider while keeping its resolved auth. No effect on the piolium leg. |
| `--api-key` | - | string | - | BYOK API key for the run (literal, $ENV_NAME, or @path). claude→ANTHROPIC_API_KEY, codex→OPENAI_API_KEY. Empty inherits agent.olium.* config. Mutually exclusive with --oauth-token / --oauth-cred-file. |
| `--clean-raw` | - | bool | `false` | [audit] Remove <source>/vigolium-results/ from the source tree after the run (the session copy is always kept). Inverts the default --keep-raw retention of the source-folder copy. No effect on the piolium leg. |
| `--commit-depth` | - | int | `1` | git clone --depth value when --source is a git URL (default 1; use 0 for full history; overrides --intensity) |
| `--driver` | - | string | `auto` | Audit driver: auto (run audit; fall back to piolium only when audit cannot start - claude/codex CLI missing, binary not embedded, or no audit-supported mode in the chain), both (audit then piolium), audit, or piolium (default auto) |
| `--intensity` | - | string | `balanced` | Audit intensity preset: quick, balanced, or deep |
| `--interactive` | `-i` | bool | `false` | Drop into the coding agent with the audit harness installed and drive the audit yourself (audit-only; the embedded vigolium-audit binary's -i). Skips NDJSON streaming, the AgenticScan row, and findings auto-import — results land in <source>/vigolium-results/; import them afterward with 'vigolium import'. Not valid with --driver=piolium. |
| `--keep-raw` | - | bool | `true` | [audit] Keep raw scanner output, draft findings, and intermediate workspaces under <source>/vigolium-results/ for manual review (overrides audit's deep/confirm auto-prune). On by default; the source-folder copy is also retained. Pass --clean-raw to remove it from the source tree. No effect on the piolium leg. |
| `--list-modes` | - | bool | `false` | List the available audit modes (audit's mode graph: phases, time estimate, descriptions) and exit |
| `--mode` | - | string | - | Audit mode override (overrides --intensity). Shared modes: lite, balanced, deep, revisit, confirm, merge. Driver-specific: piolium=longshot/smoke/diff/status, audit=reinvest/refresh/mock/diff/status |
| `--modes` | - | string | - | Run a chain of modes back-to-back (comma-separated, e.g. deep,refresh,confirm). Overrides --mode/--intensity. Stops on the first non-complete mode. audit runs the chain natively (--modes); piolium chains via sequential runs collapsed into one row; with driver=auto/both, modes a driver can't run are skipped on that driver's leg. |
| `--no-dedup` | - | bool | `false` | Skip the post-pass project-wide findings dedup that runs after the audit completes |
| `--no-preflight` | - | bool | `false` | Skip the pre-audit roundtrip checks for both drivers (pi+claude auth/model availability) |
| `--no-stream` | - | bool | `false` | Don't echo agent output to the console (still written to {session}/<driver>/runtime.log) |
| `--oauth-cred-file` | - | string | - | BYOK OAuth credential file path (literal or $ENV_NAME). Codex ('~/.codex/auth.json' shape). Staged under <pi-agent-dir>/auth.json with backup-and-restore for piolium runs. Mutually exclusive with --api-key / --oauth-token. |
| `--oauth-token` | - | string | - | BYOK Anthropic OAuth bearer token (literal, $ENV_NAME, or @path). Claude only — produced by 'claude setup-token'. Mutually exclusive with --api-key / --oauth-cred-file. |
| `--output` | `-o` | string | - | HTML report path for --stateless runs (default vigolium-result/vigolium-audit-report.html; supports gs://<project>/<key> and {ts}). Only applies with -S/--stateless. |
| `--output-dir` | - | string | - | Bundle directory for --stateless runs: collects the HTML report (as vigolium-audit-report.html) AND a copy of the raw vigolium-results/ output into one folder. A relative -o/--output is nested under it; an absolute path or gs:// URL wins. The source-tree copy is left in place. Supports {ts}/{project-uuid}. Only applies with -S/--stateless. |
| `--pi-model` | - | string | - | [piolium] Override pi's defaultModel (e.g. claude-opus-5, gemini-3.1-pro) |
| `--pi-provider` | - | string | - | [piolium] Override pi's defaultProvider (e.g. vertex-anthropic, google-vertex) |
| `--plm-command-retries` | - | int | `0` | [piolium] Per-command retry count (0=piolium default) |
| `--plm-longshot-langs` | - | string | - | [piolium] Longshot language allowlist (comma-separated, e.g. python,go) |
| `--plm-longshot-limit` | - | int | `0` | [piolium] Max files hunted in longshot mode (0=piolium default) |
| `--plm-longshot-timeout` | - | int | `0` | [piolium] Per-file kill timer in longshot mode in ms (0=piolium default) |
| `--plm-phase-retries` | - | int | `0` | [piolium] Per-phase retry count (0=piolium default) |
| `--plm-scan-limit` | - | int | `0` | [piolium] Cap commit-history scan to N commits (0=piolium default) |
| `--plm-scan-since` | - | string | - | [piolium] Cap commit-history scan to a git --since window (e.g. "60 days ago") |
| `--preflight-timeout` | - | duration | `30s` | Per-driver preflight timeout (e.g. 30s, 1m); applies to both pi and claude |
| `--provider` | - | string | - | [audit] Olium provider hint to drive audit's --agent: anthropic-* → claude, openai-* → codex (also forwards that provider's BYOK auth). Empty inherits agent.olium.provider. For a pure agent switch without changing auth, prefer --agent. |
| `--show-thinking` | - | bool | `false` | Render the agent's internal thinking blocks (audit NDJSON 'thinking' events) in the live stream. Off by default — thinking is verbose and produces many lines per phase. |
| `--source` | - | string | - | Source to audit (required): local directory (pass --source . for the current directory), git URL, gs://<project>/<key> archive, or local .zip/.tar.gz |
| `--stateless` | `-S` | bool | `false` | Run the audit into a throwaway temporary database (the main DB is left untouched) and auto-write a self-contained HTML report. Mirrors 'vigolium scan -S'. Not valid with --interactive. |
| `--upload-results` | - | bool | `false` | Upload session bundle to cloud storage after completion (requires storage config) |

## vigolium auth

Authentication management utilities

_No command-specific flags._

## vigolium auth check

Usage: `vigolium auth check <session-file|session-name> [--url <protected-url>]`

Check that a session is really logged in on a protected URL

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--method` | - | string | - | HTTP method for the check request (default: check.method, then GET) |
| `--session` | - | string | - | Check only this session from a multi-session file |
| `--timeout` | - | duration | `30s` | Timeout for each login and check request |
| `--url` | - | string | - | Protected URL to check (default: the session's check.url, then scanning_strategy.session.validate_url) |

## vigolium auth lint

Usage: `vigolium auth lint [session-file...]`

Validate session auth config files for errors and warnings

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--stdin` | - | bool | `false` | Read session config from stdin |

## vigolium auth list

Aliases: `ls`

List session authentication configs

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--host` | - | string | - | Filter by hostname |
| `--show-secrets` | - | bool | `false` | Reveal session tokens, auth headers, and login request/body values in plaintext instead of [redacted]; prints a warning to stderr |

## vigolium auth load

Usage: `vigolium auth load [session-file]`

Load session auth configs from a file or stdin into the database

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent-format` | - | bool | `false` | Force parsing as agent session-config.json format |
| `--force` | - | bool | `false` | **(overrides the global `--force`)** Save sessions whose login check failed (still exits 1) |
| `--host` | - | string | - | Hostname to associate sessions with (derived from login URL if omitted) |
| `--name` | - | string | - | Session name (used with raw HTTP request input) |
| `--no-validate` | - | bool | `false` | Skip executing login flows for validation |
| `--source` | - | string | `cli` | Source label for the session rows |
| `--timeout` | - | duration | `30s` | Timeout for each login request |

## vigolium auth totp

Generate a TOTP code from a base32 secret

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--secret` | - | string | - | Base32 TOTP secret, or - to read it from stdin (a literal value is visible in the process list; prefer --secret-env/--secret-file) |
| `--secret-env` | - | string | `VIGOLIUM_TOTP_SECRET` | Environment variable holding the base32 TOTP secret |
| `--secret-file` | - | string | - | File holding the base32 TOTP secret |

## vigolium config

Manage configuration

_No command-specific flags._

## vigolium config clean

Reset Vigolium to a clean state

_No command-specific flags._

## vigolium config ls

Usage: `vigolium config ls [filter]`

Aliases: `list`, `view`

Display current configuration

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--show-secrets` | - | bool | `false` | Reveal sensitive values (API keys, tokens, credentials) in plaintext instead of [redacted]; prints a warning to stderr |

## vigolium config set

Usage: `vigolium config set <key> <value>`

Set a configuration value

_No command-specific flags._

## vigolium config validate

Check the configuration for values that break or silently weaken scans

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--project` | - | string | - | Also validate this project's config overlay, checking the merged global → project settings |
| `--recent` | - | int | `5` | Check a wildcard-free scope.host.include against the targets of the last N scans (0 disables) |
| `--strict` | - | bool | `false` | Exit 1 on warnings as well as errors |

## vigolium db

Manage database records

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--search` | - | string | - | Quick search across record fields (URLs, paths, descriptions) |
| `--table` | - | string | - | Database table to operate on (http_records, findings, scans) |
| `--watch` | - | string | - | Re-run on interval (e.g. 10s, 1m, 5m) |

## vigolium db clean

Clean database records

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all` | - | bool | `false` | Delete every row from all data tables (requires --force unless --dry-run) |
| `--before` | - | string | - | Delete records created strictly before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 (the named day itself is kept) |
| `--dry-run` | - | bool | `false` | Show what would be deleted without deleting |
| `--findings-only` | - | bool | `false` | Delete findings only, keep HTTP records |
| `--host` | - | string | - | Delete records matching the specified hostname |
| `--orphans` | - | bool | `false` | Delete findings with no matching HTTP record |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Delete records belonging to the specified scan UUID |
| `--severity` | - | string | - | Delete findings matching the specified severity level (findings only; HTTP records are kept) |
| `--status` | - | intSlice | - | Delete records with matching HTTP status codes |
| `--table` | - | string | - | Delete all rows from a specific table (e.g., http_records, findings, scans) |

## vigolium db compact

Shrink stored bodies over a size limit to their head, keeping every record

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all-projects` | - | bool | `false` | Compact records of every project in the database (default: the active project only) |
| `--body-over` | - | string | `64k` | Compact a request or response body larger than this size |
| `--dry-run` | - | bool | `false` | Report what would be compacted without changing anything |
| `--keep-head` | - | string | `4k` | Bytes of each compacted body to keep (must be smaller than --body-over) |
| `--max-db-size` | - | string | - | Size budget: compact the oldest records first until the database is at most this size after VACUUM |
| `--no-vacuum` | - | bool | `false` | Skip the VACUUM that returns freed pages to the filesystem |
| `--older-than` | - | string | - | Compact only records sent strictly before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 |
| `--only-content-type` | - | stringSlice | - | Compact only records whose response media type matches one of these globs (OR'ed with --only-path) |
| `--only-path` | - | stringSlice | - | Compact only records whose URL path matches one of these globs (OR'ed with --only-content-type) |
| `--skip-content-type` | - | stringSlice | - | Never compact a record whose response media type matches one of these globs (e.g. '*javascript*') |
| `--skip-path` | - | stringSlice | - | Never compact a record whose URL path matches one of these globs (e.g. '*.js') |

## vigolium db export

Export database records

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | string | `jsonl` | **(overrides the global `--format`)** Export format: jsonl, json, raw, markdown (alias: md), markdown-table (alias: md-table), csv, bundle (alias: gz), fs (alias: file-system; flat traffic/finding tree) |
| `--from` | - | string | - | Export records at or after this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 (alias: --since) |
| `--host` | - | string | - | Filter records by hostname pattern |
| `--limit` | - | int | `0` | Maximum number of records to export, 0 for unlimited |
| `--method` | - | stringSlice | - | Filter records by HTTP method (can be specified multiple times) |
| `--offset` | - | int | `0` | Number of records to skip before exporting |
| `--output` | `-o` | string | - | Output file path, defaults to stdout |
| `--path` | - | string | - | Filter records by URL path pattern |
| `--report-url` | - | string | - | URL for the "Raw Report URL" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL) |
| `--request-only` | - | bool | `false` | Export only HTTP requests, omitting responses (raw format only) |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Filter records by scan UUID |
| `--severity` | - | string | - | Filter findings by severity level |
| `--status` | - | intSlice | - | Filter records by HTTP status code (can be specified multiple times) |
| `--to` | - | string | - | Export records at or before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339; a bare date covers the whole day (alias: --until) |
| `--uuid` | - | string | - | Export exactly one record by its UUID (or unique 8+ char prefix). Honored by every --format (including fs) and resolved before pagination, so a record outside the --limit window is still found |

## vigolium db list

Usage: `vigolium db list [table]`

Aliases: `ls`

List database records (default: http_records)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--asc` | - | bool | `false` | Sort in ascending order instead of descending |
| `--body` | - | string | - | Search only the HTTP request/response body (not headers); use --search to span the whole exchange |
| `--columns` | - | stringSlice | - | Columns to include in output, comma-separated |
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--finding-source` | - | string | - | Filter findings by source (dynamic-assessment, spa, agent, oast, source-tools, extension) |
| `--from` | - | string | - | Show records at or after this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 (alias: --since) |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--header` | - | string | - | Search only the HTTP header block of the request/response (not bodies); use --search to span the whole exchange |
| `--host` | - | string | - | Filter records by hostname pattern (wildcard supported) |
| `--limit` | `-n` | int | `100` | Maximum number of records to display |
| `--list-columns` | - | bool | `false` | List column names for the current table |
| `--list-tables` | - | bool | `false` | List all database table names |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--method` | - | stringSlice | - | Filter records by HTTP method (can be specified multiple times) |
| `--min-risk` | - | int | `0` | Show only records with risk score at or above this value |
| `--min-surface` | - | int | `0` | Show only records with attack-surface score at or above this value (0-100, percent of the attack-surface signals present) |
| `--module-type` | - | string | - | Filter findings by module type (active, passive, nuclei, agent, source-tools, oast, extension) |
| `--offset` | - | int | `0` | Number of records to skip before displaying |
| `--output` | `-o` | string | - | With --json: write the result document to this file and print a receipt instead; '-' forces stdout |
| `--path` | - | string | - | Filter records by URL path pattern |
| `--raw` | - | bool | `false` | Show full raw HTTP request and response |
| `--record-kind` | - | string | - | Filter by record kind (finding, candidate, observation; comma-separated). Default: finding |
| `--remark` | - | string | - | Filter records containing this text in remarks |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Filter records by scan UUID |
| `--severity` | - | string | - | Filter findings by severity: critical,high,medium,low,suspect,info (comma-separated; single-letter shorthands ok, e.g. 'h,c') |
| `--sort` | - | string | `created_at` | Sort results by field: uuid, created_at, sent_at, method, status_code, response_time, risk_score, surface_score |
| `--status` | - | intSlice | - | Filter records by HTTP status code (can be specified multiple times) |
| `--to` | - | string | - | Show records at or before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339; a bare date covers the whole day (alias: --until) |
| `--tree` | - | bool | `false` | Display results in hierarchical tree format |
| `--url` | - | stringArray | - | Select records whose URL matches EXACTLY (repeatable; OR-ed). Compared against the stored URL with no normalization — use --path or --search for substring matching |
| `--uuid` | - | stringSlice | - | Select exact stored record(s) by UUID or unique 8+ char prefix (repeatable/comma-separated). Applied before pagination |

## vigolium db migrate

Upgrade the database schema to this vigolium's version

_No command-specific flags._

## vigolium db reset

Delete and recreate the database from scratch (SQLite only)

_No command-specific flags._

## vigolium db seed

Populate database with sample data for development and testing

_No command-specific flags._

## vigolium db stats

Show database statistics

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--detailed` | - | bool | `false` | Show per-host and per-module breakdown |
| `--host` | - | string | - | Show statistics for a specific hostname |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Show statistics for a specific scan UUID |

## vigolium dig

Usage: `vigolium dig [vigolium globals] [--] [dig flags]`

Resolve names using dig's argv (routed to `vigolium dns`, which stores the answers)

**Compatibility shim.** This command parses another tool's argv itself rather than through cobra, so it accepts that tool's flags, not the ones listed here. It is a subset: run it with `-h` for what is actually translated.

_No command-specific flags._

## vigolium dns

Usage: `vigolium dns [name|url ...]`

Resolve names (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA) and store the answers

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--compact` | - | bool | `false` | With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata |
| `--concurrency` | `-c` | int | `10` | Names resolved in parallel |
| `--fields` | - | stringSlice | - | Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop |
| `--ignore-scope` | - | bool | `false` | Resolve names outside the configured host scope |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--no-header` | - | bool | `false` | With --format tsv, omit the header line |
| `--no-store` | - | bool | `false` | Print the answers without storing them |
| `--resolver` | - | stringArray | - | Resolver host[:port] to ask (repeatable; default the system resolver) |
| `--target` | `-t` | stringArray | - | Name or URL to resolve (repeatable) |
| `--target-file` | `-T` | stringArray | - | File of names or URLs, one per line (repeatable) |
| `--timeout` | - | duration | `5s` | Per-query timeout |
| `--type` | - | stringSlice | - | Record types (comma-separated): a, aaaa, cname, mx, ns, txt, soa, caa (default all) |

## vigolium doctor

Check system readiness and diagnose configuration issues

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--fix` | - | bool | `false` | Auto-install/fix failing checks |
| `--for` | - | string | - | Scope the verdict to one purpose: scan\|agent\|server (checks that do not affect it are reported but not counted) |
| `--only` | - | stringSlice | - | Fix only specific items (nuclei,chrome,bun,claude,agent-browser,pi,piolium,skill) |
| `--stateless` | `-S` | bool | `false` | With --for scan: the scan will use a temporary database, so the database check is skipped |
| `--strict` | - | bool | `false` | Exit 1 when the verdict is degraded, not only when it is not_ready |
| `--target` | `-t` | string | - | With --for scan: also check DNS, TCP and TLS reachability of this URL |
| `--yes` | `-y` | bool | `false` | With --fix: also run vendor installers piped into a shell and global agent tooling installs (bun, claude, agent-browser, pi, piolium) without asking |

## vigolium endpoints

Usage: `vigolium endpoints [search-term]`

Aliases: `endpoint`

List endpoints (origin + path template) aggregated from stored traffic

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--collapse` | - | int | `0` | Merge N or more sibling literal segments sharing the same child templates into {var} (0 = off; >= 2) |
| `--compact` | - | bool | `false` | With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata |
| `--fields` | - | stringSlice | - | Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop |
| `--from` | - | string | - | Only records sent at or after this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 (alias: --since) |
| `--glob-db` | - | string | - | Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S |
| `--glob-strict` | - | bool | `false` | Fail the read on the first --glob-db source that cannot be imported, instead of skipping it with a warning |
| `--host` | - | string | - | Filter by hostname pattern (wildcard supported) |
| `--limit` | `-n` | int | `100` | Maximum endpoints to list (0 = all); the aggregate always covers every matched record |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--method` | - | stringSlice | - | Filter by HTTP method (repeatable) |
| `--min-records` | - | int64 | `0` | Only endpoints seen in at least this many records |
| `--no-header` | - | bool | `false` | With --format tsv, omit the header line |
| `--offset` | - | int | `0` | Number of endpoints to skip (for pagination) |
| `--output` | `-o` | string | - | With --json: write the result document to this file and print a receipt instead; '-' forces stdout |
| `--path` | - | string | - | Filter by URL path pattern (wildcard supported) |
| `--remark` | - | stringArray | - | Keep records carrying a remark containing this text (repeatable, AND-combined; e.g. --remark jstangle: for JS-derived records, --remark jstangle:not_found) |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Only records first stored by this scan (http_records.scan_uuid; records deduplicated against an earlier scan keep that scan's uuid) |
| `--sort` | - | string | `records` | Sort by: records, findings, template, last_seen |
| `--source` | - | string | - | Filter by record source (e.g. scanner, deparos, jstangle, html-form, api-spec, ingest-cli, ingest-proxy) |
| `--stateless` | `-S` | bool | `false` | Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB |
| `--status` | - | intSlice | - | Filter by HTTP status code (repeatable) |
| `--to` | - | string | - | Only records sent at or before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339; a bare date covers the whole day (alias: --until) |

## vigolium export

Export database tables and module registry

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--exclude` | - | stringSlice | `[module]` | Exclude items by type (comma-separated, e.g. module,scan) |
| `--format` | - | string | `jsonl` | **(overrides the global `--format`)** Export format(s), comma-separated: jsonl, html, report, pdf (headless Chrome), markdown (alias: md), sarif (SARIF 2.1.0), csv, junit (failures at/above --fail-on), github (workflow commands; stdout without -o), bundle (alias: gz), fs (alias: file-system; flat traffic/finding tree) |
| `--glob-db` | - | string | - | Export across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S |
| `--glob-strict` | - | bool | `false` | Fail the read on the first --glob-db source that cannot be imported, instead of skipping it with a warning |
| `--limit` | - | int | `0` | Maximum number of records to export per table (0 = unlimited) |
| `--max-body-bytes` | - | int | `4096` | Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap |
| `--no-redact` | - | bool | `false` | Keep credential headers, cookie values and sensitive query parameters in HTML/PDF/SARIF/Markdown report evidence (redacted by default; also output.redact_evidence: false). JSONL and the database always keep the raw exchange |
| `--no-url-dedup` | - | bool | `false` | Emit every stored HTTP exchange; by default exchanges sharing a URL collapse to the first one (plus any a finding links to) |
| `--omit-response` | - | bool | `false` | Omit raw HTTP request/response bytes (keeps metadata, smaller files) |
| `--only` | - | stringSlice | - | Export only these tables (repeatable: http, findings, scans, modules, oast, source-repos, scopes) |
| `--output` | `-o` | string | - | Output file path or gs://<project>/<key> URL (required for html; base path when multiple formats are given); supports {ts} and {project-uuid} placeholders |
| `--pdf-timeout` | - | duration | `0s` | Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else 1m30s) |
| `--report-duration` | - | string | - | Human-readable scan duration for the report (e.g. "10h42m5s") |
| `--report-generated-at` | - | string | - | ISO timestamp for report generation (e.g. "2026-04-18T03:00:00Z") |
| `--report-target` | - | string | - | Target name for the report (e.g. repository name or URL) |
| `--report-title` | - | string | - | Custom title for the HTML report (default: "Vigolium Static Report") |
| `--report-url` | - | string | - | URL for the "Raw Report URL" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL) |
| `--scan-uuid` | - | stringSlice | - | **(overrides the global `--scan-uuid`)** Agentic scan UUID(s) whose session directories to include in --format bundle (repeatable) |
| `--search` | - | string | - | Fuzzy search filter across URLs, paths, hostnames, methods, content types, and sources |
| `--severity` | - | string | - | Filter findings by severity (comma-separated: critical,high,medium,low,info) |
| `--stateless` | `-S` | bool | `false` | Read from --db (a standalone .sqlite or .jsonl export) instead of your project DB; never writes to it |

## vigolium extensions

Usage: `vigolium extensions [filter]`

Aliases: `ext`

Manage JavaScript extensions

_No command-specific flags._

## vigolium extensions docs

Usage: `vigolium extensions docs [function]`

Aliases: `doc`, `api`

Show extension API reference with examples

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--example` | - | bool | `false` | Show usage examples for each function |

## vigolium extensions eval

Usage: `vigolium extensions eval [code]`

Aliases: `exec`

Evaluate JavaScript code with vigolium.* APIs available

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--allow-network` | - | bool | `false` | Let the extension send requests (default: every request fails and is counted) |
| `--ext-file` | - | string | - | Path to JS file to evaluate |
| `--handler` | - | string | - | Handler to call: scanPerRequest, scanPerHost or scanPerInsertionPoint (default: every handler the module declares) |
| `--insertion` | - | string | - | Insertion point for scanPerInsertionPoint as TYPE:name, e.g. URL_PARAM:id (default: every point) |
| `--record-uuid` | - | string | - | Stored HTTP record to run the extension against (UUID or unique prefix; see vigolium traffic) |
| `--stdin` | - | bool | `false` | Read JS code from stdin |
| `--timeout` | - | duration | `30s` | Execution timeout |

## vigolium extensions example

Usage: `vigolium extensions example [filter]`

Aliases: `examples`, `templates`, `tpl`

Print copy-pasteable example extensions in every supported format

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--lang` | - | string | - | Restrict to one language: javascript (js), yaml, or json |
| `--list` | `-l` | bool | `false` | Print only the catalog index (keys + titles), no code |

## vigolium extensions lint

Usage: `vigolium extensions lint [file-or-directory]`

Validate extension files for syntax errors and unknown API calls

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--stdin` | - | bool | `false` | Read extension source from stdin |
| `--stdin-kind` | - | string | - | Language of --stdin source: js, ts or yaml (default: sniffed — a top-level id:/type: YAML map without module.exports is yaml) |
| `--strict` | - | bool | `false` | Treat warnings as errors (exit 1 on any issue) |

## vigolium extensions ls

Usage: `vigolium extensions ls [filter]`

Aliases: `list`

List loaded extensions

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--type` | - | string | `all` | Filter by type: all, active, passive, pre_hook, post_hook |
| `--verbose` | `-v` | bool | `false` | **(overrides the global `--verbose`)** Show long description and confirmation criteria per extension |

## vigolium extensions preset

Usage: `vigolium extensions preset [name]`

Aliases: `presets`, `init`

Install example extension presets into extensions directory

_No command-specific flags._

## vigolium extensions run

Usage: `vigolium extensions run [file]`

Run one extension against a stored record (offline unless --allow-network)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--allow-network` | - | bool | `false` | Let the extension send requests (default: every request fails and is counted) |
| `--handler` | - | string | - | Handler to call: scanPerRequest, scanPerHost or scanPerInsertionPoint (default: every handler the module declares) |
| `--insertion` | - | string | - | Insertion point for scanPerInsertionPoint as TYPE:name, e.g. URL_PARAM:id (default: every point) |
| `--record-uuid` | - | string | - | Stored HTTP record to run the extension against (UUID or unique prefix; see vigolium traffic) |

## vigolium extensions test

Usage: `vigolium extensions test <dir|file>`

Run extensions against their fixture cases (offline; active ones against a local mock)

_No command-specific flags._

## vigolium extensions types

Print or write vigolium.d.ts, the extension API type declarations

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | - | Write the declarations to this file, or to <dir>/vigolium.d.ts when it is a directory (default: stdout) |

## vigolium ffuf

Usage: `vigolium ffuf [vigolium globals] [--] [ffuf flags]`

Content discovery / fuzzing with ffuf's argv (routed to `vigolium run discovery` or `vigolium fuzz`)

**Compatibility shim.** This command parses another tool's argv itself rather than through cobra, so it accepts that tool's flags, not the ones listed here. It is a subset: run it with `-h` for what is actually translated.

_No command-specific flags._

## vigolium finding

Usage: `vigolium finding [search-term]`

Aliases: `findings`

Browse vulnerability findings with fuzzy search and filtering

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agentic-scan` | - | string | - | Filter by agentic-scan UUID (findings produced by an agent autopilot/swarm/audit run) |
| `--asc` | - | bool | `false` | Sort in ascending order (default: descending) |
| `--body` | - | string | - | Search only the linked request/response body (not headers); use --search to span the whole exchange |
| `--burp` | - | bool | `false` | Display in Burp Suite-style format (colored request/response) |
| `--burp-bridge-url` | `-B` | string | - | Loopback Burp/Caido bridge URL used by --push-to-burp / --to-repeater (alias: --caido-bridge-url) |
| `--columns` | - | stringSlice | - | Columns to show (comma-separated, e.g. ID,SEVERITY,MODULE) |
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--confidence` | - | string | - | Filter by confidence: certain,firm,tentative (comma-separated) |
| `--curl` | - | bool | `false` | Render each selected finding's proving request (its stored evidence, else its first linked record) as a curl command; -j gives {id, finding_hash, record_uuid, curl, argv} |
| `--curl-all` | - | bool | `false` | Like --curl, but render every HTTP record linked to each finding |
| `--exclude-body` | - | string | - | Exclude findings whose linked request/response body contains the term (inverse of --body; bodies only) |
| `--exclude-columns` | - | stringSlice | - | Columns to hide (comma-separated) |
| `--exclude-header` | - | string | - | Exclude findings whose linked request/response header block contains the term (inverse of --header; headers only) |
| `--exclude-search` | - | stringArray | - | Exclude findings where the term appears in the module metadata, matched location, or linked request/response (repeatable; dropped if ANY term matches — the inverse of --search) |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--finding-source` | - | string | - | Filter by finding source (dynamic-assessment, spa, agent, oast, source-tools, extension) |
| `--from` | - | string | - | Show findings at or after this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 (alias: --since) |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--glob-db` | - | string | - | Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S |
| `--glob-strict` | - | bool | `false` | Fail the read on the first --glob-db source that cannot be imported, instead of skipping it with a warning |
| `--header` | - | string | - | Search only the HTTP header block of the linked request/response (not bodies); use --search to span the whole exchange |
| `--host` | - | string | - | Filter by hostname pattern (wildcard supported) |
| `--http-mode` | - | string | - | With --send-via-burp: wire protocol — auto\|http1\|http2\|http2_ignore_alpn (default auto) |
| `--id` | - | string | - | Filter by finding ID (the integer from the ID column, e.g. --id 42) |
| `--include-dismissed` | - | bool | `false` | With --new-since: keep findings marked false_positive or accepted_risk |
| `--limit` | `-n` | int | `100` | Maximum findings to display |
| `--markdown` | - | bool | `false` | Render the matched findings as Markdown (evidence + request/response in fenced http blocks) to stdout; response bodies are compacted to a preview by default (use --full-body for whole bodies) |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--method` | - | stringSlice | - | Filter by HTTP method (repeatable) |
| `--min-severity` | - | string | - | Filter by minimum severity (e.g. high → high+critical); ignored when --severity is set |
| `--module-type` | - | string | - | Filter by module type (active, passive, nuclei, agent, source-tools, oast, extension) |
| `--new-since` | - | string | - | Only findings new since a scan (UUID, 8+ char prefix, latest, previous: first observed by a later scan and not by it) or a time (2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339: stored after it). Leaves out false_positive/accepted_risk unless --include-dismissed or --verdict |
| `--no-header` | - | bool | `false` | With --format tsv, omit the header line |
| `--no-tui` | - | bool | `false` | Force TUI off (escape hatch if TUI ever becomes default) |
| `--offset` | - | int | `0` | Number of findings to skip (for pagination) |
| `--output` | `-o` | string | - | With --json: write the result document to this file and print a receipt instead; '-' forces stdout |
| `--path` | - | string | - | Filter by URL path pattern |
| `--pick` | - | string | - | Select finding(s) by 1-based position in the result list (e.g. 2, 1,3, 2-4); applied after --search/filters and sort |
| `--push-to-burp` | - | bool | `false` | Push the selected finding(s)' evidence request+response to Burp's Organizer for manual confirmation; requires --burp-bridge-url |
| `--raw` | - | bool | `false` | Show full raw HTTP request and response for each finding |
| `--record-fields` | - | stringSlice | - | With --with-records: restrict each embedded HTTP record to these keys (independent of --fields) |
| `--record-kind` | - | string | - | Filter by record kind (finding, candidate, observation; comma-separated). Default: finding |
| `--record-limit` | - | int | `20` | With --with-records: max HTTP records embedded per finding (0 = no cap) |
| `--redact-auth` | - | bool | `false` | With --curl/--curl-all: replace Authorization/Cookie/API-key header values with <redacted> |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Filter by scan UUID |
| `--search` | - | stringArray | - | Search across the finding's module metadata, matched location, and the linked request/response (headers + body); repeatable, AND-combined (each term further narrows) |
| `--send-via-burp` | - | bool | `false` | With --push-to-burp/--to-repeater: re-issue the request through Burp's engine and store the fresh response |
| `--severity` | - | string | - | Filter by severity: critical,high,medium,low,suspect,info (comma-separated; single-letter shorthands or any unambiguous prefix ok, e.g. 'h,c' or 'me,info'). Alias: --sev |
| `--sort` | - | string | `found_at` | Sort by: found_at, created_at, severity, module, confidence |
| `--source` | - | string | - | Filter by record source (e.g. scanner, ingest-cli) |
| `--stateless` | `-S` | bool | `false` | Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB |
| `--status` | - | intSlice | - | Filter by HTTP status code (repeatable) |
| `--to` | - | string | - | Show findings at or before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339; a bare date covers the whole day (alias: --until) |
| `--to-repeater` | - | bool | `false` | Also stage the selected finding(s) in a Burp Repeater tab (respects Burp's 30-tabs/min cap). Composes with --push-to-burp, like 'vigolium replay'. |
| `--tree` | - | bool | `false` | Display as a host/path hierarchy tree; repeated titles collapse into one node with each affected URL listed below |
| `--tui` | - | bool | `false` | Open interactive TUI (arrow keys to navigate, enter to view details, c to copy id) |
| `--verdict` | - | string | - | Filter by lifecycle status: draft,triaged,confirmed,false_positive,accepted_risk,fixed (comma-separated; set with 'finding mark') |
| `--with-records` | - | bool | `false` | With --json: resolve and embed the linked HTTP records (self-contained triage bundle) |

## vigolium finding load

Usage: `vigolium finding load [file]`

Import findings from a file or stdin

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--finding-file` | - | string | - | Path to findings file |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Associate imported findings with a scan UUID |

## vigolium finding mark

Usage: `vigolium finding mark <id|hash>... --as <verdict>`

Record a verdict on findings (false_positive, confirmed, accepted_risk, fixed, triaged)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--as` | - | string | - | Verdict to record: false_positive\|confirmed\|accepted_risk\|fixed\|triaged (required) |
| `--by` | - | string | - | Who decided (default "cli") |
| `--note` | - | string | - | Why: stored with the verdict and in the finding's status history |
| `--stateless` | `-S` | bool | `false` | Write to the standalone .sqlite named by --db with project scoping off |

## vigolium finding verify

Usage: `vigolium finding verify <id|hash>... [--scan-uuid <uuid>]`

Re-run a finding's module against its target and record whether it reproduces

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--dry-run` | - | bool | `false` | Print the reconstructed module, baseline request and insertion point; send nothing and write nothing |
| `--fail-if` | - | string | - | Exit 4 when any finding gets one of these verdicts: confirmed,not_reproduced,inconclusive,unsupported (comma-separated) |
| `--mark` | - | bool | `false` | Also set the status: not_reproduced → false_positive, confirmed → confirmed |
| `--no-write` | - | bool | `false` | Run the verification but do not store the verdict |
| `--rate-limit` | - | float64 | `0` | Max requests/second across the verification (0 = unlimited; fractions allowed) |
| `--refetch` | - | bool | `false` | Passive findings: fetch a fresh response instead of re-analyzing the stored one |
| `--stateless` | `-S` | bool | `false` | Use the standalone .sqlite named by --db with project scoping off |
| `--timeout` | - | duration | `2m0s` | Time limit for verifying one finding (one request is capped at 15s) |

## vigolium fingerprint

Usage: `vigolium fingerprint [url ...]`

Fingerprint origins with a bounded set of reads and store the result as host facts

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--advanced-options` | `-a` | stringToString | - | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--allow-risky-payloads` | - | bool | `false` | Allow risk:high payloads and modules below --intensity deep (OR-per-row and stacked time-blind SQLi, so MSSQL time-blind; state-changing probes). Always on at deep. Overrides config dynamic-assessment.allow_risky_payloads |
| `--auth` | - | stringArray | - | Inline session in 'name:Header:value' format. Repeatable; commas are literal (header values may contain commas). |
| `--auth-file` | - | stringArray | - | Path to auth file (YAML/JSON, single session or sessions: bundle), or bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal. |
| `--baseline` | - | string | - | Previous run's findings (.jsonl export or .sqlite store): --fail-on counts only findings not in it; -j adds baseline{new,unchanged,fixed,ignored} |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine: 'chromium', 'ungoogled', or 'fingerprint' |
| `--browser-insecure` | - | bool | `false` | Spider with every browser security exception on: no sandbox, TLS errors ignored, mixed content allowed, same-origin policy off. For local test apps only |
| `--browsers` | `-b` | int | `1` | Browser instances to launch for spidering (clamped to 1; for parallel crawling set spidering.tabs in the config, which runs N tabs of the one browser) |
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--concurrency` | `-c` | int|phase=int | `25` | Number of concurrent scan workers. Accepts a phase qualifier, repeatable: --concurrency discovery=10 |
| `--db-isolate` | - | bool | `false` | Scan into a private temporary database, then merge results into --db (or the default DB) at the end — lets many parallel scans share one --db without write contention (SQLite only; ignored under --stateless, which keeps nothing to merge; combine with -P -T to fan out targets and export one unified output from the merged DB) |
| `--depth` | - | string | - | Reads per origin: light, standard or full (default standard, light past 50 targets) |
| `--discover` | - | bool | `false` | Force the content discovery phase on (balanced and deep already run it; --skip discovery turns it off) |
| `--discover-max-time` | - | duration | `1h0m0s` | Max time for content discovery per target |
| `--discovery-extensions` | - | stringSlice | - | Extensions discovery also tries on every wordlist name, e.g. php,bak (ffuf's -e; leading dots optional). Swept directly, without the confirm-before-fuzzing gate that otherwise guards server-side extensions. Overrides discovery.extensions.custom_list |
| `--discovery-max-depth` | - | int | `0` | Maximum directory recursion depth for discovery (ffuf's -recursion-depth); 0 turns recursion off. Overrides discovery.recursion.max_depth (default 5) |
| `--discovery-wordlist` | - | stringArray | - | Custom wordlist file seeding the discovery phase's /FUZZ brute-force (enables fuzzing on the fly). Repeatable: the files are streamed in order and each word is tried once. A missing file is a usage error. Formerly --fuzz-wordlist; distinct from 'vigolium fuzz -w'. |
| `--events` | - | string | - | Emit a machine-readable event stream to stdout while the scan runs: 'ndjson' (one JSON object per line, flushed per event). The human console stays on stderr, so a driver reads the stream with 2>/dev/null. Events: scan.started, phase.started/progress/finished, waf.block, waf.pacing, finding.new, error, scan.finished. |
| `--export-only` | - | stringSlice | - | Limit the --format jsonl envelope to these record types (comma-separated: http, findings, scans, modules, oast, source-repos, scopes). Defaults to 'http' on a probe-only run, where every finding is a tech detection already carried on the record's technology field. |
| `--external-harvest` | - | bool | `false` | Enable external intelligence gathering phase (Wayback, CT logs, etc.) |
| `--fail-on` | - | string | - | Exit non-zero if a finding at or above this severity is present (info\|suspect\|low\|medium\|high\|critical); findings marked false_positive/accepted_risk do not count — for CI/agent gating. Scoped to this scan; implies --fail-on-partial; --soft-fail overrides; with -P it is evaluated per child. |
| `--fail-on-partial` | - | bool | `false` | Exit 5 (incomplete) when the scan's coverage was partial (a phase cut short, blocked, or failed); implied by --fail-on |
| `--favicon` | - | bool | `false` | Fetch each answering origin's icon once (the page's <link rel="icon">, else /favicon.ico; redirects not followed) and hash it: mmh3 (Shodan http.favicon.hash, FOFA icon_hash), MD5, SHA-256. Stored per host:port; read it as 'favicon_mmh3' with 'vigolium hosts', or as 'favicon' on 'traffic -j' rows and jsonl http_record lines. Read by the probe phase (the fingerprint phase always fetches the icon) |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--follow-subdomains` | - | bool | `false` | Pull in-scope subdomains discovered in responses into the scan (exact hosts only, not the whole apex; auto-on at --intensity deep) |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--headed` | - | bool | `false` | Show the browser window during spidering (sugar for --headless=false; wins when both are set) |
| `--header` | `-H` | stringArray | - | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token'). Commas are literal — repeat -H for multiple headers. |
| `--header-fuzz` | - | string | - | Header insertion points: gated (default: noise headers skipped, logged/negotiation/routing headers once per host and only for the vuln classes they can sink) or all (every header, every module, per path). Overrides config dynamic-assessment.header_points |
| `--headless` | - | bool | `true` | Run browser in headless mode |
| `--heuristics-check` | - | string | - | Pre-scan heuristics level: none, basic, advanced (default: basic) |
| `--ignore-file` | - | string | - | YAML list of finding hashes to ignore ({hash, reason, expires}); default .vigolium-ignore.yaml when present |
| `--include-response` | - | bool | `false` | Include full HTTP response body in output |
| `--input` | `-i` | string | `-` | Input file path or spec (use - for stdin) |
| `--input-mode` | `-I` | string | `urls` | Input format: urls, nuclei, openapi, wsdl, postman, curl, burpraw, burpxml, burpscope, har, deparos (aliases accepted, see --list-input-mode) |
| `--input-read-timeout` | - | duration | `3m0s` | Deadline for reading input from stdin; 0 disables it |
| `--intensity` | - | string | - | How hard to scan: quick, balanced (default), or deep — the one dial for phases, pace and module tiers (sets --strategy and --scanning-profile) |
| `--keep-db-on-error` | - | bool | `false` | On a failed -S/--stateless scan, move the throwaway working database to ~/.vigolium/recovered instead of deleting it, so the partial results survive the failure (requires -S) |
| `--known-issue-scan-exclude-tags` | - | stringSlice | - | Nuclei template tags to exclude (comma-separated) |
| `--known-issue-scan-severities` | - | stringSlice | - | Filter Nuclei templates by severity (critical,high,medium,low,info) |
| `--known-issue-scan-tags` | - | stringSlice | - | Nuclei template tags to include (comma-separated) |
| `--known-issue-scan-templates` | - | stringArray | - | Run only these Nuclei templates (nuclei's -t for a file): a template file, or a path relative to the templates directory such as http/cves/2021/CVE-2021-44228.yaml. Repeatable; combined with --known-issue-scan-templates-dir, the named directories run too. |
| `--known-issue-scan-templates-dir` | - | stringArray | - | Custom Nuclei templates directory (alias: --templates-dir). Pin it to avoid the one-time clone into ~/nuclei-templates. Repeatable: the first replaces known_issue_scan.templates_dir, and every named directory is loaded. |
| `--limit` | `-n` | int | `200` | With -j: the most findings the scan document embeds in items, highest severity first (0 = no cap); total, counts_by_severity and query cover the rest |
| `--max-body-bytes` | - | int | `4096` | Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap |
| `--max-findings-per-module` | - | int | `50` | Stop reporting after N distinct findings per module; drops are counted in the summary and events (0 = unlimited) |
| `--max-host-error` | - | int | `30` | Skip host after reaching this many consecutive errors |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--max-per-host` | - | int|phase=int | `40` | Maximum concurrent requests allowed per host. Accepts a phase qualifier, repeatable: --max-per-host spidering=4 |
| `--max-requests` | - | int | `0` | Stop the scan after N requests to the targets (0 = unlimited). Exact for gated traffic; the browser crawl is held to it within 500ms; nuclei is not counted (see request_cap_enforcement on scan.started). A scan it stops is partial with stop_reason request_budget. Config: scanning_pace.max_requests |
| `--max-requests-per-host` | - | int | `0` | Send at most N requests to any one target host (0 = unlimited); further requests to that host fail fast and the phase records the host_request_budget limit. Config: scanning_pace.max_requests_per_host |
| `--max-time` | - | duration | `0s` | Maximum total scan duration, e.g. 15m, 2h (default: scanning_pace.scan_max_duration, 1h; alias --scanning-max-duration) |
| `--module-tag` | - | stringSlice | - | Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection) |
| `--modules` | `-m` | stringSlice | - | Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli) |
| `--no-carry-browser-session` | - | bool | `false` | Do not carry the spidering browser's cleared session (cookies + UA) into discovery/scanning (on by default when --spider runs; scoped to the same host, respects -H) |
| `--no-cdp` | - | bool | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-clustering` | - | bool | `false` | Disable deduplication of identical concurrent HTTP requests |
| `--no-discovery-fuzz` | - | bool | `false` | Disable discovery's /FUZZ brute-force (alias --no-fuzz). Overrides every reason it would auto-enable — --intensity deep, a discovery-only run such as 'vigolium run discover', and the low-yield auto-enable. Link extraction, JS parsing, response-word harvesting and the short dir/file wordlists still run. |
| `--no-forms` | - | bool | `false` | Disable form filling and submission during spidering (sets spidering.interaction edit_fields and submit_forms off; an explicit interaction key wins) |
| `--no-param-dedup` | - | bool | `false` | Keep testing a parameter with every module of a vuln class after one already reported it (default: one finding per param and class, e.g. sqli-time-blind skips a param sqli-error-based confirmed). For audit runs |
| `--no-prefix-breaker` | - | bool | `false` | Disable per-prefix circuit breaker that stops discovery from recursing into trap directories |
| `--no-redact` | - | bool | `false` | Keep credential headers, cookie values and sensitive query parameters in HTML/PDF/SARIF/Markdown report evidence (redacted by default; also output.redact_evidence: false). JSONL and the database always keep the raw exchange |
| `--no-tech-filter` | - | bool | `false` | Disable the tech-stack allowlist (run every module regardless of detected stack). Auto-enabled by --intensity=deep. |
| `--no-waf-pacing` | - | bool | `false` | Disable proactive CDN/WAF-edge pacing (don't pre-throttle per-host concurrency when a CloudFront/Cloudflare/etc. edge is detected); reactive back-off after a WAF block still applies |
| `--oast-url` | - | string | - | Fixed out-of-band callback URL instead of interactsh; put {nonce} in it (https://{nonce}.cb.example.com) to attribute logged callbacks with 'vigolium oast ingest' |
| `--omit-response` | - | bool | `false` | Omit raw HTTP request/response bytes from output file (keeps metadata, smaller files) |
| `--only` | - | string | - | Run only these phases (comma-separated: ingestion, probe, fingerprint, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension, heuristics-check, port-sweep, targeted-respider; aliases accepted, see 'vigolium run --help') |
| `--output` | `-o` | string | - | Write findings to specified output file |
| `--parallel` | `-P` | int | `1` | Scan up to N targets concurrently as isolated child processes (requires -S -T --split-by-host, OR --db-isolate -T which merges into --db and exports one unified output; each target keeps its own --concurrency, so real in-flight requests ≈ N × --concurrency) |
| `--param-mining` | - | bool | `false` | Mine hidden parameters (Arjun-style) on this scan's dynamic endpoints before the assessment, so injection modules test them too. Default: on at --intensity deep, off below; --param-mining=false turns it off at deep. Budget: dynamic-assessment.param_mining in config |
| `--pdf-timeout` | - | duration | `0s` | Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else 1m30s) |
| `--port-sweep-ports` | - | string | - | Override the alternate HTTP(S) ports swept on CLI target hosts (comma-separated; sweep runs at --intensity deep or --follow-subdomains) |
| `--print-finding` | - | bool | `false` | After the scan, print each finding to stdout as Markdown (description + matched evidence + request/response), like 'vigolium finding --markdown'. Pairs well with -S and --silent for a quick scan. |
| `--print-traffic` | - | bool | `false` | After the scan, print the run's raw HTTP request/response pairs to stdout, like 'vigolium traffic --raw'. Pairs well with -S and --silent. |
| `--print-traffic-tree` | - | bool | `false` | After the scan, print the run's HTTP traffic to stdout as a host/path hierarchy tree, like 'vigolium traffic --tree'. Pairs well with -S and --silent. |
| `--probe` | - | bool | `false` | Enable the host-sweep phase: one request per target, passive tech fingerprinting + surface scoring, no content discovery or fuzzing (same as 'vigolium run probe') |
| `--rate-limit` | `-r` | int|phase=int | `100` | Global requests/second cap, applied to native scanning AND known-issue-scan. Applies at its documented default even when unset; pass 0 for no cap. Accepts a phase qualifier, repeatable: --rate-limit known-issue-scan=20 |
| `--record-redirect-chain` | - | bool | `false` | Store a followed redirect's hops as their own http_records rows, chained by parent_uuid, instead of keeping only the final response. Canonical hops (scheme upgrade, trailing slash, www.) collapse into their destination row, and a chain stores at most 4 rows, keeping the first and the last. Read by the probe phase; on by default under 'run probe'. |
| `--redirect-mode` | - | string | - | Which redirects to follow: off \| same-host \| same-apex \| in-scope \| any (default in-scope; 'run probe' defaults to same-apex). 'in-scope' follows a hop only to a host the scan scope admits (same-apex when no scope is set). 'same-apex' follows within the registrable domain, so www.example.com -> example.com follows but example.com -> tracker.example.net does not. A hop to another host never carries session or -H headers. Every mode also stops at a login/SSO wall, whatever its host, and records the 3xx instead. |
| `--report-url` | - | string | - | URL for the "Raw Report URL" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL) |
| `--require-auth` | - | bool | `false` | Fail a target's spidering instead of crawling anonymously when configured authentication (session cookies/auth headers) cannot be applied to the browser (sets spidering.require_auth) |
| `--required-only` | - | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--resume` | - | bool | `false` | Resume a prior -S -T --split-by-host -P run from its progress manifest (<output>.progress.json): skip targets that already completed cleanly and scan only the remainder. Run bare ('vigolium scan --resume', no other flags) to auto-discover the *.progress.json in the current directory and relaunch the saved run from it (pass -o <prefix> to disambiguate when several exist) |
| `--resume-scan` | - | string | - | Resume a previous scan by UUID: reuse its scan row and cursor and skip the records/modules its coverage ledger records as done |
| `--retries` | - | int | `1` | Number of retry attempts for failed requests |
| `--safe` | - | bool | `false` | Bounded, non-mutating scan: GET/HEAD traffic only, no form submission/uploads/login attempts in the browser, no risky payloads or intrusive templates, low pace, 15m total budget (typed flags still win) |
| `--scanning-profile` | - | string | - | Advanced: scanning profile name or YAML file path (pace, discovery depth, templates); --intensity picks this for you |
| `--scope-origin` | - | string | - | Host scope strictness: all, relaxed, balanced, strict (default balanced; balanced admits any host sharing the target's eTLD+1, including subdomains already in the database from earlier scans). Bounds which STORED records a phase works and, under the default --redirect-mode in-scope, which hosts a redirect may follow to |
| `--skip` | - | stringSlice | - | Skip these phases (repeatable: ingestion, probe, fingerprint, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension, heuristics-check, port-sweep, harvest-probe, targeted-respider, param-mining, preflight; aliases accepted, see 'vigolium run --help') |
| `--skip-format-validation` | - | bool | `false` | Skip validation of input file format |
| `--skip-heuristics` | - | bool | `false` | Disable pre-scan heuristics (equivalent to --heuristics-check=none) |
| `--spider` | - | bool | `false` | Force the browser spidering phase on (balanced and deep already run it; --skip spidering turns it off) |
| `--spider-max-time` | - | duration | `30m0s` | Max time for spidering per target |
| `--split-by-host` | - | bool | `false` | In stateless multi-target mode (-S -T file), write a separate per-host output file (base-<host>.<ext>) instead of one unified file |
| `--stateless` | `-S` | bool | `false` | Use a temporary database that is discarded after the scan (pass --output/--format to persist results) |
| `--stats` | - | bool | `false` | Show live progress stats during scanning |
| `--strategy` | - | string | - | Advanced: which phases run (lite, balanced, deep); --intensity picks this for you |
| `--stream` | - | bool | `false` | Process targets as a stream without buffering or deduplication |
| `--target` | `-t` | stringArray | - | Target URL to scan (repeatable). Commas are literal so a URL query like ?ids=1,2,3 stays one target — repeat -t for multiple targets. |
| `--target-file` | `-T` | stringArray | - | File containing target URLs (one per line; repeatable for multiple files). Commas in the path are literal. |
| `--timeout` | - | duration | `15s` | HTTP request timeout (e.g. 30s, 1m, 2h) |
| `--tls-probe` | - | bool | `false` | Probe each HTTPS target's TLS: negotiated version/cipher plus the leaf certificate (subject, SANs, issuer, validity, fingerprints). Stored per host:port; read it with 'vigolium hosts -j' or as 'tls' on 'traffic -j' rows. Read by the probe phase (the fingerprint phase always probes HTTPS) |
| `--upload-results` | - | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |

## vigolium fuzz

Usage: `vigolium fuzz [url]`

Inject payloads into a request and report per-payload response anomalies

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all-results` | - | bool | `false` | Emit every result, not just matched ones |
| `--allow-baseline-error` | - | bool | `false` | Run even when every baseline send fails (deltas, calibration and anomaly scoring then compare against an empty response) |
| `--anomaly` | `-a` | bool | `false` | Auto-detect interesting responses instead of requiring explicit matchers: score each response against the baseline AND the run's own population (rare status, unique body, size/time outliers, new error signatures, changed headers, unencoded reflection) |
| `--anomaly-min-population` | - | int | `0` | Responses needed before population signals (rarity/outliers) count (default 12) |
| `--anomaly-threshold` | - | string | `medium` | How strong a signal must be to report: low\|medium\|high, or a number |
| `--auth-session` | - | string | - | Auth session name whose headers are merged in (from 'vigolium auth list') |
| `--baseline-samples` | - | int | `0` | Send the un-fuzzed request this many times to measure timing jitter, enabling time_z (default 1, or 3 with --anomaly) |
| `--burp-bridge-url` | `-B` | string | - | Loopback Burp/Caido bridge URL used by --send-via-burp / --matches-to-organizer (alias: --caido-bridge-url) |
| `--cacert` | - | string | - | CA bundle used to verify the target (implies --verify-tls) |
| `--cert` | - | string | - | Client certificate file (PEM), curl's -E |
| `--class` | - | stringSlice | - | Built-in payload class to inject: cmdi,crlf,lfi,open_redirect,path_traversal,sqli,ssrf,ssti,xss,xxe (comma-list) |
| `--compact` | - | bool | `false` | With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata |
| `--compressed` | - | bool | `false` | Request a compressed response (already transparent) — accepted for curl compatibility |
| `--concurrency` | `-c` | int | `10` | Concurrent requests |
| `--connect-timeout` | - | duration | `0s` | TCP/TLS connect timeout (e.g. 5s) |
| `--cookie` | - | string | - | Cookie header value, curl's -b (e.g. 'a=1; b=2') |
| `--data` | `-d` | string | - | Request body override (refreshes Content-Length) |
| `--data-binary` | - | stringArray | - | Body data; '@file' is read verbatim, newlines kept (repeatable) |
| `--data-raw` | - | stringArray | - | Body data with '@' taken literally (repeatable) |
| `--data-urlencode` | - | stringArray | - | URL-encoded body data; supports curl's name=value, @file and name@file forms (repeatable) |
| `--delay` | - | int | `0` | Delay in ms before each request (per worker) |
| `--dry-run` | - | bool | `false` | Resolve positions and payloads, print what would be sent, and exit without any network traffic |
| `--exclude-header` | - | stringArray | - | Exclude on a response header: 'Name' for presence, or 'Name: regex' (repeatable) |
| `--exclude-lines` | - | stringSlice | - | Exclude response line counts: N, N-M, >N, <N, !N |
| `--exclude-mode` | - | string | `any` | Combine exclude flags with 'any' (OR) or 'all' (AND) |
| `--exclude-regex` | - | string | - | Exclude responses whose body matches this regex |
| `--exclude-size` | - | stringSlice | - | Exclude response sizes in bytes: N, N-M, >N, <N, !N |
| `--exclude-status-code` | - | stringSlice | - | Exclude status codes: N, N-M, >N, <N, !N, or 'all' |
| `--exclude-time` | - | stringSlice | - | Exclude response times in ms: N, N-M, >N, <N, !N (bare N means >=N) |
| `--exclude-time-z` | - | stringSlice | - | Exclude response times by standard deviations above the baseline mean (needs --baseline-samples > 1); e.g. 4 or '>3' |
| `--exclude-words` | - | stringSlice | - | Exclude response word counts: N, N-M, >N, <N, !N |
| `--fail-on-match` | - | bool | `false` | Exit non-zero (3) if any result matches (for agent/CI gating) |
| `--fields` | - | stringSlice | - | Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop |
| `--form` | - | stringArray | - | multipart/form-data field 'name=value', 'name=@file' or 'name=<file' (repeatable) |
| `--form-string` | - | stringArray | - | multipart field whose value is never interpreted (repeatable) |
| `--fuzz` | - | string | - | What to fuzz: method\|path\|params\|param-name\|new-param[:query\|body\|json]\|body\|headers[:synthetic]\|cookies\|all (default: all insertion points; param-name renames a parameter, new-param adds one, body replaces the body) |
| `--fuzz-header` | - | stringArray | - | Fuzz a specific header by name (repeatable) |
| `--get` | - | bool | `false` | Send the accumulated data as query parameters on a GET, curl's -G |
| `--head` | - | bool | `false` | Use HEAD, curl's -I |
| `--header` | `-H` | stringArray | - | Request header 'Name: value', added or replaced on the source request (repeatable) |
| `--http-mode` | - | string | - | With --send-via-burp: wire protocol — auto\|http1\|http2\|http2_ignore_alpn (default auto; use http1 for request smuggling/desync) |
| `--http-version` | - | string | - | Wire protocol: auto (default: HTTP/3, then HTTP/2, then HTTP/1.1), 1.1, 2, 3, or 3-only |
| `--http1.1` | - | bool | `false` | Force HTTP/1.1 |
| `--http2` | - | bool | `false` | Stay on TCP and use HTTP/2 where the target negotiates it (no HTTP/3) |
| `--http3` | - | bool | `false` | Prefer HTTP/3, falling back to HTTP/2 or HTTP/1.1 (the default; curl's --http3) |
| `--http3-only` | - | bool | `false` | Require HTTP/3 and fail when the target does not speak it (curl's --http3-only) |
| `--ignore-scope` | - | bool | `false` | Fuzz a host outside the project's configured scope |
| `--input` | `-i` | string | - | Raw input: curl, raw HTTP, Burp XML, base64 or URL text, a path to a file holding one, or '-' for stdin |
| `--input-file` | - | string | - | Read --input value from a file |
| `--insecure` | - | bool | `false` | Skip TLS verification (already the default; accepted for curl compatibility) |
| `--key` | - | string | - | Client certificate private key file (PEM) |
| `--keyword` | - | string | `FUZZ` | Marker keyword replaced by each payload when present in the request |
| `--location` | - | bool | `false` | Follow 30x redirects (already the default; use --no-redirects to stop) — accepted for curl compatibility |
| `--match-header` | - | stringArray | - | Match on a response header: 'Name' for presence, or 'Name: regex' (repeatable) |
| `--match-lines` | - | stringSlice | - | Match response line counts: N, N-M, >N, <N, !N |
| `--match-mode` | - | string | `any` | Combine match flags with 'any' (OR) or 'all' (AND) |
| `--match-regex` | - | string | - | Match responses whose body matches this regex |
| `--match-size` | - | stringSlice | - | Match response sizes in bytes: N, N-M, >N, <N, !N |
| `--match-status-code` | - | stringSlice | - | Match status codes: N, N-M, >N, <N, !N, or 'all' |
| `--match-time` | - | stringSlice | - | Match response times in ms: N, N-M, >N, <N, !N (bare N means >=N) |
| `--match-time-z` | - | stringSlice | - | Match response times by standard deviations above the baseline mean (needs --baseline-samples > 1); e.g. 4 or '>3' |
| `--match-words` | - | stringSlice | - | Match response word counts: N, N-M, >N, <N, !N |
| `--matches-to-organizer` | - | bool | `false` | Push each matched result's request to Burp's Organizer (Burp re-issues it) for manual triage; requires --burp-bridge-url |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--max-redirs` | - | int | `0` | Maximum redirects to follow (0 = Go's default of 10) |
| `--max-requests` | - | int | `10000` | Refuse a run whose plan expands to more payload sends than this (0 = no cap; baseline and calibration sends are not counted) |
| `--max-time` | - | duration | `0s` | Total per-request budget; alias for --timeout, curl's -m |
| `--mode` | - | string | `sniper` | With several markers (FUZZ, FUZZ2, ...): sniper (one at a time) \| batteringram (same payload everywhere) \| pitchfork (lists in lockstep) \| clusterbomb (every combination) |
| `--no-calibrate` | - | bool | `false` | Disable auto-calibration of the target's catch-all response |
| `--no-cookies` | - | bool | `false` | Don't carry cookies (overrides --session-id) |
| `--no-redirects` | - | bool | `false` | Don't follow 30x redirects |
| `--output` | `-o` | string | - | Write the per-payload JSONL stream to this file (stdout keeps the human table, or the -j envelope) |
| `--path-as-is` | - | bool | `false` | Send the path byte-for-byte (already the case; see pkg/replay wire fidelity) — accepted for curl compatibility |
| `--payload` | `-p` | stringArray | - | Inline payload literal (repeatable) |
| `--point` | - | stringArray | - | Explicit insertion point 'TYPE:name' e.g. URL_PARAM:id (repeatable) |
| `--rate-limit` | `-r` | float64 | `100` | Max requests/second across all workers, counting baseline and calibration sends (0 = unlimited; fractions allowed, e.g. 0.5). Not taken from scanning config |
| `--record-uuid` | `-u` | string | - | Use a stored HTTP record (UUID or unique 8+ char prefix) as the request to fuzz |
| `--referer` | - | string | - | Referer header, curl's -e |
| `--request` | `-X` | string | - | HTTP method override (default: the source request's, or GET) |
| `--resolve` | - | stringArray | - | Pin a host to an address, curl's --resolve host:port:addr (repeatable) |
| `--send-timeout` | - | duration | `0s` | With --send-via-burp: per-request response timeout (<=2m; default uses the bridge's 30s) |
| `--send-via-burp` | - | bool | `false` | Send each payload through Burp's own HTTP stack (exact bytes — malformed/smuggling preserved) instead of Go's client; requires --burp-bridge-url |
| `--session-id` | - | string | - | Persist cookies across runs under ~/.vigolium/replay-jars/<id>.json |
| `--suffix` | - | stringSlice | - | Also send each payload with each of these suffixes appended, literally (comma-list, e.g. .php,.bak — ffuf's -e) |
| `--target` | `-t` | string | - | Override scheme/host/port the request is sent to (e.g. https://staging.acme.test) |
| `--timeout` | - | duration | `25s` | Per-request timeout (e.g. 30s) |
| `--user` | - | string | - | Basic auth 'user:password', curl's -u |
| `--user-agent` | - | string | - | User-Agent header, curl's -A |
| `--verify-tls` | - | bool | `false` | Verify TLS certificates — the inverse of --insecure, and NOT the default |
| `--wordlist` | `-w` | stringArray | - | Payload wordlist: a file path or a builtin name (dir-long, dir-short, file-long, file-short, fuzz, params; 'builtin' = fuzz) (repeatable) |

## vigolium gau

Usage: `vigolium gau [vigolium globals] [--] [gau flags]`

Harvest archived URLs using gau's argv (routed to `vigolium run external-harvest`)

**Compatibility shim.** This command parses another tool's argv itself rather than through cobra, so it accepts that tool's flags, not the ones listed here. It is a subset: run it with `-h` for what is actually translated.

_No command-specific flags._

## vigolium host

Usage: `vigolium host [vigolium globals] [--] [host flags]`

Resolve names using host's argv (routed to `vigolium dns`, which stores the answers)

**Compatibility shim.** This command parses another tool's argv itself rather than through cobra, so it accepts that tool's flags, not the ones listed here. It is a subset: run it with `-h` for what is actually translated.

_No command-specific flags._

## vigolium hosts

Usage: `vigolium hosts [host-pattern]`

Read stored host facts: DNS, TLS certificate, fingerprint and not-found baseline

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--compact` | - | bool | `false` | With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata |
| `--fields` | - | stringSlice | - | Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop |
| `--has` | - | string | - | Only hosts carrying this fact: dns, favicon, fingerprint, not-found, tls |
| `--history` | - | bool | `false` | Every observation, not just the latest per host:port |
| `--host` | - | string | - | Only this hostname, or a pattern with * wildcards (same as the positional) |
| `--limit` | `-n` | int | `100` | Maximum hosts to list (0 = all) |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--no-header` | - | bool | `false` | With --format tsv, omit the header line |
| `--offset` | - | int | `0` | Hosts to skip (pagination) |
| `--sans` | - | bool | `false` | Print the distinct DNS names in the matched certificates' SANs, one per line, and nothing else |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Only observations recorded by this run |
| `--soft-404` | - | bool | `false` | Only origins that answer 2xx/3xx to a path that does not exist |
| `--stateless` | `-S` | bool | `false` | Read from --db (a standalone .sqlite) with project scoping off; never writes to your project DB |

## vigolium import

Usage: `vigolium import [path|gs://...] [more-paths...]`

Import scan data, databases, or live Burp Proxy history

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all-hosts` | - | bool | `false` | Import the operator's ENTIRE proxy history, unfiltered. Required when no filter is given — an unfiltered pull copies every host ever browsed, with its cookies and tokens, into this database. |
| `--burp-bridge-url` | `-B` | string | - | Import live Burp/Caido proxy history from this loopback bridge URL into the database (alias: --caido-bridge-url) |
| `--exclude-search` | - | stringArray | - | Skip records matching this term (repeatable) |
| `--from` | - | string | - | Import only records from this time onward (2d, 12h, today, YYYY-MM-DD, RFC3339) |
| `--glob-db` | - | string | - | Glob of local files to import alongside any positional paths (use one format per run), e.g. --glob-db 'prefix-*.sqlite' or '*.jsonl' |
| `--host` | - | string | - | Import only records for this host (supports * wildcards, e.g. '*.example.com') |
| `--limit` | `-n` | int | `0` | Import at most N records (0 = no limit) |
| `--max-body-bytes` | - | int | `4096` | Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap |
| `--method` | - | stringSlice | - | Import only these HTTP methods (comma-separated) |
| `--no-redact` | - | bool | `false` | Keep credential headers, cookie values and sensitive query parameters in HTML/PDF/SARIF/Markdown report evidence (redacted by default; also output.redact_evidence: false). JSONL and the database always keep the raw exchange |
| `--output` | `-o` | string | - | Report output path or gs://<project>/<key> URL (required when --format is set; supports {ts}) |
| `--path` | - | string | - | Import only records whose path matches this pattern |
| `--pdf-timeout` | - | duration | `0s` | Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else 1m30s) |
| `--report-duration` | - | string | - | Human-readable scan duration for the report (e.g. "10h42m5s") |
| `--report-generated-at` | - | string | - | ISO timestamp for report generation (e.g. "2026-04-18T03:00:00Z") |
| `--report-target` | - | string | - | Target name for the report (e.g. repository name or URL) |
| `--report-title` | - | string | - | Custom title for the HTML report (default: "Vigolium Static Report") |
| `--report-url` | - | string | - | URL for the "Raw Report URL" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL) |
| `--search` | - | string | - | Fuzzy search filter across finding fields included in the report; under --burp-bridge-url, narrows which records are imported |
| `--severity` | - | string | - | Filter report findings by severity (comma-separated: critical,high,medium,low,info) |
| `--status` | - | intSlice | - | Import only these response status codes (comma-separated) |
| `--to` | - | string | - | Import only records up to this time |
| `--upload` | - | bool | `false` | Upload the local import source to cloud storage after import |
| `--upload-key` | - | string | - | Explicit storage key for --upload (default: imports/<basename>-<ts>.<ext>) |
| `--yes` | - | bool | `false` | Skip the pre-flight confirmation for a bridge import |

## vigolium ingest

Ingest HTTP requests into database (locally or via server)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--concurrency` | `-c` | int|phase=int | `25` | Number of concurrent scan workers. Accepts a phase qualifier, repeatable: --concurrency discovery=10 |
| `--dir` | - | string | - | Ingest every matching file in this directory in one process (pairs with -I to fix the format, and --dir-glob to narrow the match) |
| `--dir-glob` | - | string | `*` | Filename pattern for --dir (e.g. '*.har') |
| `--disable-fetch-response` | - | bool | `false` | Store requests without fetching responses during ingestion |
| `--full-native-scan-on-receive` | - | bool | `false` | Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records, instead of dynamic-assessment only |
| `--input` | `-i` | string | `-` | Input file path or spec (use - for stdin) |
| `--input-mode` | `-I` | string | `urls` | Input format: urls, nuclei, openapi, wsdl, postman, curl, burpraw, burpxml, burpscope, har, deparos (aliases accepted, see --list-input-mode) |
| `--input-read-timeout` | - | duration | `3m0s` | Deadline for reading input from stdin; 0 disables it |
| `--keep-blocked` | - | bool | `false` | Store a fetched response the block detector classifies as a WAF/bot-wall page (remark blocked:<reason>) instead of dropping the record |
| `--max-findings-per-module` | - | int | `50` | Stop reporting after N distinct findings per module; drops are counted in the summary and events (0 = unlimited) |
| `--max-host-error` | - | int | `30` | Skip host after reaching this many consecutive errors |
| `--max-per-host` | - | int|phase=int | `40` | Maximum concurrent requests allowed per host. Accepts a phase qualifier, repeatable: --max-per-host spidering=4 |
| `--module-tag` | - | stringSlice | - | Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection) |
| `--modules` | `-m` | stringSlice | - | Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli) |
| `--no-clustering` | - | bool | `false` | Disable deduplication of identical concurrent HTTP requests |
| `--no-tech-filter` | - | bool | `false` | Disable the tech-stack allowlist (run every module regardless of detected stack). Auto-enabled by --intensity=deep. |
| `--no-waf-pacing` | - | bool | `false` | Disable proactive CDN/WAF-edge pacing (don't pre-throttle per-host concurrency when a CloudFront/Cloudflare/etc. edge is detected); reactive back-off after a WAF block still applies |
| `--rate-limit` | `-r` | int|phase=int | `100` | Global requests/second cap, applied to native scanning AND known-issue-scan. Applies at its documented default even when unset; pass 0 for no cap. Accepts a phase qualifier, repeatable: --rate-limit known-issue-scan=20 |
| `--scan-on-receive` | - | bool | `false` | Continuously scan new HTTP records as they arrive in the database |
| `--scope-origin` | - | string | - | Host scope strictness: all, relaxed, balanced, strict (default balanced; balanced admits any host sharing the target's eTLD+1, including subdomains already in the database from earlier scans). Bounds which STORED records a phase works and, under the default --redirect-mode in-scope, which hosts a redirect may follow to |
| `--server` | `-s` | string | - | Server URL for remote ingestion (omit for local mode) |
| `--spec-default` | - | string | `1` | Fallback value for required OpenAPI parameters that lack examples |
| `--spec-header` | - | stringArray | - | Add HTTP header to OpenAPI-generated requests (repeatable; commas are literal) |
| `--spec-url` | - | bool | `false` | Use base URLs from the OpenAPI spec's servers field |
| `--spec-var` | - | stringSlice | - | Set OpenAPI parameter value as key=value (repeatable) |
| `--target` | `-t` | stringArray | - | Target URL to scan (repeatable). Commas are literal so a URL query like ?ids=1,2,3 stays one target — repeat -t for multiple targets. |
| `--target-file` | `-T` | stringArray | - | File containing target URLs (one per line; repeatable for multiple files). Commas in the path are literal. |
| `--timeout` | - | duration | `15s` | HTTP request timeout (e.g. 30s, 1m, 2h) |

## vigolium init

Initialize Vigolium with default configuration and preset data

_No command-specific flags._

## vigolium js

Execute JavaScript with the full vigolium.* API

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--code` | - | string | - | Inline JavaScript code to execute |
| `--code-file` | - | string | - | Path to JavaScript/TypeScript file to execute |
| `--target` | - | string | - | Set TARGET variable in JS scope (URL) |
| `--timeout` | - | duration | `30s` | Execution timeout |

## vigolium katana

Usage: `vigolium katana [vigolium globals] [--] [katana flags]`

Crawl using katana's argv (routed to `vigolium run spidering`)

**Compatibility shim.** This command parses another tool's argv itself rather than through cobra, so it accepts that tool's flags, not the ones listed here. It is a subset: run it with `-h` for what is actually translated.

_No command-specific flags._

## vigolium kit

Standalone security utilities (harvest, js-beautify, jwt-crack, oast, param-mine, payload, secret-scan, tmp-clean, wordlist)

_No command-specific flags._

## vigolium kit harvest

Usage: `vigolium kit harvest [domain...|-]`

Collect known URLs for a domain from public archives and indexes

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--source` | - | stringSlice | - | Override sources (comma-separated): wayback, commoncrawl, alienvault, arquivo, urlscan, virustotal |
| `--timeout` | - | duration | `5m0s` | Overall harvest timeout |

## vigolium kit js-beautify

Usage: `vigolium kit js-beautify [file|url|-]`

Unminify and unpack a JavaScript bundle into readable source

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--deadline` | - | duration | `0s` | Analysis deadline (0 = engine default) |
| `--extract` | - | bool | `false` | Also extract every fact kind (a full analysis pass); listed in -j output, summarized on stderr otherwise |
| `--kinds` | - | stringSlice | - | Only report these fact kinds (endpoints, routes, assets, graphql, realtime, dom_flows, paths); implies --extract |
| `--max-ast-nodes` | - | int | `0` | Maximum parsed AST nodes before the analysis degrades to a per-module scan (0 = engine default) |
| `--max-input-mb` | - | int | `0` | Lower the input size limit, in MiB; cannot raise it above the service ceiling (0 = engine default) |
| `--modules` | - | string | - | Write each recovered bundle module to its own file under this directory |
| `--output` | `-o` | string | - | Write the beautified source to this file instead of stdout |
| `--profile` | - | string | - | Analysis profile (beautify, endpoints, discovery, discovery-lite, full, inspect, dom-security, legacy); default depends on --extract |
| `--secrets` | - | bool | `false` | Also scan the beautified source for leaked credentials (values redacted) |
| `--show-secrets` | - | bool | `false` | With --secrets, print secret values in full instead of redacted |
| `--timeout` | - | duration | `30s` | Timeout for fetching a URL argument |
| `--unpack-modules` | - | bool | `false` | Unpack a detected bundle and re-scan each module for endpoints (implies --extract) |

## vigolium kit jwt-crack

Usage: `vigolium kit jwt-crack [token|-]`

Recover a JWT's HMAC signing secret from a wordlist

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--fail-on-crack` | - | bool | `false` | Exit 3 when the secret is recovered (for CI/agent gating) |
| `--secret` | `-p` | stringArray | - | Additional inline candidate secret (repeatable) |
| `--wordlist` | `-w` | string | - | Wordlist: a built-in name (see 'vigolium kit wordlist') or a file path (default: embedded jwt.secrets.list) |

## vigolium kit oast

Mint out-of-band (OOB/OAST) callback URLs and drain their interactions

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--session` | - | string | `oast-session.yaml` | Session file path (holds the interactsh keys/correlation id) |

## vigolium kit oast new

Register an OAST session and mint one or more callback URLs

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--count` | `-n` | int | `1` | Number of callback URLs to mint |
| `--server` | - | string | `oast.pro` | interactsh server URL |
| `--token` | - | string | - | interactsh auth token (for a self-hosted server; falls back to $VIGOLIUM_OAST_TOKEN) |

## vigolium kit oast poll

Poll a saved OAST session for received interactions

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--deregister` | - | bool | `false` | After draining, deregister the session server-side and delete the session file |
| `--interval` | - | duration | `5s` | Polling interval (auto-shrunk if larger than --wait) |
| `--wait` | - | duration | `15s` | How long to poll for interactions before exiting |

## vigolium kit param-mine

Usage: `vigolium kit param-mine [-t URL]`

Discover hidden parameters an endpoint accepts (Arjun-style)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--data` | `-d` | string | - | Request body (form or JSON); names are added to it |
| `--header` | `-H` | stringArray | - | Request header 'Name: value' (repeatable) |
| `--location` | - | string | `auto` | Where names go: auto, query, form, json |
| `--max-requests` | - | int | `60` | Request budget, baselines and confirmations included |
| `--method` | `-X` | string | `GET` | HTTP method |
| `--no-builtin` | - | bool | `false` | Use only the -w wordlists, not the built-in list |
| `--rate-limit` | - | int | `20` | Maximum requests per second (0 = unlimited) |
| `--target` | `-t` | string | - | Endpoint URL to mine (or pass it as the argument) |
| `--timeout` | - | duration | `15s` | Per-request timeout |
| `--wordlist` | `-w` | stringArray | - | File of parameter names, one per line, tried before the built-in list (repeatable) |

## vigolium kit payload

Emit built-in payload sets by vulnerability class

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--class` | `-c` | stringSlice | - | Vulnerability class(es), comma-separated (see --list) |
| `--list` | - | bool | `false` | List available payload classes |

## vigolium kit secret-scan

Usage: `vigolium kit secret-scan [files|dirs|-]`

Scan files or stdin for leaked credentials using the built-in secret catalog

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--exclude-rule` | - | stringSlice | - | Skip these rule IDs (comma-separated / repeatable) |
| `--fail-on-match` | - | bool | `false` | Exit 3 when at least one secret is found (for CI/agent gating) |
| `--max-file-size` | - | int64 | `16777216` | Skip files larger than this many bytes |
| `--min-confidence` | - | string | `low` | Minimum confidence to report: low, medium, high |
| `--redact` | - | bool | `false` | Mask the secret value in output (show only a prefix/suffix) |
| `--rule` | - | stringSlice | - | Only report these rule IDs (comma-separated / repeatable) |

## vigolium kit tmp-clean

Remove vigolium scratch left in the system temp directory

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--max-age` | - | duration | `6h0m0s` | Only remove scratch untouched for at least this long (0 removes everything not held by a running scan) |

## vigolium kit wordlist

Usage: `vigolium kit wordlist [name]`

List the built-in wordlists or print one to stdout

_No command-specific flags._

## vigolium log

Usage: `vigolium log [uuid]`

View raw logs for a native scan or agentic scan

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--follow` | `-f` | bool | `false` | Follow log output as it is written (tail -f) |
| `--full` | - | bool | `false` | Show the full log (shortcut for --tail -1) |
| `--no-tui` | - | bool | `false` | Force TUI off (escape hatch if TUI ever becomes default) |
| `--raw` | - | bool | `false` | For agentic sessions, print the raw transcript JSONL verbatim instead of the rendered replay |
| `--strip-ansi` | - | bool | `false` | Strip ANSI color codes from output |
| `--tail` | `-n` | int | `200` | Show the last N lines (0 = none, -1 = all) |
| `--tui` | - | bool | `false` | Open interactive TUI (arrow keys to navigate, enter to view details, c to copy id) |

## vigolium log ls

List native scan and agentic scan sessions

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--compact` | - | bool | `false` | With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata |
| `--fields` | - | stringSlice | - | Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--no-tui` | - | bool | `false` | Force TUI off (escape hatch if TUI ever becomes default) |
| `--reap` | - | bool | `false` | Finalize abandoned running scan rows as failed (stop_reason abandoned) and prune expired status.json files; writes the store |
| `--tui` | - | bool | `false` | Open interactive TUI (arrow keys to navigate, enter to view details, c to copy id) |

## vigolium match-not-found

Classify responses read from stdin against their origin's stored not-found baseline

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--compact` | - | bool | `false` | With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata |
| `--fields` | - | stringSlice | - | Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--no-header` | - | bool | `false` | With --format tsv, omit the header line |
| `--stateless` | `-S` | bool | `false` | Read from --db (a standalone .sqlite) with project scoping off; never writes to your project DB |

## vigolium module

Usage: `vigolium module [search]`

Aliases: `mo`, `modules`

Manage scanner modules

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--list-enabled` | - | bool | `false` | Show only enabled modules |
| `--tags` | - | bool | `false` | Show only unique module tags |
| `--type` | - | string | `all` | Filter modules by type: all, active, or passive |
| `--verbose` | `-v` | bool | `false` | **(overrides the global `--verbose`)** Show long description and confirmation criteria |

## vigolium module disable

Usage: `vigolium module disable <search>`

Aliases: `d`

Disable modules matching a search term

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--id` | - | bool | `false` | Match exact module ID instead of fuzzy search |

## vigolium module enable

Usage: `vigolium module enable <search>`

Aliases: `e`

Enable modules matching a search term

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--id` | - | bool | `false` | Match exact module ID instead of fuzzy search |

## vigolium module ls

Usage: `vigolium module ls [filter]`

Aliases: `list`

List available modules

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--list-enabled` | - | bool | `false` | Show only enabled modules |
| `--tags` | - | bool | `false` | Show only unique module tags |
| `--type` | - | string | `all` | Filter modules by type: all, active, or passive |
| `--verbose` | `-v` | bool | `false` | **(overrides the global `--verbose`)** Show long description and confirmation criteria |

## vigolium nuclei

Usage: `vigolium nuclei [vigolium globals] [--] [nuclei flags]`

Run the known-issue scan using nuclei's argv (routed to `vigolium run known-issue-scan`)

**Compatibility shim.** This command parses another tool's argv itself rather than through cobra, so it accepts that tool's flags, not the ones listed here. It is a subset: run it with `-h` for what is actually translated.

_No command-specific flags._

## vigolium oast

Attribute out-of-band callbacks logged by your own OAST endpoint

_No command-specific flags._

## vigolium oast ingest

Usage: `vigolium oast ingest [file|-]`

Turn logged OAST callbacks into findings of the scan that planted them

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--protocol` | - | string | - | Protocol of every raw-log line (http, https, dns, smtp); default: guessed per line |
| `--stateless` | `-S` | bool | `false` | Write to the standalone .sqlite named by --db with project scoping off |

## vigolium oast poll

Collect late out-of-band callbacks for the interactsh sessions scans kept open

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--close` | - | bool | `false` | Deregister each session after polling it |
| `--open` | - | bool | `false` | Poll every open session in the project |
| `--scan` | - | string | - | Poll the session(s) kept by this scan |
| `--wait` | - | duration | `3s` | How long to poll each session |

## vigolium olium

Usage: `vigolium olium [prompt...]`

Aliases: `ol`

Launch vigolium — interactive TUI agent (alias for `vigolium agent olium`)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--base-url` | - | string | - | Endpoint URL for openai-compatible provider (e.g. http://localhost:11434/v1 for Ollama); falls back to agent.olium.custom_provider.base_url |
| `--bridge-bin` | - | string | - | Path to the 'vigolium-audit' binary hosting the SDK bridge (anthropic-claude-sdk-bridge provider; default: embedded blob, then PATH) |
| `--claude-bin` | - | string | - | Path to the 'claude' binary (anthropic-cli provider) |
| `--gcp-location` | - | string | - | GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1) |
| `--gcp-project` | - | string | - | GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id) |
| `--llm-api-key` | - | string | - | API key for key-based providers (anthropic-api-key, openai-api-key); else uses ANTHROPIC_API_KEY / OPENAI_API_KEY env |
| `--model` | - | string | - | Model id (provider-specific default if empty) |
| `--oauth-cred` | - | string | - | Path to OAuth/SA credential file (openai-codex-oauth: ~/.codex/auth.json; anthropic-vertex/google-vertex: SA JSON or $GOOGLE_APPLICATION_CREDENTIALS) |
| `--oauth-token` | - | string | - | Anthropic OAuth bearer token (anthropic-oauth; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY) |
| `--prompt` | `-p` | string | - | Run one prompt non-interactively and stream to stdout (skips the TUI). Pass '-' to read the prompt from stdin |
| `--provider` | - | string | - | Olium provider override: openai-codex-oauth \| openai-api-key \| openai-responses \| anthropic-api-key \| anthropic-oauth \| anthropic-cli \| anthropic-claude-sdk-bridge \| anthropic-vertex \| google-vertex \| openai-compatible \| anthropic-compatible (default: agent.olium.provider; auto-detected when unset); default openai-compatible |
| `--stdin` | - | bool | `false` | Force reading prompt from stdin |
| `--system` | - | string | - | Override system prompt |

## vigolium params

Usage: `vigolium params [search-term]`

Aliases: `param`, `parameters`

List parameters per endpoint with value-type histograms, from stored traffic

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--compact` | - | bool | `false` | With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata |
| `--endpoint` | - | string | - | Only this endpoint: an id from 'vigolium endpoints' or a path template (/users/{int}) |
| `--fields` | - | stringSlice | - | Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop |
| `--from` | - | string | - | Only records sent at or after this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 (alias: --since) |
| `--glob-db` | - | string | - | Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S |
| `--glob-strict` | - | bool | `false` | Fail the read on the first --glob-db source that cannot be imported, instead of skipping it with a warning |
| `--host` | - | string | - | Filter by hostname pattern (wildcard supported) |
| `--limit` | `-n` | int | `100` | Maximum parameters to list (0 = all); the aggregate always covers every matched record |
| `--location` | - | stringSlice | - | Only these locations (comma-separated): query, body, json, xml, cookie, multipart, header, path, other |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--method` | - | stringSlice | - | Filter by HTTP method (repeatable) |
| `--min-occurrences` | - | int64 | `0` | Only parameters seen at least this many times |
| `--no-header` | - | bool | `false` | With --format tsv, omit the header line |
| `--offset` | - | int | `0` | Number of parameters to skip (for pagination) |
| `--output` | `-o` | string | - | With --json: write the result document to this file and print a receipt instead; '-' forces stdout |
| `--path` | - | string | - | Filter by URL path pattern (wildcard supported) |
| `--remark` | - | stringArray | - | Keep records carrying a remark containing this text (repeatable, AND-combined; e.g. --remark jstangle: for JS-derived records, --remark jstangle:not_found) |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Only records first stored by this scan (http_records.scan_uuid; records deduplicated against an earlier scan keep that scan's uuid) |
| `--show-values` | - | bool | `false` | Print sample values unredacted (cookies, headers and secret-looking names are redacted by default) |
| `--source` | - | string | - | Filter by record source (e.g. scanner, deparos, jstangle, html-form, api-spec, ingest-cli, ingest-proxy) |
| `--stateless` | `-S` | bool | `false` | Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB |
| `--status` | - | intSlice | - | Filter by HTTP status code (repeatable) |
| `--to` | - | string | - | Only records sent at or before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339; a bare date covers the whole day (alias: --until) |
| `--type` | - | stringSlice | - | Only parameters whose dominant value type is one of these (comma-separated, e.g. integer,uuid,sequential_id) |

## vigolium project

Manage projects for multi-tenant data isolation

_No command-specific flags._

## vigolium project config

Usage: `vigolium project config [uuid]`

Show or edit a project's config file path

_No command-specific flags._

## vigolium project create

Usage: `vigolium project create [name]`

Create a new project

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--description` | - | string | - | Project description |

## vigolium project delete

Usage: `vigolium project delete <project-uuid>`

Aliases: `rm`, `remove`

Delete a project and every record tied to it

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--keep-config` | - | bool | `false` | Keep the project's config directory (~/.vigolium/projects/<uuid>) on disk |

## vigolium project list

Aliases: `ls`

List all projects

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--no-tui` | - | bool | `false` | Force TUI off (escape hatch if TUI ever becomes default) |
| `--tui` | - | bool | `false` | Open interactive TUI (arrow keys to navigate, enter to view details, c to copy id) |

## vigolium project use

Usage: `vigolium project use <uuid>`

Set the active project (the global ~/.vigolium/active-project file)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--create` | - | bool | `false` | Create the project with this UUID when it does not exist (otherwise an unknown UUID is a not_found error) |
| `--description` | - | string | - | Description for a project created by --create |
| `--name` | - | string | - | Name for a project created by --create (default: "Project <short-uuid>") |

## vigolium replay

Usage: `vigolium replay [search-term]`

Re-send a stored or supplied HTTP request and diff baseline vs replay

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all` | `-a` | bool | `false` | Bulk: replay every matched stored record (lifts the -n/--limit cap); re-send all stored traffic |
| `--asc` | - | bool | `false` | Bulk: sort ascending (default: descending) |
| `--auth-session` | - | string | - | Auth session name to merge headers from (from 'vigolium auth list') |
| `--baseline` | - | bool | `false` | Also send the un-mutated request first and diff the two. A supplied request (-i, --raw-request) is otherwise sent once with no diff; a stored record diffs against its stored response either way |
| `--body` | - | string | - | Bulk: filter records whose request/response body contains this text |
| `--burp-bridge-url` | `-B` | string | - | Loopback Burp/Caido bridge URL used by --save-to-burp / --send-via-burp / --to-repeater / --to-organizer (alias: --caido-bridge-url) |
| `--compact` | - | bool | `false` | With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata |
| `--concurrency` | `-c` | int | `10` | Bulk: concurrent replays; keep low to avoid overwhelming an intercepting proxy like Burp |
| `--exclude-body` | - | string | - | Bulk: drop records whose request/response body contains the term (inverse of --body) |
| `--exclude-header-search` | - | string | - | Bulk: drop records whose HTTP header names/values contain the term (inverse of --header-search) |
| `--exclude-search` | - | stringArray | - | Bulk: drop records where the term appears in the URL, path, or raw request/response (repeatable; dropped if ANY term matches — inverse of --search) |
| `--fields` | - | stringSlice | - | Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop |
| `--finding-id` | - | int64 | `0` | Finding ID — replay the finding's linked record (or its stored evidence) |
| `--from` | - | string | - | Bulk: only records at or after this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 (alias: --since) |
| `--header` | `-H` | stringArray | - | Extra request header 'Name: value' (repeatable, overrides baseline) |
| `--header-search` | - | string | - | Bulk: filter records by text in HTTP header names/values (the search filter 'traffic --header' applies; -H/--header overrides headers instead) |
| `--highlight` | - | string | - | Highlight colour for the --to-organizer item: none\|red\|orange\|yellow\|green\|cyan\|blue\|pink\|magenta\|gray |
| `--host` | - | string | - | Bulk: filter records by hostname pattern (wildcard supported) |
| `--http-mode` | - | string | - | With --send-via-burp: wire protocol — auto\|http1\|http2\|http2_ignore_alpn (default auto; use http1 for request smuggling/desync) |
| `--in-replace` | - | bool | `false` | When the source is a stored record, update its stored response with the replay |
| `--input` | `-i` | string | - | Raw input: curl, raw HTTP, Burp XML, base64 or URL text, a path to a file holding one, or '-' for stdin |
| `--input-file` | - | string | - | Read --input value from a file |
| `--limit` | `-n` | int | `100` | Bulk: max records to replay (use --all to lift the cap) |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--method` | - | stringSlice | - | Bulk: filter records by HTTP method (repeatable) |
| `--no-cookies` | - | bool | `false` | Don't carry cookies (overrides --session-id) |
| `--no-redirects` | - | bool | `false` | Don't follow 30x redirects |
| `--notes` | - | string | - | Note attached to the --to-organizer item (longer than 200 chars is truncated with an ellipsis, not rejected) |
| `--offset` | - | int | `0` | Bulk: skip this many matched records before replaying (pagination) |
| `--output` | `-o` | string | - | Write the JSONL result stream (one object per record) to this file; stdout keeps the human summary, or the -j envelope |
| `--path` | - | string | - | Bulk: filter records by URL path pattern |
| `--raw-request` | - | string | - | Full raw HTTP request override — send these exact bytes instead of the resolved baseline |
| `--raw-request-file` | - | string | - | Read --raw-request from a file |
| `--record-uuid` | `-u` | string | - | Stored HTTP record UUID (or unique 8+ char prefix) to use as baseline |
| `--repeater-tab` | - | string | - | Repeater tab name for --to-repeater (default: vigolium) |
| `--save-to-burp` | - | bool | `false` | Add each replayed request and its fresh response to Burp's Target Site map |
| `--search` | - | stringArray | - | Bulk: search across URL, path, and the raw request/response (headers + body); repeatable, AND-combined |
| `--send-timeout` | - | duration | `0s` | With --send-via-burp: response timeout (<=2m; default uses the bridge's 30s) |
| `--send-via-burp` | - | bool | `false` | Send the request through Burp's own HTTP stack (exact bytes — malformed/smuggling preserved) instead of Go's client; requires --burp-bridge-url |
| `--session-id` | - | string | - | Persist cookies across calls under ~/.vigolium/replay-jars/<id>.json |
| `--sort` | - | string | `created_at` | Bulk: sort matched records by: uuid, created_at, sent_at, method, status, time |
| `--source` | - | string | - | Bulk: filter records by source (burp, caido, scanner, probe, ingest-cli, ingest-proxy, seed, ...) |
| `--stateless` | `-S` | bool | `false` | Read records from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB |
| `--status` | - | intSlice | - | Bulk: filter records by stored status code (repeatable) |
| `--target` | `-t` | string | - | Override scheme/host/port (e.g. https://staging.example.com) |
| `--timeout` | - | duration | `25s` | Per-request timeout (e.g. 30s, 1m) |
| `--to` | - | string | - | Bulk: only records at or before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339; a bare date covers the whole day (alias: --until) |
| `--to-organizer` | - | bool | `false` | Store the replayed request + response in Burp's Organizer for manual follow-up; requires --burp-bridge-url |
| `--to-repeater` | - | bool | `false` | Stage the replayed request in a Burp Repeater tab for manual testing; requires --burp-bridge-url |
| `--with-browser` | - | bool | `false` | Load each record's URL in a real browser routed via --proxy so an intercepting proxy captures browser-driven traffic; navigation-only, so no baseline-vs-replay diff is produced |

## vigolium run

Usage: `vigolium run <phase>`

Aliases: `r`

Run a single native scan phase (alias for scan --only <phase>)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--advanced-options` | `-a` | stringToString | - | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--all-records` | - | bool | `false` | Scan every HTTP record already stored in the active project (the database rescan). Required when no -t/-T/-i/stdin target is given; cannot be combined with them |
| `--allow-risky-payloads` | - | bool | `false` | Allow risk:high payloads and modules below --intensity deep (OR-per-row and stacked time-blind SQLi, so MSSQL time-blind; state-changing probes). Always on at deep. Overrides config dynamic-assessment.allow_risky_payloads |
| `--auth` | - | stringArray | - | Inline session in 'name:Header:value' format. Repeatable; commas are literal (header values may contain commas). |
| `--auth-file` | - | stringArray | - | Path to auth file (YAML/JSON, single session or sessions: bundle), or bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal. |
| `--baseline` | - | string | - | Previous run's findings (.jsonl export or .sqlite store): --fail-on counts only findings not in it; -j adds baseline{new,unchanged,fixed,ignored} |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine: 'chromium', 'ungoogled', or 'fingerprint' |
| `--browser-insecure` | - | bool | `false` | Spider with every browser security exception on: no sandbox, TLS errors ignored, mixed content allowed, same-origin policy off. For local test apps only |
| `--browsers` | `-b` | int | `1` | Browser instances to launch for spidering (clamped to 1; for parallel crawling set spidering.tabs in the config, which runs N tabs of the one browser) |
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--concurrency` | `-c` | int|phase=int | `25` | Number of concurrent scan workers. Accepts a phase qualifier, repeatable: --concurrency discovery=10 |
| `--db-isolate` | - | bool | `false` | Scan into a private temporary database, then merge results into --db (or the default DB) at the end — lets many parallel scans share one --db without write contention (SQLite only; ignored under --stateless, which keeps nothing to merge; combine with -P -T to fan out targets and export one unified output from the merged DB) |
| `--discover` | - | bool | `false` | Force the content discovery phase on (balanced and deep already run it; --skip discovery turns it off) |
| `--discover-max-time` | - | duration | `1h0m0s` | Max time for content discovery per target |
| `--discovery-extensions` | - | stringSlice | - | Extensions discovery also tries on every wordlist name, e.g. php,bak (ffuf's -e; leading dots optional). Swept directly, without the confirm-before-fuzzing gate that otherwise guards server-side extensions. Overrides discovery.extensions.custom_list |
| `--discovery-max-depth` | - | int | `0` | Maximum directory recursion depth for discovery (ffuf's -recursion-depth); 0 turns recursion off. Overrides discovery.recursion.max_depth (default 5) |
| `--discovery-wordlist` | - | stringArray | - | Custom wordlist file seeding the discovery phase's /FUZZ brute-force (enables fuzzing on the fly). Repeatable: the files are streamed in order and each word is tried once. A missing file is a usage error. Formerly --fuzz-wordlist; distinct from 'vigolium fuzz -w'. |
| `--dry-run` | - | bool | `false` | Resolve and print the scan plan — phases (with why each disabled one is off), budgets, pace, modules, scope, auth session names, scope admission and a rough request estimate — then exit without scanning. Mints no scan UUID, writes no output file or scan row, materializes no wordlist, runs no login and registers no OAST; an existing database is only read. -j prints it as a document (items = phases, plan = the full plan, dry_run: true) |
| `--events` | - | string | - | Emit a machine-readable event stream to stdout while the scan runs: 'ndjson' (one JSON object per line, flushed per event). The human console stays on stderr, so a driver reads the stream with 2>/dev/null. Events: scan.started, phase.started/progress/finished, waf.block, waf.pacing, finding.new, error, scan.finished. |
| `--export-only` | - | stringSlice | - | Limit the --format jsonl envelope to these record types (comma-separated: http, findings, scans, modules, oast, source-repos, scopes). Defaults to 'http' on a probe-only run, where every finding is a tech detection already carried on the record's technology field. |
| `--external-harvest` | - | bool | `false` | Enable external intelligence gathering phase (Wayback, CT logs, etc.) |
| `--fail-on` | - | string | - | Exit non-zero if a finding at or above this severity is present (info\|suspect\|low\|medium\|high\|critical); findings marked false_positive/accepted_risk do not count — for CI/agent gating. Scoped to this scan; implies --fail-on-partial; --soft-fail overrides; with -P it is evaluated per child. |
| `--fail-on-partial` | - | bool | `false` | Exit 5 (incomplete) when the scan's coverage was partial (a phase cut short, blocked, or failed); implied by --fail-on |
| `--favicon` | - | bool | `false` | Fetch each answering origin's icon once (the page's <link rel="icon">, else /favicon.ico; redirects not followed) and hash it: mmh3 (Shodan http.favicon.hash, FOFA icon_hash), MD5, SHA-256. Stored per host:port; read it as 'favicon_mmh3' with 'vigolium hosts', or as 'favicon' on 'traffic -j' rows and jsonl http_record lines. Read by the probe phase (the fingerprint phase always fetches the icon) |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--fingerprint-depth` | - | string | - | With the fingerprint phase: reads per origin, light\|standard\|full (default standard, light past 50 targets; 'vigolium fingerprint --depth') |
| `--follow-subdomains` | - | bool | `false` | Pull in-scope subdomains discovered in responses into the scan (exact hosts only, not the whole apex; auto-on at --intensity deep) |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--headed` | - | bool | `false` | Show the browser window during spidering (sugar for --headless=false; wins when both are set) |
| `--header` | `-H` | stringArray | - | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token'). Commas are literal — repeat -H for multiple headers. |
| `--header-fuzz` | - | string | - | Header insertion points: gated (default: noise headers skipped, logged/negotiation/routing headers once per host and only for the vuln classes they can sink) or all (every header, every module, per path). Overrides config dynamic-assessment.header_points |
| `--headless` | - | bool | `true` | Run browser in headless mode |
| `--heuristics-check` | - | string | - | Pre-scan heuristics level: none, basic, advanced (default: basic) |
| `--ignore-file` | - | string | - | YAML list of finding hashes to ignore ({hash, reason, expires}); default .vigolium-ignore.yaml when present |
| `--include-response` | - | bool | `false` | Include full HTTP response body in output |
| `--input` | `-i` | string | `-` | Input file path or spec (use - for stdin) |
| `--input-mode` | `-I` | string | `urls` | Input format: urls, nuclei, openapi, wsdl, postman, curl, burpraw, burpxml, burpscope, har, deparos (aliases accepted, see --list-input-mode) |
| `--input-read-timeout` | - | duration | `3m0s` | Deadline for reading input from stdin; 0 disables it |
| `--intensity` | - | string | - | How hard to scan: quick, balanced (default), or deep — the one dial for phases, pace and module tiers (sets --strategy and --scanning-profile) |
| `--keep-db-on-error` | - | bool | `false` | On a failed -S/--stateless scan, move the throwaway working database to ~/.vigolium/recovered instead of deleting it, so the partial results survive the failure (requires -S) |
| `--known-issue-scan-exclude-tags` | - | stringSlice | - | Nuclei template tags to exclude (comma-separated) |
| `--known-issue-scan-severities` | - | stringSlice | - | Filter Nuclei templates by severity (critical,high,medium,low,info) |
| `--known-issue-scan-tags` | - | stringSlice | - | Nuclei template tags to include (comma-separated) |
| `--known-issue-scan-templates` | - | stringArray | - | Run only these Nuclei templates (nuclei's -t for a file): a template file, or a path relative to the templates directory such as http/cves/2021/CVE-2021-44228.yaml. Repeatable; combined with --known-issue-scan-templates-dir, the named directories run too. |
| `--known-issue-scan-templates-dir` | - | stringArray | - | Custom Nuclei templates directory (alias: --templates-dir). Pin it to avoid the one-time clone into ~/nuclei-templates. Repeatable: the first replaces known_issue_scan.templates_dir, and every named directory is loaded. |
| `--limit` | `-n` | int | `200` | With -j: the most findings the scan document embeds in items, highest severity first (0 = no cap); total, counts_by_severity and query cover the rest |
| `--max-body-bytes` | - | int | `4096` | Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap |
| `--max-findings-per-module` | - | int | `50` | Stop reporting after N distinct findings per module; drops are counted in the summary and events (0 = unlimited) |
| `--max-host-error` | - | int | `30` | Skip host after reaching this many consecutive errors |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--max-per-host` | - | int|phase=int | `40` | Maximum concurrent requests allowed per host. Accepts a phase qualifier, repeatable: --max-per-host spidering=4 |
| `--max-requests` | - | int | `0` | Stop the scan after N requests to the targets (0 = unlimited). Exact for gated traffic; the browser crawl is held to it within 500ms; nuclei is not counted (see request_cap_enforcement on scan.started). A scan it stops is partial with stop_reason request_budget. Config: scanning_pace.max_requests |
| `--max-requests-per-host` | - | int | `0` | Send at most N requests to any one target host (0 = unlimited); further requests to that host fail fast and the phase records the host_request_budget limit. Config: scanning_pace.max_requests_per_host |
| `--max-time` | - | duration | `0s` | Maximum total scan duration, e.g. 15m, 2h (default: scanning_pace.scan_max_duration, 1h; alias --scanning-max-duration) |
| `--module-tag` | - | stringSlice | - | Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection) |
| `--modules` | `-m` | stringSlice | - | Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli) |
| `--no-carry-browser-session` | - | bool | `false` | Do not carry the spidering browser's cleared session (cookies + UA) into discovery/scanning (on by default when --spider runs; scoped to the same host, respects -H) |
| `--no-cdp` | - | bool | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-clustering` | - | bool | `false` | Disable deduplication of identical concurrent HTTP requests |
| `--no-discovery-fuzz` | - | bool | `false` | Disable discovery's /FUZZ brute-force (alias --no-fuzz). Overrides every reason it would auto-enable — --intensity deep, a discovery-only run such as 'vigolium run discover', and the low-yield auto-enable. Link extraction, JS parsing, response-word harvesting and the short dir/file wordlists still run. |
| `--no-forms` | - | bool | `false` | Disable form filling and submission during spidering (sets spidering.interaction edit_fields and submit_forms off; an explicit interaction key wins) |
| `--no-param-dedup` | - | bool | `false` | Keep testing a parameter with every module of a vuln class after one already reported it (default: one finding per param and class, e.g. sqli-time-blind skips a param sqli-error-based confirmed). For audit runs |
| `--no-prefix-breaker` | - | bool | `false` | Disable per-prefix circuit breaker that stops discovery from recursing into trap directories |
| `--no-redact` | - | bool | `false` | Keep credential headers, cookie values and sensitive query parameters in HTML/PDF/SARIF/Markdown report evidence (redacted by default; also output.redact_evidence: false). JSONL and the database always keep the raw exchange |
| `--no-tech-filter` | - | bool | `false` | Disable the tech-stack allowlist (run every module regardless of detected stack). Auto-enabled by --intensity=deep. |
| `--no-waf-pacing` | - | bool | `false` | Disable proactive CDN/WAF-edge pacing (don't pre-throttle per-host concurrency when a CloudFront/Cloudflare/etc. edge is detected); reactive back-off after a WAF block still applies |
| `--oast-url` | - | string | - | Fixed out-of-band callback URL instead of interactsh; put {nonce} in it (https://{nonce}.cb.example.com) to attribute logged callbacks with 'vigolium oast ingest' |
| `--omit-response` | - | bool | `false` | Omit raw HTTP request/response bytes from output file (keeps metadata, smaller files) |
| `--only` | - | string | - | Run only these phases (comma-separated: ingestion, probe, fingerprint, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension, heuristics-check, port-sweep, targeted-respider; aliases accepted, see 'vigolium run --help') |
| `--output` | `-o` | string | - | Write findings to specified output file |
| `--parallel` | `-P` | int | `1` | Scan up to N targets concurrently as isolated child processes (requires -S -T --split-by-host, OR --db-isolate -T which merges into --db and exports one unified output; each target keeps its own --concurrency, so real in-flight requests ≈ N × --concurrency) |
| `--param-mining` | - | bool | `false` | Mine hidden parameters (Arjun-style) on this scan's dynamic endpoints before the assessment, so injection modules test them too. Default: on at --intensity deep, off below; --param-mining=false turns it off at deep. Budget: dynamic-assessment.param_mining in config |
| `--pdf-timeout` | - | duration | `0s` | Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else 1m30s) |
| `--port-sweep-ports` | - | string | - | Override the alternate HTTP(S) ports swept on CLI target hosts (comma-separated; sweep runs at --intensity deep or --follow-subdomains) |
| `--print-finding` | - | bool | `false` | After the scan, print each finding to stdout as Markdown (description + matched evidence + request/response), like 'vigolium finding --markdown'. Pairs well with -S and --silent for a quick scan. |
| `--print-traffic` | - | bool | `false` | After the scan, print the run's raw HTTP request/response pairs to stdout, like 'vigolium traffic --raw'. Pairs well with -S and --silent. |
| `--print-traffic-tree` | - | bool | `false` | After the scan, print the run's HTTP traffic to stdout as a host/path hierarchy tree, like 'vigolium traffic --tree'. Pairs well with -S and --silent. |
| `--probe` | - | bool | `false` | Enable the host-sweep phase: one request per target, passive tech fingerprinting + surface scoring, no content discovery or fuzzing (same as 'vigolium run probe') |
| `--rate-limit` | `-r` | int|phase=int | `100` | Global requests/second cap, applied to native scanning AND known-issue-scan. Applies at its documented default even when unset; pass 0 for no cap. Accepts a phase qualifier, repeatable: --rate-limit known-issue-scan=20 |
| `--record-redirect-chain` | - | bool | `false` | Store a followed redirect's hops as their own http_records rows, chained by parent_uuid, instead of keeping only the final response. Canonical hops (scheme upgrade, trailing slash, www.) collapse into their destination row, and a chain stores at most 4 rows, keeping the first and the last. Read by the probe phase; on by default under 'run probe'. |
| `--redirect-mode` | - | string | - | Which redirects to follow: off \| same-host \| same-apex \| in-scope \| any (default in-scope; 'run probe' defaults to same-apex). 'in-scope' follows a hop only to a host the scan scope admits (same-apex when no scope is set). 'same-apex' follows within the registrable domain, so www.example.com -> example.com follows but example.com -> tracker.example.net does not. A hop to another host never carries session or -H headers. Every mode also stops at a login/SSO wall, whatever its host, and records the 3xx instead. |
| `--report-url` | - | string | - | URL for the "Raw Report URL" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL) |
| `--require-auth` | - | bool | `false` | Fail a target's spidering instead of crawling anonymously when configured authentication (session cookies/auth headers) cannot be applied to the browser (sets spidering.require_auth) |
| `--required-only` | - | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--resume` | - | bool | `false` | Resume a prior -S -T --split-by-host -P run from its progress manifest (<output>.progress.json): skip targets that already completed cleanly and scan only the remainder. Run bare ('vigolium scan --resume', no other flags) to auto-discover the *.progress.json in the current directory and relaunch the saved run from it (pass -o <prefix> to disambiguate when several exist) |
| `--resume-scan` | - | string | - | Resume a previous scan by UUID: reuse its scan row and cursor and skip the records/modules its coverage ledger records as done |
| `--retries` | - | int | `1` | Number of retry attempts for failed requests |
| `--safe` | - | bool | `false` | Bounded, non-mutating scan: GET/HEAD traffic only, no form submission/uploads/login attempts in the browser, no risky payloads or intrusive templates, low pace, 15m total budget (typed flags still win) |
| `--scanning-profile` | - | string | - | Advanced: scanning profile name or YAML file path (pace, discovery depth, templates); --intensity picks this for you |
| `--scope-origin` | - | string | - | Host scope strictness: all, relaxed, balanced, strict (default balanced; balanced admits any host sharing the target's eTLD+1, including subdomains already in the database from earlier scans). Bounds which STORED records a phase works and, under the default --redirect-mode in-scope, which hosts a redirect may follow to |
| `--skip` | - | stringSlice | - | Skip these phases (repeatable: ingestion, probe, fingerprint, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension, heuristics-check, port-sweep, harvest-probe, targeted-respider, param-mining, preflight; aliases accepted, see 'vigolium run --help') |
| `--skip-format-validation` | - | bool | `false` | Skip validation of input file format |
| `--skip-heuristics` | - | bool | `false` | Disable pre-scan heuristics (equivalent to --heuristics-check=none) |
| `--spec-default` | - | string | `1` | Fallback value for required OpenAPI parameters that lack examples |
| `--spec-header` | - | stringArray | - | Add HTTP header to OpenAPI-generated requests (repeatable; commas are literal) |
| `--spec-url` | - | bool | `false` | Use base URLs from the OpenAPI spec's servers field |
| `--spec-var` | - | stringSlice | - | Set OpenAPI parameter value as key=value (repeatable) |
| `--spider` | - | bool | `false` | Force the browser spidering phase on (balanced and deep already run it; --skip spidering turns it off) |
| `--spider-max-time` | - | duration | `30m0s` | Max time for spidering per target |
| `--split-by-host` | - | bool | `false` | In stateless multi-target mode (-S -T file), write a separate per-host output file (base-<host>.<ext>) instead of one unified file |
| `--stateless` | `-S` | bool | `false` | Use a temporary database that is discarded after the scan (pass --output/--format to persist results) |
| `--stats` | - | bool | `false` | Show live progress stats during scanning |
| `--strategy` | - | string | - | Advanced: which phases run (lite, balanced, deep); --intensity picks this for you |
| `--stream` | - | bool | `false` | Process targets as a stream without buffering or deduplication |
| `--target` | `-t` | stringArray | - | Target URL to scan (repeatable). Commas are literal so a URL query like ?ids=1,2,3 stays one target — repeat -t for multiple targets. |
| `--target-file` | `-T` | stringArray | - | File containing target URLs (one per line; repeatable for multiple files). Commas in the path are literal. |
| `--timeout` | - | duration | `15s` | HTTP request timeout (e.g. 30s, 1m, 2h) |
| `--tls-probe` | - | bool | `false` | Probe each HTTPS target's TLS: negotiated version/cipher plus the leaf certificate (subject, SANs, issuer, validity, fingerprints). Stored per host:port; read it with 'vigolium hosts -j' or as 'tls' on 'traffic -j' rows. Read by the probe phase (the fingerprint phase always probes HTTPS) |
| `--upload-results` | - | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |

## vigolium scan

Run a native scan — deterministic multi-phase vulnerability scanning

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--advanced-options` | `-a` | stringToString | - | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--all-records` | - | bool | `false` | Scan every HTTP record already stored in the active project (the database rescan). Required when no -t/-T/-i/stdin target is given; cannot be combined with them |
| `--allow-risky-payloads` | - | bool | `false` | Allow risk:high payloads and modules below --intensity deep (OR-per-row and stacked time-blind SQLi, so MSSQL time-blind; state-changing probes). Always on at deep. Overrides config dynamic-assessment.allow_risky_payloads |
| `--auth` | - | stringArray | - | Inline session in 'name:Header:value' format. Repeatable; commas are literal (header values may contain commas). |
| `--auth-file` | - | stringArray | - | Path to auth file (YAML/JSON, single session or sessions: bundle), or bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal. |
| `--baseline` | - | string | - | Previous run's findings (.jsonl export or .sqlite store): --fail-on counts only findings not in it; -j adds baseline{new,unchanged,fixed,ignored} |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine: 'chromium', 'ungoogled', or 'fingerprint' |
| `--browser-insecure` | - | bool | `false` | Spider with every browser security exception on: no sandbox, TLS errors ignored, mixed content allowed, same-origin policy off. For local test apps only |
| `--browsers` | `-b` | int | `1` | Browser instances to launch for spidering (clamped to 1; for parallel crawling set spidering.tabs in the config, which runs N tabs of the one browser) |
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--concurrency` | `-c` | int|phase=int | `25` | Number of concurrent scan workers. Accepts a phase qualifier, repeatable: --concurrency discovery=10 |
| `--db-isolate` | - | bool | `false` | Scan into a private temporary database, then merge results into --db (or the default DB) at the end — lets many parallel scans share one --db without write contention (SQLite only; ignored under --stateless, which keeps nothing to merge; combine with -P -T to fan out targets and export one unified output from the merged DB) |
| `--discover` | - | bool | `false` | Force the content discovery phase on (balanced and deep already run it; --skip discovery turns it off) |
| `--discover-max-time` | - | duration | `1h0m0s` | Max time for content discovery per target |
| `--discovery-extensions` | - | stringSlice | - | Extensions discovery also tries on every wordlist name, e.g. php,bak (ffuf's -e; leading dots optional). Swept directly, without the confirm-before-fuzzing gate that otherwise guards server-side extensions. Overrides discovery.extensions.custom_list |
| `--discovery-max-depth` | - | int | `0` | Maximum directory recursion depth for discovery (ffuf's -recursion-depth); 0 turns recursion off. Overrides discovery.recursion.max_depth (default 5) |
| `--discovery-wordlist` | - | stringArray | - | Custom wordlist file seeding the discovery phase's /FUZZ brute-force (enables fuzzing on the fly). Repeatable: the files are streamed in order and each word is tried once. A missing file is a usage error. Formerly --fuzz-wordlist; distinct from 'vigolium fuzz -w'. |
| `--dry-run` | - | bool | `false` | Resolve and print the scan plan — phases (with why each disabled one is off), budgets, pace, modules, scope, auth session names, scope admission and a rough request estimate — then exit without scanning. Mints no scan UUID, writes no output file or scan row, materializes no wordlist, runs no login and registers no OAST; an existing database is only read. -j prints it as a document (items = phases, plan = the full plan, dry_run: true) |
| `--events` | - | string | - | Emit a machine-readable event stream to stdout while the scan runs: 'ndjson' (one JSON object per line, flushed per event). The human console stays on stderr, so a driver reads the stream with 2>/dev/null. Events: scan.started, phase.started/progress/finished, waf.block, waf.pacing, finding.new, error, scan.finished. |
| `--export-only` | - | stringSlice | - | Limit the --format jsonl envelope to these record types (comma-separated: http, findings, scans, modules, oast, source-repos, scopes). Defaults to 'http' on a probe-only run, where every finding is a tech detection already carried on the record's technology field. |
| `--external-harvest` | - | bool | `false` | Enable external intelligence gathering phase (Wayback, CT logs, etc.) |
| `--fail-on` | - | string | - | Exit non-zero if a finding at or above this severity is present (info\|suspect\|low\|medium\|high\|critical); findings marked false_positive/accepted_risk do not count — for CI/agent gating. Scoped to this scan; implies --fail-on-partial; --soft-fail overrides; with -P it is evaluated per child. |
| `--fail-on-partial` | - | bool | `false` | Exit 5 (incomplete) when the scan's coverage was partial (a phase cut short, blocked, or failed); implied by --fail-on |
| `--favicon` | - | bool | `false` | Fetch each answering origin's icon once (the page's <link rel="icon">, else /favicon.ico; redirects not followed) and hash it: mmh3 (Shodan http.favicon.hash, FOFA icon_hash), MD5, SHA-256. Stored per host:port; read it as 'favicon_mmh3' with 'vigolium hosts', or as 'favicon' on 'traffic -j' rows and jsonl http_record lines. Read by the probe phase (the fingerprint phase always fetches the icon) |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--fingerprint-depth` | - | string | - | With the fingerprint phase: reads per origin, light\|standard\|full (default standard, light past 50 targets; 'vigolium fingerprint --depth') |
| `--follow-subdomains` | - | bool | `false` | Pull in-scope subdomains discovered in responses into the scan (exact hosts only, not the whole apex; auto-on at --intensity deep) |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--headed` | - | bool | `false` | Show the browser window during spidering (sugar for --headless=false; wins when both are set) |
| `--header` | `-H` | stringArray | - | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token'). Commas are literal — repeat -H for multiple headers. |
| `--header-fuzz` | - | string | - | Header insertion points: gated (default: noise headers skipped, logged/negotiation/routing headers once per host and only for the vuln classes they can sink) or all (every header, every module, per path). Overrides config dynamic-assessment.header_points |
| `--headless` | - | bool | `true` | Run browser in headless mode |
| `--heuristics-check` | - | string | - | Pre-scan heuristics level: none, basic, advanced (default: basic) |
| `--ignore-file` | - | string | - | YAML list of finding hashes to ignore ({hash, reason, expires}); default .vigolium-ignore.yaml when present |
| `--include-response` | - | bool | `false` | Include full HTTP response body in output |
| `--input` | `-i` | string | `-` | Input file path or spec (use - for stdin) |
| `--input-mode` | `-I` | string | `urls` | Input format: urls, nuclei, openapi, wsdl, postman, curl, burpraw, burpxml, burpscope, har, deparos (aliases accepted, see --list-input-mode) |
| `--input-read-timeout` | - | duration | `3m0s` | Deadline for reading input from stdin; 0 disables it |
| `--intensity` | - | string | - | How hard to scan: quick, balanced (default), or deep — the one dial for phases, pace and module tiers (sets --strategy and --scanning-profile) |
| `--keep-db-on-error` | - | bool | `false` | On a failed -S/--stateless scan, move the throwaway working database to ~/.vigolium/recovered instead of deleting it, so the partial results survive the failure (requires -S) |
| `--known-issue-scan-exclude-tags` | - | stringSlice | - | Nuclei template tags to exclude (comma-separated) |
| `--known-issue-scan-severities` | - | stringSlice | - | Filter Nuclei templates by severity (critical,high,medium,low,info) |
| `--known-issue-scan-tags` | - | stringSlice | - | Nuclei template tags to include (comma-separated) |
| `--known-issue-scan-templates` | - | stringArray | - | Run only these Nuclei templates (nuclei's -t for a file): a template file, or a path relative to the templates directory such as http/cves/2021/CVE-2021-44228.yaml. Repeatable; combined with --known-issue-scan-templates-dir, the named directories run too. |
| `--known-issue-scan-templates-dir` | - | stringArray | - | Custom Nuclei templates directory (alias: --templates-dir). Pin it to avoid the one-time clone into ~/nuclei-templates. Repeatable: the first replaces known_issue_scan.templates_dir, and every named directory is loaded. |
| `--limit` | `-n` | int | `200` | With -j: the most findings the scan document embeds in items, highest severity first (0 = no cap); total, counts_by_severity and query cover the rest |
| `--max-body-bytes` | - | int | `4096` | Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap |
| `--max-findings-per-module` | - | int | `50` | Stop reporting after N distinct findings per module; drops are counted in the summary and events (0 = unlimited) |
| `--max-host-error` | - | int | `30` | Skip host after reaching this many consecutive errors |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--max-per-host` | - | int|phase=int | `40` | Maximum concurrent requests allowed per host. Accepts a phase qualifier, repeatable: --max-per-host spidering=4 |
| `--max-requests` | - | int | `0` | Stop the scan after N requests to the targets (0 = unlimited). Exact for gated traffic; the browser crawl is held to it within 500ms; nuclei is not counted (see request_cap_enforcement on scan.started). A scan it stops is partial with stop_reason request_budget. Config: scanning_pace.max_requests |
| `--max-requests-per-host` | - | int | `0` | Send at most N requests to any one target host (0 = unlimited); further requests to that host fail fast and the phase records the host_request_budget limit. Config: scanning_pace.max_requests_per_host |
| `--max-time` | - | duration | `0s` | Maximum total scan duration, e.g. 15m, 2h (default: scanning_pace.scan_max_duration, 1h; alias --scanning-max-duration) |
| `--module-id` | - | stringSlice | - | Run exactly these module IDs (exact match against active AND passive modules, repeatable). Unlike -m, also selects passive modules. |
| `--module-tag` | - | stringSlice | - | Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection) |
| `--modules` | `-m` | stringSlice | - | Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli) |
| `--no-carry-browser-session` | - | bool | `false` | Do not carry the spidering browser's cleared session (cookies + UA) into discovery/scanning (on by default when --spider runs; scoped to the same host, respects -H) |
| `--no-cdp` | - | bool | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-clustering` | - | bool | `false` | Disable deduplication of identical concurrent HTTP requests |
| `--no-discovery-fuzz` | - | bool | `false` | Disable discovery's /FUZZ brute-force (alias --no-fuzz). Overrides every reason it would auto-enable — --intensity deep, a discovery-only run such as 'vigolium run discover', and the low-yield auto-enable. Link extraction, JS parsing, response-word harvesting and the short dir/file wordlists still run. |
| `--no-forms` | - | bool | `false` | Disable form filling and submission during spidering (sets spidering.interaction edit_fields and submit_forms off; an explicit interaction key wins) |
| `--no-param-dedup` | - | bool | `false` | Keep testing a parameter with every module of a vuln class after one already reported it (default: one finding per param and class, e.g. sqli-time-blind skips a param sqli-error-based confirmed). For audit runs |
| `--no-prefix-breaker` | - | bool | `false` | Disable per-prefix circuit breaker that stops discovery from recursing into trap directories |
| `--no-redact` | - | bool | `false` | Keep credential headers, cookie values and sensitive query parameters in HTML/PDF/SARIF/Markdown report evidence (redacted by default; also output.redact_evidence: false). JSONL and the database always keep the raw exchange |
| `--no-tech-filter` | - | bool | `false` | Disable the tech-stack allowlist (run every module regardless of detected stack). Auto-enabled by --intensity=deep. |
| `--no-waf-pacing` | - | bool | `false` | Disable proactive CDN/WAF-edge pacing (don't pre-throttle per-host concurrency when a CloudFront/Cloudflare/etc. edge is detected); reactive back-off after a WAF block still applies |
| `--oast-url` | - | string | - | Fixed out-of-band callback URL instead of interactsh; put {nonce} in it (https://{nonce}.cb.example.com) to attribute logged callbacks with 'vigolium oast ingest' |
| `--omit-response` | - | bool | `false` | Omit raw HTTP request/response bytes from output file (keeps metadata, smaller files) |
| `--only` | - | string | - | Run only these phases (comma-separated: ingestion, probe, fingerprint, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension, heuristics-check, port-sweep, targeted-respider; aliases accepted, see 'vigolium run --help') |
| `--output` | `-o` | string | - | Write findings to specified output file |
| `--parallel` | `-P` | int | `1` | Scan up to N targets concurrently as isolated child processes (requires -S -T --split-by-host, OR --db-isolate -T which merges into --db and exports one unified output; each target keeps its own --concurrency, so real in-flight requests ≈ N × --concurrency) |
| `--param-mining` | - | bool | `false` | Mine hidden parameters (Arjun-style) on this scan's dynamic endpoints before the assessment, so injection modules test them too. Default: on at --intensity deep, off below; --param-mining=false turns it off at deep. Budget: dynamic-assessment.param_mining in config |
| `--passive-only` | - | bool | `false` | Run only passive modules (no active scanning). Combine with --module-id to narrow to specific passive modules. |
| `--pdf-timeout` | - | duration | `0s` | Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else 1m30s) |
| `--port-sweep-ports` | - | string | - | Override the alternate HTTP(S) ports swept on CLI target hosts (comma-separated; sweep runs at --intensity deep or --follow-subdomains) |
| `--print-finding` | - | bool | `false` | After the scan, print each finding to stdout as Markdown (description + matched evidence + request/response), like 'vigolium finding --markdown'. Pairs well with -S and --silent for a quick scan. |
| `--print-traffic` | - | bool | `false` | After the scan, print the run's raw HTTP request/response pairs to stdout, like 'vigolium traffic --raw'. Pairs well with -S and --silent. |
| `--print-traffic-tree` | - | bool | `false` | After the scan, print the run's HTTP traffic to stdout as a host/path hierarchy tree, like 'vigolium traffic --tree'. Pairs well with -S and --silent. |
| `--probe` | - | bool | `false` | Enable the host-sweep phase: one request per target, passive tech fingerprinting + surface scoring, no content discovery or fuzzing (same as 'vigolium run probe') |
| `--rate-limit` | `-r` | int|phase=int | `100` | Global requests/second cap, applied to native scanning AND known-issue-scan. Applies at its documented default even when unset; pass 0 for no cap. Accepts a phase qualifier, repeatable: --rate-limit known-issue-scan=20 |
| `--record-redirect-chain` | - | bool | `false` | Store a followed redirect's hops as their own http_records rows, chained by parent_uuid, instead of keeping only the final response. Canonical hops (scheme upgrade, trailing slash, www.) collapse into their destination row, and a chain stores at most 4 rows, keeping the first and the last. Read by the probe phase; on by default under 'run probe'. |
| `--redirect-mode` | - | string | - | Which redirects to follow: off \| same-host \| same-apex \| in-scope \| any (default in-scope; 'run probe' defaults to same-apex). 'in-scope' follows a hop only to a host the scan scope admits (same-apex when no scope is set). 'same-apex' follows within the registrable domain, so www.example.com -> example.com follows but example.com -> tracker.example.net does not. A hop to another host never carries session or -H headers. Every mode also stops at a login/SSO wall, whatever its host, and records the 3xx instead. |
| `--report-url` | - | string | - | URL for the "Raw Report URL" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL) |
| `--require-auth` | - | bool | `false` | Fail a target's spidering instead of crawling anonymously when configured authentication (session cookies/auth headers) cannot be applied to the browser (sets spidering.require_auth) |
| `--required-only` | - | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--resume` | - | bool | `false` | Resume a prior -S -T --split-by-host -P run from its progress manifest (<output>.progress.json): skip targets that already completed cleanly and scan only the remainder. Run bare ('vigolium scan --resume', no other flags) to auto-discover the *.progress.json in the current directory and relaunch the saved run from it (pass -o <prefix> to disambiguate when several exist) |
| `--resume-scan` | - | string | - | Resume a previous scan by UUID: reuse its scan row and cursor and skip the records/modules its coverage ledger records as done |
| `--retries` | - | int | `1` | Number of retry attempts for failed requests |
| `--safe` | - | bool | `false` | Bounded, non-mutating scan: GET/HEAD traffic only, no form submission/uploads/login attempts in the browser, no risky payloads or intrusive templates, low pace, 15m total budget (typed flags still win) |
| `--scanning-profile` | - | string | - | Advanced: scanning profile name or YAML file path (pace, discovery depth, templates); --intensity picks this for you |
| `--scope-origin` | - | string | - | Host scope strictness: all, relaxed, balanced, strict (default balanced; balanced admits any host sharing the target's eTLD+1, including subdomains already in the database from earlier scans). Bounds which STORED records a phase works and, under the default --redirect-mode in-scope, which hosts a redirect may follow to |
| `--skip` | - | stringSlice | - | Skip these phases (repeatable: ingestion, probe, fingerprint, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension, heuristics-check, port-sweep, harvest-probe, targeted-respider, param-mining, preflight; aliases accepted, see 'vigolium run --help') |
| `--skip-format-validation` | - | bool | `false` | Skip validation of input file format |
| `--skip-heuristics` | - | bool | `false` | Disable pre-scan heuristics (equivalent to --heuristics-check=none) |
| `--spec-default` | - | string | `1` | Fallback value for required OpenAPI parameters that lack examples |
| `--spec-header` | - | stringArray | - | Add HTTP header to OpenAPI-generated requests (repeatable; commas are literal) |
| `--spec-url` | - | bool | `false` | Use base URLs from the OpenAPI spec's servers field |
| `--spec-var` | - | stringSlice | - | Set OpenAPI parameter value as key=value (repeatable) |
| `--spider` | - | bool | `false` | Force the browser spidering phase on (balanced and deep already run it; --skip spidering turns it off) |
| `--spider-max-time` | - | duration | `30m0s` | Max time for spidering per target |
| `--split-by-host` | - | bool | `false` | In stateless multi-target mode (-S -T file), write a separate per-host output file (base-<host>.<ext>) instead of one unified file |
| `--stateless` | `-S` | bool | `false` | Use a temporary database that is discarded after the scan (pass --output/--format to persist results) |
| `--stats` | - | bool | `false` | Show live progress stats during scanning |
| `--strategy` | - | string | - | Advanced: which phases run (lite, balanced, deep); --intensity picks this for you |
| `--stream` | - | bool | `false` | Process targets as a stream without buffering or deduplication |
| `--target` | `-t` | stringArray | - | Target URL to scan (repeatable). Commas are literal so a URL query like ?ids=1,2,3 stays one target — repeat -t for multiple targets. |
| `--target-file` | `-T` | stringArray | - | File containing target URLs (one per line; repeatable for multiple files). Commas in the path are literal. |
| `--timeout` | - | duration | `15s` | HTTP request timeout (e.g. 30s, 1m, 2h) |
| `--tls-probe` | - | bool | `false` | Probe each HTTPS target's TLS: negotiated version/cipher plus the leaf certificate (subject, SANs, issuer, validity, fingerprints). Stored per host:port; read it with 'vigolium hosts -j' or as 'tls' on 'traffic -j' rows. Read by the probe phase (the fingerprint phase always probes HTTPS) |
| `--upload-results` | - | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |

## vigolium scan diff

Usage: `vigolium scan diff <base-scan> <head-scan>`

Compare two scans' findings: new, fixed, not re-observed, unchanged

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--fail-on-new` | - | string | - | Exit 4 when a NEW finding is at or above this severity (info\|suspect\|low\|medium\|high\|critical) |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--glob-db` | - | string | - | Read across a glob of result files merged into one temporary DB; implies -S |
| `--ignore-file` | - | string | - | YAML list of finding hashes to leave out of `new` ({hash, reason, expires}); default .vigolium-ignore.yaml when present |
| `--include-dismissed` | - | bool | `false` | Keep findings marked false_positive or accepted_risk |
| `--last` | - | int | `2` | With --target: compare the N-th most recent scan of the target against the most recent (N >= 2) |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--output` | `-o` | string | - | With --json: write the result document to this file and print a receipt instead; '-' forces stdout |
| `--stateless` | `-S` | bool | `false` | Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB |
| `--target` | - | string | - | Compare the scans of this target (with --last) instead of naming two scans |

## vigolium scan status

Usage: `vigolium scan status <scan-uuid>`

Show a scan's live status: phase, progress, liveness and ETA

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--glob-db` | - | string | - | Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S |
| `--stateless` | `-S` | bool | `false` | Read from --db (a .jsonl export or standalone .sqlite) with project scoping off |

## vigolium scan wait

Usage: `vigolium scan wait <scan-uuid>`

Block until a scan finishes, then print its summary and exit with its outcome

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--events` | - | string | - | Stream progress as NDJSON on stdout (value: ndjson): phase.progress lines, then scan.finished |
| `--fail-on` | - | string | - | Exit non-zero if a finding at or above this severity is present (info\|suspect\|low\|medium\|high\|critical); findings marked false_positive/accepted_risk do not count — evaluated on the finished scan (exit 4); --soft-fail overrides. |
| `--fail-on-partial` | - | bool | `false` | Exit 5 (error.code partial) when the scan completed with partial coverage |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--limit` | `-n` | int | `200` | With -j: the most findings the scan document embeds in items, highest severity first (0 = no cap); total, counts_by_severity and query cover the rest |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--poll` | - | duration | `2s` | How often to re-read the scan's status |
| `--stateless` | `-S` | bool | `false` | Read from --db (a standalone .sqlite) with project scoping off |
| `--timeout` | - | duration | `30m0s` | Give up after this long (exit 1, error.code wait_timeout); 0 waits indefinitely |

## vigolium scan-request

Scan a raw HTTP request for vulnerabilities

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--allow-risky-payloads` | - | bool | `false` | Allow risk:high payloads and modules below --intensity deep (OR-per-row and stacked time-blind SQLi, so MSSQL time-blind; state-changing probes). Always on at deep. Overrides config dynamic-assessment.allow_risky_payloads |
| `--auth` | - | stringArray | - | Inline session in 'name:Header:value' format. Repeatable; commas are literal (header values may contain commas). |
| `--auth-file` | - | stringArray | - | Path to auth file (YAML/JSON, single session or sessions: bundle), or bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal. |
| `--baseline` | - | string | - | Previous run's findings (.jsonl export or .sqlite store): --fail-on counts only findings not in it; -j adds baseline{new,unchanged,fixed,ignored} |
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--concurrency` | `-c` | int|phase=int | `25` | Number of concurrent scan workers. Accepts a phase qualifier, repeatable: --concurrency discovery=10 |
| `--discover` | - | bool | `false` | Run content discovery before scanning |
| `--events` | - | string | - | Emit a machine-readable event stream to stdout while the scan runs: 'ndjson' (one JSON object per line, flushed per event). The human console stays on stderr, so a driver reads the stream with 2>/dev/null. Events: scan.started, phase.started/progress/finished, waf.block, waf.pacing, finding.new, error, scan.finished. |
| `--external-harvest` | - | bool | `false` | Run external intelligence harvesting before scanning |
| `--fail-on` | - | string | - | Exit non-zero if a finding at or above this severity is present (info\|suspect\|low\|medium\|high\|critical); findings marked false_positive/accepted_risk do not count — for CI/agent gating; implies --fail-on-partial; --soft-fail overrides. |
| `--fail-on-partial` | - | bool | `false` | Exit 5 (incomplete) when the scan's coverage was partial (a phase cut short, blocked, or failed); implied by --fail-on |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--header` | `-H` | stringArray | - | Set a header on the captured request (repeatable, e.g. -H 'Cookie: a=1'): replaces every same-named captured header, else appends. Commas are literal — repeat -H for multiple headers. |
| `--ignore-file` | - | string | - | YAML list of finding hashes to ignore ({hash, reason, expires}); default .vigolium-ignore.yaml when present |
| `--ignore-scope` | - | bool | `false` | Scan the target even when the configured scope rejects it (relaxes scope.host/scope.path for this run) |
| `--input` | `-i` | string | `-` | Input file or - for stdin |
| `--input-read-timeout` | - | duration | `3m0s` | Deadline for reading input from stdin; 0 disables it |
| `--intensity` | - | string | - | How hard to scan: quick, balanced (default), or deep — the one dial for phases, pace and module tiers (sets --strategy and --scanning-profile) |
| `--keep-db-on-error` | - | bool | `false` | On a failed -S/--stateless scan, move the throwaway working database to ~/.vigolium/recovered instead of deleting it, so the partial results survive the failure (requires -S) |
| `--known-issue-scan` | - | bool | `false` | Run known issue scan (Nuclei + native secret scanning) |
| `--limit` | `-n` | int | `200` | With -j: the most findings the scan document embeds in items, highest severity first (0 = no cap); total, counts_by_severity and query cover the rest |
| `--max-body-bytes` | - | int | `4096` | Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap |
| `--max-findings-per-module` | - | int | `50` | Stop reporting after N distinct findings per module; drops are counted in the summary and events (0 = unlimited) |
| `--max-host-error` | - | int | `30` | Skip host after reaching this many consecutive errors |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--max-per-host` | - | int|phase=int | `40` | Maximum concurrent requests allowed per host. Accepts a phase qualifier, repeatable: --max-per-host spidering=4 |
| `--max-requests` | - | int | `0` | Stop the scan after N requests to the targets (0 = unlimited). Exact for gated traffic; the browser crawl is held to it within 500ms; nuclei is not counted (see request_cap_enforcement on scan.started). A scan it stops is partial with stop_reason request_budget. Config: scanning_pace.max_requests |
| `--max-requests-per-host` | - | int | `0` | Send at most N requests to any one target host (0 = unlimited); further requests to that host fail fast and the phase records the host_request_budget limit. Config: scanning_pace.max_requests_per_host |
| `--max-time` | - | duration | `0s` | Maximum total scan duration, e.g. 15m, 2h (default: scanning_pace.scan_max_duration, 1h; alias --scanning-max-duration) |
| `--module-id` | - | stringSlice | - | Run exactly these module IDs (exact match against active AND passive modules, repeatable). Unlike -m, also selects passive modules. |
| `--module-tag` | - | stringSlice | - | Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection) |
| `--modules` | `-m` | stringSlice | - | Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli) |
| `--no-clustering` | - | bool | `false` | Disable deduplication of identical concurrent HTTP requests |
| `--no-param-dedup` | - | bool | `false` | Keep testing a parameter with every module of a vuln class after one already reported it (default: one finding per param and class, e.g. sqli-time-blind skips a param sqli-error-based confirmed). For audit runs |
| `--no-passive` | - | bool | `false` | Skip passive modules |
| `--no-redact` | - | bool | `false` | Keep credential headers, cookie values and sensitive query parameters in HTML/PDF/SARIF/Markdown report evidence (redacted by default; also output.redact_evidence: false). JSONL and the database always keep the raw exchange |
| `--no-scheme-probe` | - | bool | `false` | Do not probe the target (TCP connect / TLS handshake) when the request carries no scheme signal; keep the https default |
| `--no-tech-filter` | - | bool | `false` | Disable the tech-stack allowlist (run every module regardless of detected stack). Auto-enabled by --intensity=deep. |
| `--no-waf-pacing` | - | bool | `false` | Disable proactive CDN/WAF-edge pacing (don't pre-throttle per-host concurrency when a CloudFront/Cloudflare/etc. edge is detected); reactive back-off after a WAF block still applies |
| `--oast-url` | - | string | - | Fixed out-of-band callback URL instead of interactsh; put {nonce} in it (https://{nonce}.cb.example.com) to attribute logged callbacks with 'vigolium oast ingest' |
| `--output` | `-o` | string | - | Write findings to this file (use with --format jsonl\|html; pairs with -S/--stateless) |
| `--passive-only` | - | bool | `false` | Run only passive modules (no active scanning). Combine with --module-id to narrow to specific passive modules. |
| `--pdf-timeout` | - | duration | `0s` | Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else 1m30s) |
| `--print-finding` | - | bool | `false` | After the scan, print each finding to stdout as Markdown (description + matched evidence + request/response), like 'vigolium finding --markdown'. Pairs well with -S and --silent for a quick single-target scan. |
| `--print-traffic` | - | bool | `false` | After the scan, print the run's raw HTTP request/response pairs to stdout, like 'vigolium traffic --raw'. Pairs well with -S and --silent. |
| `--print-traffic-tree` | - | bool | `false` | After the scan, print the run's HTTP traffic to stdout as a host/path hierarchy tree, like 'vigolium traffic --tree'. Pairs well with -S and --silent. |
| `--rate-limit` | `-r` | int|phase=int | `100` | Global requests/second cap, applied to native scanning AND known-issue-scan. Applies at its documented default even when unset; pass 0 for no cap. Accepts a phase qualifier, repeatable: --rate-limit known-issue-scan=20 |
| `--safe` | - | bool | `false` | Bounded, non-mutating scan: GET/HEAD traffic only, no form submission/uploads/login attempts in the browser, no risky payloads or intrusive templates, low pace, 15m total budget (typed flags still win) |
| `--scope-origin` | - | string | - | Host scope strictness: all, relaxed, balanced, strict (default balanced; balanced admits any host sharing the target's eTLD+1, including subdomains already in the database from earlier scans). Bounds which STORED records a phase works and, under the default --redirect-mode in-scope, which hosts a redirect may follow to |
| `--skip` | - | stringSlice | - | Skip these phases (repeatable: ingestion, probe, fingerprint, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension, heuristics-check, port-sweep, harvest-probe, targeted-respider, param-mining, preflight; aliases accepted, see 'vigolium run --help') |
| `--spider` | - | bool | `false` | Run browser-based spidering before scanning |
| `--stateless` | `-S` | bool | `false` | Use a temporary database that is discarded after the scan (pass --output/--format to persist results) |
| `--target` | `-t` | string | - | Override target URL (scheme://host) |
| `--timeout` | - | duration | `15s` | HTTP request timeout (e.g. 30s, 1m, 2h) |

## vigolium scan-url

Usage: `vigolium scan-url [url]`

Scan a single URL for vulnerabilities

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--allow-risky-payloads` | - | bool | `false` | Allow risk:high payloads and modules below --intensity deep (OR-per-row and stacked time-blind SQLi, so MSSQL time-blind; state-changing probes). Always on at deep. Overrides config dynamic-assessment.allow_risky_payloads |
| `--auth` | - | stringArray | - | Inline session in 'name:Header:value' format. Repeatable; commas are literal (header values may contain commas). |
| `--auth-file` | - | stringArray | - | Path to auth file (YAML/JSON, single session or sessions: bundle), or bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal. |
| `--baseline` | - | string | - | Previous run's findings (.jsonl export or .sqlite store): --fail-on counts only findings not in it; -j adds baseline{new,unchanged,fixed,ignored} |
| `--body` | - | string | - | Request body |
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--concurrency` | `-c` | int|phase=int | `25` | Number of concurrent scan workers. Accepts a phase qualifier, repeatable: --concurrency discovery=10 |
| `--discover` | - | bool | `false` | Run content discovery before scanning |
| `--events` | - | string | - | Emit a machine-readable event stream to stdout while the scan runs: 'ndjson' (one JSON object per line, flushed per event). The human console stays on stderr, so a driver reads the stream with 2>/dev/null. Events: scan.started, phase.started/progress/finished, waf.block, waf.pacing, finding.new, error, scan.finished. |
| `--external-harvest` | - | bool | `false` | Run external intelligence harvesting before scanning |
| `--fail-on` | - | string | - | Exit non-zero if a finding at or above this severity is present (info\|suspect\|low\|medium\|high\|critical); findings marked false_positive/accepted_risk do not count — for CI/agent gating; implies --fail-on-partial; --soft-fail overrides. |
| `--fail-on-partial` | - | bool | `false` | Exit 5 (incomplete) when the scan's coverage was partial (a phase cut short, blocked, or failed); implied by --fail-on |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--header` | `-H` | stringArray | - | Custom header (repeatable, e.g. -H 'Cookie: x=1'). Commas are literal — repeat -H for multiple headers. |
| `--ignore-file` | - | string | - | YAML list of finding hashes to ignore ({hash, reason, expires}); default .vigolium-ignore.yaml when present |
| `--ignore-scope` | - | bool | `false` | Scan the target even when the configured scope rejects it (relaxes scope.host/scope.path for this run) |
| `--input-read-timeout` | - | duration | `3m0s` | Deadline for reading input from stdin; 0 disables it |
| `--intensity` | - | string | - | How hard to scan: quick, balanced (default), or deep — the one dial for phases, pace and module tiers (sets --strategy and --scanning-profile) |
| `--keep-db-on-error` | - | bool | `false` | On a failed -S/--stateless scan, move the throwaway working database to ~/.vigolium/recovered instead of deleting it, so the partial results survive the failure (requires -S) |
| `--known-issue-scan` | - | bool | `false` | Run known issue scan (Nuclei + native secret scanning) |
| `--limit` | `-n` | int | `200` | With -j: the most findings the scan document embeds in items, highest severity first (0 = no cap); total, counts_by_severity and query cover the rest |
| `--max-body-bytes` | - | int | `4096` | Cap each HTTP request/response embedded in a Markdown report at this many bytes (UTF-8 safe, with a note naming the command that prints it whole); 0 or negative = no cap |
| `--max-findings-per-module` | - | int | `50` | Stop reporting after N distinct findings per module; drops are counted in the summary and events (0 = unlimited) |
| `--max-host-error` | - | int | `30` | Skip host after reaching this many consecutive errors |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--max-per-host` | - | int|phase=int | `40` | Maximum concurrent requests allowed per host. Accepts a phase qualifier, repeatable: --max-per-host spidering=4 |
| `--max-requests` | - | int | `0` | Stop the scan after N requests to the targets (0 = unlimited). Exact for gated traffic; the browser crawl is held to it within 500ms; nuclei is not counted (see request_cap_enforcement on scan.started). A scan it stops is partial with stop_reason request_budget. Config: scanning_pace.max_requests |
| `--max-requests-per-host` | - | int | `0` | Send at most N requests to any one target host (0 = unlimited); further requests to that host fail fast and the phase records the host_request_budget limit. Config: scanning_pace.max_requests_per_host |
| `--max-time` | - | duration | `0s` | Maximum total scan duration, e.g. 15m, 2h (default: scanning_pace.scan_max_duration, 1h; alias --scanning-max-duration) |
| `--method` | - | string | `GET` | HTTP method |
| `--module-id` | - | stringSlice | - | Run exactly these module IDs (exact match against active AND passive modules, repeatable). Unlike -m, also selects passive modules. |
| `--module-tag` | - | stringSlice | - | Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection) |
| `--modules` | `-m` | stringSlice | - | Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli) |
| `--no-clustering` | - | bool | `false` | Disable deduplication of identical concurrent HTTP requests |
| `--no-param-dedup` | - | bool | `false` | Keep testing a parameter with every module of a vuln class after one already reported it (default: one finding per param and class, e.g. sqli-time-blind skips a param sqli-error-based confirmed). For audit runs |
| `--no-passive` | - | bool | `false` | Skip passive modules |
| `--no-redact` | - | bool | `false` | Keep credential headers, cookie values and sensitive query parameters in HTML/PDF/SARIF/Markdown report evidence (redacted by default; also output.redact_evidence: false). JSONL and the database always keep the raw exchange |
| `--no-tech-filter` | - | bool | `false` | Disable the tech-stack allowlist (run every module regardless of detected stack). Auto-enabled by --intensity=deep. |
| `--no-waf-pacing` | - | bool | `false` | Disable proactive CDN/WAF-edge pacing (don't pre-throttle per-host concurrency when a CloudFront/Cloudflare/etc. edge is detected); reactive back-off after a WAF block still applies |
| `--oast-url` | - | string | - | Fixed out-of-band callback URL instead of interactsh; put {nonce} in it (https://{nonce}.cb.example.com) to attribute logged callbacks with 'vigolium oast ingest' |
| `--output` | `-o` | string | - | Write findings to this file (use with --format jsonl\|html; pairs with -S/--stateless) |
| `--passive-only` | - | bool | `false` | Run only passive modules (no active scanning). Combine with --module-id to narrow to specific passive modules. |
| `--pdf-timeout` | - | duration | `0s` | Bound the headless-Chrome PDF render (0 = $VIGOLIUM_PDF_TIMEOUT, else 1m30s) |
| `--print-finding` | - | bool | `false` | After the scan, print each finding to stdout as Markdown (description + matched evidence + request/response), like 'vigolium finding --markdown'. Pairs well with -S and --silent for a quick single-target scan. |
| `--print-traffic` | - | bool | `false` | After the scan, print the run's raw HTTP request/response pairs to stdout, like 'vigolium traffic --raw'. Pairs well with -S and --silent. |
| `--print-traffic-tree` | - | bool | `false` | After the scan, print the run's HTTP traffic to stdout as a host/path hierarchy tree, like 'vigolium traffic --tree'. Pairs well with -S and --silent. |
| `--rate-limit` | `-r` | int|phase=int | `100` | Global requests/second cap, applied to native scanning AND known-issue-scan. Applies at its documented default even when unset; pass 0 for no cap. Accepts a phase qualifier, repeatable: --rate-limit known-issue-scan=20 |
| `--safe` | - | bool | `false` | Bounded, non-mutating scan: GET/HEAD traffic only, no form submission/uploads/login attempts in the browser, no risky payloads or intrusive templates, low pace, 15m total budget (typed flags still win) |
| `--scope-origin` | - | string | - | Host scope strictness: all, relaxed, balanced, strict (default balanced; balanced admits any host sharing the target's eTLD+1, including subdomains already in the database from earlier scans). Bounds which STORED records a phase works and, under the default --redirect-mode in-scope, which hosts a redirect may follow to |
| `--skip` | - | stringSlice | - | Skip these phases (repeatable: ingestion, probe, fingerprint, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension, heuristics-check, port-sweep, harvest-probe, targeted-respider, param-mining, preflight; aliases accepted, see 'vigolium run --help') |
| `--spider` | - | bool | `false` | Run browser-based spidering before scanning |
| `--stateless` | `-S` | bool | `false` | Use a temporary database that is discarded after the scan (pass --output/--format to persist results) |
| `--target` | `-t` | stringArray | - | Target URL to scan (repeatable; alternative to the positional URL argument). Commas are literal. |
| `--timeout` | - | duration | `15s` | HTTP request timeout (e.g. 30s, 1m, 2h) |

## vigolium schema

Print the JSON Schema of -j documents, --events lines and the error envelope

_No command-specific flags._

## vigolium schema all

Print every schema in one object

_No command-specific flags._

## vigolium schema command

Usage: `vigolium schema command <name>`

Print one command's -j document schema

_No command-specific flags._

## vigolium schema error

Print the -j error envelope schema (error.code is a closed enum)

_No command-specific flags._

## vigolium schema event

Usage: `vigolium schema event [type]`

Print the schema of one --events line type, or of any line

_No command-specific flags._

## vigolium schema flags

Usage: `vigolium schema flags <command>`

List one command's flags, one entry per flag (the --usage view as data)

_No command-specific flags._

## vigolium schema list

Aliases: `ls`

List the commands, event types and documents that have a schema

_No command-specific flags._

## vigolium schema plan

Print the scan plan schema (scan --dry-run, the scan.plan event)

_No command-specific flags._

## vigolium schema storage

Usage: `vigolium schema storage [table]`

Describe the database: tables, columns, and the -j field each column surfaces as

_No command-specific flags._

## vigolium scope

Aliases: `sc`

Manage scan scope rules

_No command-specific flags._

## vigolium scope set

Usage: `vigolium scope set <component.field> <value>`

Set a scope rule

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--project` | - | string | - | Write the rule to this project's config overlay instead of the global config |

## vigolium scope view

Usage: `vigolium scope view [component]`

Aliases: `ls`, `list`

Display current scope configuration

_No command-specific flags._

## vigolium server

Serve the REST API, ingest live traffic, and scan it as it arrives

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--alternative-ingest-key` | - | stringSlice | - | Additional API key for ingestion endpoints (repeatable) |
| `--burp-bridge-url` | `-B` | string | - | Merge live proxy traffic from this loopback Burp/Caido bridge URL into /api/http-records (alias: --caido-bridge-url) |
| `--catchup-threads` | - | int | `4` | Deprecated: no-op (catch-up scanning is disabled) |
| `--demo-only` | - | bool | `false` | Expose only the demo allowlist: GET /api/findings[/:id], /api/http-records[/:uuid], /api/modules, /api/stats, /api/extensions[/:name\|/docs] |
| `--disable-catchup` | - | bool | `false` | Deprecated: no-op (catch-up scanning is already disabled) |
| `--disable-warm-session` | - | bool | `false` | Disable agent subprocess warm session pooling |
| `--discard-queued` | - | bool | `false` | Drop tasks a previous run left in the disk-spill queue instead of resuming them (tasks older than 24h are always dropped) |
| `--full-native-scan-on-receive` | - | bool | `false` | Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records, instead of dynamic-assessment only |
| `--host` | - | string | `127.0.0.1` | Bind address for the API server ($VIGOLIUM_SERVER_HOST when unset; use 0.0.0.0 to expose it) |
| `--ingest-proxy-host` | - | string | `127.0.0.1` | Bind address for the ingest proxy (config server.ingest_proxy_host). A non-loopback address needs --proxy-token or --proxy-allow |
| `--ingest-proxy-port` | - | int | `0` | Transparent HTTP proxy port for recording traffic (0 = disabled) |
| `--mem-buffer` | - | int | `10000` | In-memory queue capacity before spilling to disk |
| `--mirror-fs` | - | string | - | Mirror ingested traffic + findings to a live flat filesystem tree under this dir (<dir>/traffic, <dir>/findings), in addition to the database — readable by an external agent with ls/grep/jq |
| `--no-agent` | - | bool | `false` | Disable all agent endpoints and warm session pooling |
| `--no-auth` | `-A` | bool | `false` | Run server without API key authentication |
| `--no-swagger` | - | bool | `false` | Disable Swagger UI and API spec endpoint |
| `--output` | `-o` | string | - | Write findings to specified output file |
| `--passive-only` | - | bool | `false` | With --scan-on-receive, run passive modules only (no active scan traffic; includes secret detection) |
| `--proxy-allow` | - | stringArray | - | Accept ingest-proxy clients only from this CIDR or IP (repeatable; config server.ingest_proxy_allow) |
| `--proxy-insecure` | - | bool | `false` | When intercepting HTTPS (--proxy-mitm), skip verification of the upstream server's TLS certificate |
| `--proxy-mitm` | - | bool | `false` | Intercept HTTPS through --ingest-proxy-port using a generated CA so TLS traffic is recorded (and scanned with --scan-on-receive). Trust it with 'vigolium server ca install' |
| `--proxy-token` | - | string | - | Require this secret on every ingest-proxy request as Proxy-Authorization (Basic with any username, or Bearer); config server.ingest_proxy_token |
| `--scan-on-receive` | - | bool | `false` | Continuously scan new HTTP records as they arrive in the database |
| `--service-port` | - | int | `9002` | Port for the REST API server |
| `--timeout` | - | duration | `15s` | HTTP request timeout for background scan workers (e.g. 30s, 1m) |
| `--view-only` | - | bool | `false` | Run server in read-only mode (disables scanning, ingestion, agent, and all write endpoints) |

## vigolium server ca

Show, export and trust the ingest-proxy MITM CA certificate

_No command-specific flags._

## vigolium server ca install

Trust the MITM CA on this machine (prints the commands; --yes runs them)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--yes` | - | bool | `false` | Run the commands instead of printing them (may prompt for sudo) |

## vigolium server ca path

Print the path of the MITM CA certificate

_No command-specific flags._

## vigolium server ca print

Print the MITM CA certificate (PEM), or write it with --out

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--out` | - | string | - | Write the PEM certificate to this file instead of stdout |

## vigolium server ca uninstall

Remove trust in the MITM CA (prints the commands; --yes runs them)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--yes` | - | bool | `false` | Run the commands instead of printing them (may prompt for sudo) |

## vigolium skills

Usage: `vigolium skills [subcommand]`

Aliases: `skill`

List, inspect, and install bundled coding-agent skills

_No command-specific flags._

## vigolium skills get

Usage: `vigolium skills get [name...]`

Print a skill's full content

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all` | - | bool | `false` | Output every bundled skill |
| `--full` | - | bool | `false` | Include reference files, not just SKILL.md |

## vigolium skills install

Usage: `vigolium skills install [name...]`

Install skill bundle(s) into a coding agent's skills directory

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | - | string | `claude` | Target coding agent: claude, codex, or agents |
| `--all` | - | bool | `false` | Install every bundled skill |
| `--dir` | - | string | - | Override the destination directory (skips --agent/--scope resolution) |
| `--scope` | - | string | `project` | Install scope: project (current folder) or global (home dir) |

## vigolium skills list

Aliases: `ls`

List all bundled skills

_No command-specific flags._

## vigolium storage

Interact with cloud object storage (uploads, downloads, presigned URLs)

_No command-specific flags._

## vigolium storage download

Usage: `vigolium storage download <key>`

Aliases: `get`

Download an object from cloud storage

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | - | Write to this file instead of stdout |

## vigolium storage ls

Aliases: `list`

List objects in cloud storage for the active project

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--prefix` | - | string | - | Limit results to keys under this prefix |
| `--tree` | - | bool | `false` | Render objects as a directory tree |

## vigolium storage presign

Generate a presigned upload or download URL

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--expiry` | - | duration | `1h0m0s` | URL validity duration (e.g. 30m, 1h, 24h) |
| `--key` | - | string | - | Object key (required) |
| `--method` | - | string | `GET` | HTTP method: GET or PUT |

## vigolium storage results

Usage: `vigolium storage results <scan-uuid>`

Download the result bundle for a scan

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | - | Write to this file (default: results-<uuid>.tar.gz in cwd) |

## vigolium storage rm

Usage: `vigolium storage rm <key> [<key>...]`

Aliases: `delete`

Delete one or more objects from cloud storage

_No command-specific flags._

## vigolium storage upload

Usage: `vigolium storage upload <file>`

Upload a file to cloud storage

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--content-type` | - | string | - | Content-Type to set on the object |
| `--key` | - | string | - | Object key (default: ugc/<basename>) |

## vigolium strategy

Aliases: `st`, `phase`

Show scanning strategies, phases, intensities, and agent modes

_No command-specific flags._

## vigolium traffic

Usage: `vigolium traffic [search-term]`

Aliases: `traffics`, `tf`

Browse or replay HTTP traffic (alias: db ls --table http_records)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--all` | `-a` | bool | `false` | List/replay every matched record (ignore the -n/--limit cap); pair with --replay to re-send all stored traffic |
| `--asc` | - | bool | `false` | Sort in ascending order (default: descending) |
| `--body` | - | string | - | Search only the HTTP request/response body (not headers); use --search to span the whole exchange |
| `--burp` | - | bool | `false` | Display in Burp Suite-style format (colored request/response) |
| `--burp-bridge-url` | `-B` | string | - | Merge live traffic from this loopback Burp/Caido bridge URL with local database records (alias: --caido-bridge-url) |
| `--columns` | - | stringSlice | - | Columns to show (comma-separated, e.g. HOST,METHOD,PATH,STATUS) |
| `--compact` | - | bool | `false` | With --json, emit metadata only (omit request/response bodies). --markdown already compacts response bodies by default; use --full-body to render them whole |
| `--concurrency` | `-c` | int | `10` | Concurrent replays (--replay); keep low to avoid overwhelming an intercepting proxy like Burp |
| `--curl` | - | bool | `false` | Render each matched record as a curl command (URL from the stored scheme/host/port; renders at most 20 without -a); -j gives {uuid, url, curl, argv} |
| `--exclude-body` | - | string | - | Exclude records whose request/response body contains the term (inverse of --body; bodies only, not headers) |
| `--exclude-columns` | - | stringSlice | - | Columns to hide (comma-separated) |
| `--exclude-header` | - | string | - | Exclude records whose HTTP header block contains the term (inverse of --header; headers only, not bodies) |
| `--exclude-not-found` | - | bool | `false` | Drop records that are their origin's not-found page: a 404/410, or a response matching the not-found baseline 'vigolium fingerprint' stored (applied to the returned page) |
| `--exclude-search` | - | stringArray | - | Exclude records where the term appears in the URL, path, or raw request/response (repeatable; dropped if ANY term matches — the inverse of --search) |
| `--fields` | - | stringSlice | - | Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop |
| `--from` | - | string | - | Show records at or after this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339 (alias: --since) |
| `--full-body` | - | bool | `false` | Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown |
| `--glob-db` | - | string | - | Read across a glob of result files merged into one temporary DB (e.g. --glob-db 'scans/*.sqlite'); implies -S |
| `--glob-strict` | - | bool | `false` | Fail the read on the first --glob-db source that cannot be imported, instead of skipping it with a warning |
| `--group-by` | - | string | - | Count the matched records by one field instead of listing them (host, ip, is_authenticated, method, response_content_type, scan_uuid, source, status_code). Runs the same filters as the listing |
| `--group-limit` | - | int | `20` | With --group-by: maximum groups to show, largest first (0 = every group). The tail is reported as a count, never dropped |
| `--header` | - | string | - | Search only the HTTP header block of the request/response (not bodies); use --search to span the whole exchange |
| `--host` | - | string | - | Filter by hostname pattern (wildcard supported) |
| `--in-replace` | - | bool | `false` | With --replay: overwrite each stored response with the new replay response |
| `--limit` | `-n` | int | `100` | Maximum records to display |
| `--markdown` | - | bool | `false` | Render the matched records as Markdown (request/response in fenced http blocks) to stdout; response bodies are compacted to a preview by default (use --full-body for whole bodies) |
| `--max-output-bytes` | - | int | `0` | With --json, cap the result document at N bytes by dropping whole trailing items (0 = unlimited). The document stays valid JSON and gains an output_budget object naming how many items were returned, how many were omitted, and the next --offset |
| `--method` | - | stringSlice | - | Filter by HTTP method (repeatable, e.g. --method GET --method POST) |
| `--no-header` | - | bool | `false` | With --format tsv, omit the header line |
| `--no-tui` | - | bool | `false` | Force TUI off (escape hatch if TUI ever becomes default) |
| `--offset` | - | int | `0` | Number of records to skip (for pagination) |
| `--output` | `-o` | string | - | With --json: write the result document to this file and print a receipt instead; '-' forces stdout |
| `--path` | - | string | - | Filter by URL path pattern |
| `--raw` | - | bool | `false` | Show full raw HTTP request and response |
| `--redact-auth` | - | bool | `false` | With --curl: replace Authorization/Cookie/API-key header values with <redacted> |
| `--replay` | - | bool | `false` | Re-send the matched requests and compare original vs new response (instead of listing) |
| `--save-to-burp` | - | bool | `false` | Copy the database records selected by the active filters into Burp's Target Site map |
| `--save-to-vigolium-db` | - | bool | `false` | Persist the live Burp records selected by the active filters into the database |
| `--scan-uuid` | - | string | - | **(overrides the global `--scan-uuid`)** Only records first stored by this scan (http_records.scan_uuid; a record deduplicated against an earlier scan keeps that scan's uuid) |
| `--search` | - | stringArray | - | Search across URL, path, and the raw request/response (headers + body); repeatable, AND-combined (each term further narrows) |
| `--sort` | - | string | `created_at` | Sort by: uuid, created_at, sent_at, method, status, time |
| `--source` | - | string | - | Filter by record source (e.g. burp, caido, scanner, probe, ingest-cli, ingest-server, ingest-proxy, seed) |
| `--stateless` | `-S` | bool | `false` | Read from --db (a .jsonl export or standalone .sqlite) with project scoping off; never writes to your project DB |
| `--status` | - | intSlice | - | Filter by HTTP status code (repeatable, e.g. --status 200 --status 404) |
| `--timeout` | - | duration | `15s` | Per-request timeout for --replay (e.g. 30s, 1m) |
| `--to` | - | string | - | Show records at or before this time — 2d, 12h, 30m, today, yesterday, 2026-08-05, "2026-08-05 14:30", or RFC3339; a bare date covers the whole day (alias: --until) |
| `--tree` | - | bool | `false` | Display as host/path hierarchy tree |
| `--tui` | - | bool | `false` | Open interactive TUI (arrow keys to navigate, enter to view details, c to copy id) |
| `--url` | - | stringArray | - | Select records whose URL matches EXACTLY (repeatable; OR-ed). Compared against the stored URL with no normalization — use --path or --search for substring matching |
| `--uuid` | - | stringSlice | - | Select exact stored record(s) by UUID or unique 8+ char prefix (repeatable/comma-separated). Applied before pagination, so a match is never missed because it fell outside -n |
| `--with-browser` | - | bool | `false` | Replay each URL through a real browser routed via --proxy (--replay), so Burp captures browser-driven traffic |

## vigolium traffic body

Usage: `vigolium traffic body [uuid]`

Extract one stored request or response body

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--allow-incomplete` | - | bool | `false` | Write the body even when the capture is known to be incomplete (the receipt still reports complete: false) |
| `--output` | `-o` | string | - | Write to this file instead of stdout; '-' forces stdout |
| `--representation` | - | string | `decoded` | Body representation: 'decoded' removes supported content encodings (gzip); 'stored' returns the bytes exactly as captured |
| `--request` | - | bool | `false` | Read the request side |
| `--response` | - | bool | `false` | Read the response side (default) |
| `--stateless` | `-S` | bool | `false` | Read from --db (a standalone .sqlite) with project scoping off; never writes to your project DB |
| `--uuid` | - | string | - | UUID (or unique prefix, 8+ chars) of the stored record to read; the positional argument is the same |

## vigolium traffic headers

Usage: `vigolium traffic headers [uuid]`

Read one stored message's headers without its body

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--name` | - | string | - | Return only entries with this header name (case-insensitive); every matching entry is returned, not just the first |
| `--output` | `-o` | string | - | Write to this file instead of stdout; '-' forces stdout |
| `--request` | - | bool | `false` | Read the request side |
| `--response` | - | bool | `false` | Read the response side (default) |
| `--stateless` | `-S` | bool | `false` | Read from --db (a standalone .sqlite) with project scoping off; never writes to your project DB |
| `--uuid` | - | string | - | UUID (or unique prefix, 8+ chars) of the stored record to read; the positional argument is the same |

## vigolium update

Update Vigolium and its nuclei templates to the latest version

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--check` | - | bool | `false` | Only report whether a newer release is available; download and change nothing |
| `--dry-run` | - | bool | `false` | Resolve and verify the signed release and check the binary is writable, but download and replace nothing |
| `--install-dir` | - | string | - | Install the binary into this directory instead of replacing the running one (e.g. ~/.local/bin) |
| `--skip-binary` | - | bool | `false` | Only update nuclei templates; do not update the binary |
| `--skip-templates` | - | bool | `false` | Only update the binary; do not refresh nuclei templates |

## vigolium version

Show version information

_No command-specific flags._
