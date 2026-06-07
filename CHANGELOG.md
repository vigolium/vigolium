# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.24-beta] - 2026-06-07

A false-positive-reduction and severity-recalibration release: per-template severity overrides for known-issue scan, decode-confirmed LFI and marker-confirmed WordPress detection, right-sized passive DOM-XSS severities, and a fix for response bodies being dropped from stored known-issue findings.

### Added

- **Known-issue-scan severity overrides** — a new `known_issue_scan.severity_overrides` map remaps a finding's recorded severity by nuclei template ID (case-insensitive), applied after a match but before output/persistence so the stored finding, console output, and severity counts all agree. Lets you right-size noisy or context-dependent templates without forking the upstream template (which reverts on `nuclei -update-templates`). Ships a default `config-json-exposure-fuzz: medium` — an exposed `config.json` often carries only public base URLs / feature flags rather than always-critical secrets; set an entry back to the template's own severity to undo a remap.

### Changed

- **WordPress module false-positive hardening** — `wp-ajax-exposure` now requires plugin/action-specific markers (AND-of-OR groups via `modkit.MatchAllGroups`) in the response body and rejects generic CDN/WAF/SPA error pages, so an unrelated "load-failed … Refresh" page is no longer mislabelled as a critical export vulnerability. `cms-installer-exposure` now requires the CMS-name anchor and installer-specific context to co-occur (instead of any single generic word like "language" or "database") and adds a soft-404 / SPA-shell gate (`ConfirmNotSoft404`) to reject wildcard catch-all hosts.
- **LFI base64-read confirmation** — the `php://filter/convert.base64-encode` read is now confirmed by actually decoding the returned base64 and requiring real PHP source (a PHP open tag, not already present in the baseline), replacing a bare `^[A-Za-z0-9+/=]{50,}` charset regex that fired on incidental base64 (data-URI images/fonts) embedded in ordinary CDN/static 404 pages. LFI matches are additionally gated to 2xx/3xx responses, so a 4xx/5xx error/404 body is never mistaken for leaked file content.
- **Passive DOM-XSS severity recalibration** — `dom-xss-detect`, `dom-xss-taint`, and `unsafe-html-sink` (and each of its per-sink patterns) are lowered from Medium to Low, reflecting that these are static source/sink indicators without runtime confirmation.

### Fixed

- **Known-issue-scan findings lost their response body** — `formatJSON` zeroed `Response` in place on the shared `*ResultEvent` before `SaveFinding`/`SaveRecord` ran, wiping the response body from the stored finding and its HTTP record. It now serializes a shallow copy with `Response` cleared, leaving the persisted finding and record intact.

## [v0.1.23-beta] - 2026-06-06

A combined detection and agentic-scan reliability release: routing-based SSRF detection from PortSwigger's "Cracking the lens" research, OpenRouter provider routing for the olium agent, resilient agent streaming with run cancellation and graceful shutdown, plus continued Spring/false-positive hardening.

### Added

- **Routing-based SSRF detection ("Cracking the lens")** — two new active modules. `routing-ssrf` writes an attacker-chosen host on the request line (absolute-URI `http://internal/`, `@`-userinfo, protocol-relative `//host/`) while still connecting to the victim host, confirming via an out-of-band OAST callback or a self-evidencing internal/metadata marker that reproduces, is absent from a baseline, and is absent for a benign decoy. `upgrade-routing-ssrf` detects internal/metadata endpoints reachable only when a WebSocket-upgrade handshake bypasses a proxy URL filter, confirmed by a with-vs-without differential. Backed by a new `http.Options.RawRequestTarget` request-line primitive (rawhttp, Host/target mismatch preserved) and shared `infra` payload ladders.
- **"Collaborator Everywhere" OAST headers** — `oast-probe` expands its blind-callback header fan-out (`True-Client-IP`, `CF-Connecting-IP`, `Forwarded`, `X-WAP-Profile`, …) with per-header value shaping and a `Cache-Control: no-transform` hint, surfacing SSRF in routing/analytics headers that backends behind a reverse proxy commonly fetch.
- **OpenRouter provider routing** — a typed `agent.olium.custom_provider.provider_routing` knob (provider order, fallbacks, data-collection, quantization, …) plus a generic `extra_body` JSON passthrough merged into every openai-compatible request, for steering OpenRouter and other OpenAI-compatible backends.
- **Agent run cancellation** — `POST /api/agent/scans/:uuid/cancel` aborts an in-flight autopilot/swarm/query/audit run (recorded as `cancelled`), wired to a Stop control in the workbench UI.
- **Agent config hot-reload** — the `agent` config section now reloads at runtime, so `vigolium config set agent.olium.*` (provider/model/credentials) takes effect on the next run without a server restart; the CLI echoes a reload line.
- **Invalid-date mutation payloads** — the mutation engine now emits explicit, labeled invalid-date boundary values (impossible day-of-month, out-of-range month 13) for date parameters to probe lenient date parsers/validators, deterministically and reproducibly.

### Changed

- **Spring module false-positive hardening** — `spring-actuator-misconfig` now confirms each endpoint by its actuator-specific JSON structure (`"status":"UP"` for `/health`, the `propertySources` envelope for `/env`, dotted Micrometer metric ids for `/metrics`, …) instead of a generic word match, and the seven sibling exposure modules (boot-admin, cloud-config, data-rest, debug, gateway, h2-console, jolokia) now require co-occurring marker groups rather than any single weak token. All eight probe a guaranteed-nonexistent sibling under the same directory to reject catch-all handlers (e.g. Keycloak i18n message bundles, SPA fallbacks) that 200 every child path. New shared `modkit` primitives back this: `MatchAllGroups` (AND-of-OR groups) and `SiblingPathCatchAll`, folded into a single `MatchAndConfirmSibling` helper.
- **Parallel-scan interrupts** — Ctrl-C during a `-P`/`--parallel` batch now treats un-started and cut-short targets as "not scanned" rather than failures: a muted per-target line, no `ERROR` log spam, a `Parallel scan interrupted · N not scanned` roll-up, and an exit status that distinguishes an operator stop from a genuine all-failed batch.

### Fixed

- **Streaming agent disconnects** — a streaming (`stream: true`) agent run no longer freezes `runtime.log` or hangs in `running` when the SSE client disconnects (e.g. a connection dropped during a long model "thinking" pause). Writes now drain the agent pipe to EOF so logging and DB finalization always complete, a vanished client cancels the run instead of burning its full budget, and a client disconnect or server shutdown is recorded as `cancelled` rather than `failed`. Concurrent SSE producers (swarm phase callbacks) are serialized through a single sink to stop interleaved/half-written events.
- **Graceful server shutdown** — shutdown now cancels in-flight agent runs first so live SSE streams release their connections, honors the caller's deadline (`ShutdownWithContext`) instead of waiting indefinitely for connections to go idle, and a second Ctrl+C (or a hard deadline) force-quits a hung shutdown. The config watcher also watches the actual `--config` file rather than only the default path.

## [v0.1.22-beta] - 2026-06-06

An agentic-scan and traffic-capture release: attack-vector skills wired into autopilot and swarm with planner-driven selection, an HTTPS-intercepting ingest proxy, sturdier olium stream recovery, a static-root traversal file-read oracle, and cleaner parallel-scan output.

### Added

- **Attack-vector skills for agentic scan** — confirmation/escalation playbooks the agent loads to confirm and escalate findings (new `xss-browser-confirm`, upgraded `idor-blast-radius`). Built-in skills are materialized to `~/.vigolium/skills` (override `VIGOLIUM_SKILLS_DIR`) on `vigolium init` as editable copies, which the loader prefers over the embedded fallback.
- **Planner-driven skill selection** — the swarm planner picks skills matching the target's attack surface (`RECOMMENDED_SKILLS`) and the triage phase loads just that subset; autopilot runs an equivalent best-effort pre-flight pick before its run. `--skill`, `--skill-tag`, and `--no-skill-filter` (on `agent autopilot` / `agent swarm`) override the selection per run, and `agent.olium.always_on_skills` (default `triage-finding`, `write-jsext`) pins general-purpose playbooks that stay available regardless of filtering.
- **HTTPS-intercepting ingest proxy** — `vigolium server --ingest-proxy-port N --proxy-mitm` terminates TLS with a generated CA so HTTPS traffic is recorded (and scanned with `-S`); trust the CA printed at startup or write it out with `--export-ca <path>`, and use `--proxy-insecure` to skip upstream TLS verification. Plain HTTP and un-intercepted CONNECT tunnels still pass through untouched.

### Changed

- **Active module improvements** — additional detection coverage and false-positive hardening across the active modules (including a new static-root file-read oracle in `path-normalization`).
- **Sturdier olium stream recovery** — transient upstream stream failures (HTTP/2 `INTERNAL_ERROR`/`GOAWAY`/idle reset and content-less codex `error` frames) now retry even mid-tool-call instead of tearing down the run, recovering exactly the in-flight-tool-call blips that previously killed autopilot/swarm runs.
- **Parallel scan output** — each `-P`/`--parallel` child now writes a self-contained `<output>.console.log` that captures the live finding stream (even with deferred JSONL and no `console` format) and drops the repetitive `[status]` progress ticker, so per-target logs read like a normal console scan.

## [v0.1.21-beta] - 2026-06-05

A false-positive-reduction and observability release: broad confirmation-hardening across the active and passive modules, full secret disclosure in findings, and Pi-compatible JSONL transcripts for every olium agent mode.

### Added

- **Olium session transcripts** — every olium run (`olium`/`ol` TUI, `-p` headless, `agent autopilot`, and `agent swarm`/`query` per phase) writes a Pi-compatible JSONL conversation transcript to its session dir for debugging.
- **Shared confirmation primitives** — static-asset Content-Type gate, WAF/CDN challenge-page detection (catching 200/202 Cloudflare/Incapsula interstitials), a genuine WebSocket-handshake check, and body-similarity / raw-replay helpers, reused across the hardening below.

### Changed

- **Active false-positive hardening** — ~20 High/Critical modules now drop findings that fail strict confirmation (soft-404 / wildcard / reflection / content-shape gates), and ones that confirmed on HTTP status alone now require a content/body gate, so catch-all and SPA 200s no longer trip findings.
- **Error/marker matching** (`sqli-error-based`, `graphql-scan`, `ssrf-detection`, `ldap-injection`, `xxe-generic`, `nosqli-*`, …) skips WAF/CDN challenge, auth-gate, and rate-limit pages before matching, closing the SSO/Cloudflare-challenge false-positive class.
- **Passive false-positive hardening** — ~12 detectors (env-secret, info-disclosure, error-message, MCP-endpoint, jackson/joomla, …) skip static-asset and binary bodies, so a token baked into a minified bundle is no longer flagged.
- **Secrets shown in full** — target-discovered secrets are now reported unredacted (`secret-detect`, `env-secret-exposure`, `jwt-weak-secret`, `jwt-claims-detect`); only operator BYOK credentials in logs/config stay masked.
- **vigolium-audit harness** — restructured output layout with pre-merge and artifact-redaction passes, so `agent audit` runs land cleaner, deduplicated, secret-safe output.

## [v0.1.20-beta] - 2026-06-02

A detection-expansion and false-positive-reduction release: OS command-injection detection, a `-P/--parallel` multi-target fan-out, finding evidence in output, and a broad hardening pass across the active modules and shared diffscan engine.

### Added

- **OS command-injection detection** — three new active modules covering results-based (in-band), out-of-band (OAST callback), and time-based blind techniques, each confirming execution across multiple rounds against a baseline to avoid false positives.
- **`-P`/`--parallel` flag** (`scan`, default `1`): scan up to N targets concurrently via isolated child processes. Pair with `-S -T --split-by-host` for per-host output files, or `--db-isolate -T` to merge every target into one shared `--db` and export a single unified result. Single target / `-P 1` is unchanged.
- **Finding evidence** — findings now carry the supporting request/response pairs (baselines, confirmation rounds, control fetches) behind each decision, surfaced in console output and stored in the database.

### Changed

- **Broad false-positive hardening** across the active modules: findings now have to reproduce and show real content-level changes, so they survive WAF/rate-limit pages, dynamic-content jitter, transient flaps, and reflection artifacts instead of misreading them as vulnerabilities. Confirmation replays also bypass the response cache so each sample is genuinely fresh.
- **diffscan engine** — excludes reflection-prone and volatile attributes from comparisons, gates out responses where the payload couldn't have been evaluated (redirects, empty bodies, 404s), and surfaces which attributes actually differed across confirmation rounds.
- **Severity recalibration** — server-side template injection lowered to Info (a human-confirmation lead) and HTTP method tampering to Suspect (frequently non-exploitable alone).
- **Passive checks** — missing-security-header detection now also flags weak `Referrer-Policy` values and cacheable sensitive HTTPS responses; CSRF detection filters out requests that aren't actually CSRF-reachable (JSON bodies, header-based auth, no session cookie).
- **OAST service** — command-injection callbacks are now classified as confirmed OS command injection rather than generic SSRF/XXE.
- **Olium autopilot** — project custom skills now load from `.agents/skills/`, with a startup summary of available skills by source.

### Removed

- Folded the standalone cacheable-HTTPS and Referrer-Policy passive checks into the missing-security-header module.

## [v0.1.19-beta] - 2026-06-01

### Added

- Five new active modules: `ssrf-filter-bypass`, `ssrf-protocol-smuggling`, `open-redirect-confusion`, `reverse-proxy-path-confusion` (High), and `cache-poisoned-dos` / CPDoS (Medium).
- `--db-isolate` flag (`scan`, `agent autopilot`, `agent swarm`): scan into a private temp SQLite DB and merge into `--db` at the end, so parallel scans can share one `--db` without write contention.
- `--soft-fail` global flag: always exit 0 even on error (error still printed to stderr) for CI/scripts.

### Changed

- `response-header-injection`: confirmed injections served over a keep-alive connection are now flagged as likely to let an attacker poison the shared connection's response queue and deliver their responses to other users, and are raised to High.

## [v0.1.18-beta] - 2026-05-30

A false-positive reduction release: high/critical active modules now re-confirm findings (replay payload vs. clean baseline) before reporting, plus discovery and crawler robustness fixes.

### Re-confirmation safety net

- Executor-level net (`modkit.ConfirmBodyDifferential` + opt-in `BodyDifferentialConfirmable`) replays a finding's payload vs. a clean baseline and drops it without a reproducible difference, fails *open* on anything inconclusive. Opted in by `host-header-injection`, `reflected-ssti`, `struts-ognl-injection`, `web-cache-poisoning`.
- Dropped findings counted and surfaced via `SuppressedFindings()`.

### SQL & NoSQL injection

- **`sqli-boolean-blind`** — single-shot comparison replaced by a multi-round, multi-factor logic battery (operator probing, alternating comparisons, per-branch stability, invalid-syntax probe) + WAF payload mutation.
- **`sqli-time-blind`** — multi-round, delay-scaling confirmation to separate injection from network jitter.
- **`nosqli-operator-injection`, `nosqli-error-based`** — size-change hits re-confirmed against per-request variance; now require a captured baseline.
- New `pkg/modules/infra` SQLi helpers: `sqldbms.go`, `sqlvalue.go`, `sqlwaf.go`.

### Active module confirmation

- **`crlf-injection`, `response-header-injection`** — replay with fresh canaries across rounds.
- **`open-redirect`** — require the redirect to track a fresh injected domain across rounds.
- **`ssrf-detection`** — verify matched markers are payload-introduced, not ambient.
- **`idor-detection`, `idor-guid`** — determinism gate vs. per-request variance (skips analytics/beacon endpoints).
- **`mass-assignment`** — canary field detects endpoints that echo arbitrary keys.
- **`http-method-tampering`** — catch-all guard drops endpoints that accept *any* method.

### Discovery & spidering

- Built-in wordlists materialized to disk and used as defaults (`internal/resources/wordlists`).
- `dedup_cluster_cap` (default 10) collapses near-identical responses so catch-all/SPA targets don't flood the scan; `auto_fuzz_low_yield` (default on) enables `FUZZ` brute-forcing on low-yield/SSO-walled spidering.
- Initial navigation retries on transient transport errors; proxied scans force Chrome to HTTP/1.1 (fixes `net::ERR_HTTP2_PROTOCOL_ERROR` through Burp/ZAP); off-host start redirects classified as SSO wall vs. relocated app (host adopted into scope).

## [v0.1.17-beta] - 2026-05-29

Expand XSS detection with additive modules that sit alongside the existing scanners rather than changing them. The WAF-aware evasion and encoding-payload work takes inspiration from [dalfox](https://github.com/hahwul/dalfox).

### XSS

- **Stored XSS (`xss-stored`)** — browser-confirmed persistent XSS: writes a unique canary, re-fetches the page with a clean request, and only reports when the canary both persists and executes, distinguishing stored from reflected.
- **DOM-XSS taint (`dom-xss-taint`)** — passive AST taint analysis that raises a finding only when a DOM-controlled source (`location.hash`, `document.cookie`, …) provably flows into a dangerous sink (`innerHTML`, `eval`, …), complementing the pattern-based `dom-xss-detect`.
- **Pre-encoded injection (`xss-light-encoded`)** — targets filters that decode a parameter (base64 / double-URL) before reflecting it.
- **WAF-aware evasion** — a per-host `WAFRegistry` lets modules publish the detected WAF/CDN so later insertion points reuse it, and a package-level `waf.ClassifyParts` helper classifies blocks from raw response primitives. Inspired by dalfox's WAF handling.
- **Encoding payloads** — `pkg/modules/infra/xssencode` supplies execution-preserving payload mutators and an encoding ladder for bypassing filters. Inspired by dalfox's evasion payloads.

### jsscan

- Add axios and custom-protocol request-pattern extraction.
- Surface DOM-XSS source→sink taint flows (`dom_flows`) in scanner output.
- Add `linux/arm64` / `darwin/amd64` correlation testdata.

### Audit

- vigolium-audit no longer forces a hardcoded per-platform model and reasoning effort; it now inherits the agent runtime's own configured default unless `--model` or `VIGOLIUM_AUDIT_MODEL` is set explicitly.

## [v0.1.16-beta] - 2026-05-28

Fix cross-platform release packaging for embedded helper binaries: GoReleaser, snapshot, release, public-release, and Docker builds now stage the matching `vigolium-audit` blob per target, run cross-builds sequentially where the shared go:embed path would otherwise race, and restore the host blob afterward so local builds do not inherit the last release target. Add runtime and npm packaging guards that detect wrong-platform embedded audit blobs before users hit opaque exec-format failures. Also add missing `jsscan` embeds for `linux/arm64` and `darwin/amd64`, with coverage tests to ensure every shipped release target has a real scanner binary instead of the unsupported stub.

## [v0.1.15-beta] - 2026-05-28

Make `--format jsonl` emit the same post-scan, project-scoped `{"type":...,"data":...}` envelope as `vigolium export` (instead of the live nuclei-style stream) across scan, scan-url phase mode, and stateless runs; default stateless multi-target scans (`-S -T file`) to a single unified output file with new `--split-by-host` to opt into per-host files; surface timed-out modules in the scan status line (`X/Y (A active, P passive, T timed out)`); make failed scans exit non-zero and skip the "completed" banner instead of logging at INFO; accept `--session`/`--session-file` as aliases for `--auth`/`--auth-file`; and fold phases, intensities, and agent modes into `vigolium strategy` (dropping the `ls` subcommand).

## [v0.1.14-beta] - 2026-05-25

Publish multi-arch Docker images: `make docker-publish` now builds and pushes both `linux/amd64` and `linux/arm64` (override via `DOCKER_PLATFORMS`) as a single manifest using `docker buildx`.

## [v0.1.13-beta] - 2026-05-24

Make `--scanning-max-duration` cap total scan wall-clock time (all phases combined), widen severities to all levels for single-phase known-issue-scan runs, and add `cve`/`kis`/`known-issues` phase aliases.

## [v0.1.12-beta] - 2026-05-24

Bound the known-issue-scan phase to its `max_duration` and default it to critical+high severities.

## [v0.1.11-beta] - 2026-05-24

Initial release of Vigolium open source.
