# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.29-beta] - 2026-06-12

A coverage-expansion and finding-quality release: a targeted re-spider phase that browser-crawls the SPA routes discovery finds after spidering already ran, Next.js route-manifest harvesting (Pages Router, SSG, and App Router route recovery), a ground-up rewrite of every module's finding description plus classification tags on native findings, and a consolidated `traffic --replay` that can drive a real browser through Burp.

### Added

- **Targeted re-spider of discovery-found SPA routes** — a new `targeted-respider` native phase (after discovery dedup, before dynamic assessment) closes a structural gap in the pipeline: the one-shot browser spider runs *before* discovery, so a rich route that discovery surfaces later — `/ui/`, `/console/`, an admin panel found in a JS bundle — never got its client-rendered pages crawled, and its XHR/fetch API calls never entered the scan. The phase re-reads discovery's already-stored response bodies straight from the database (zero extra HTTP for candidate selection), keeps only pages that look client-rendered/SPA or meaningfully interactive, screens out login/SSO walls so the browser budget isn't burned on auth bounces, and dedups candidates per (host, app-shell) so one crawl covers an entire SPA router instead of re-crawling the same shell per route. Survivors get short, budgeted browser crawls whose records land in `http_records` under a distinct `targeted-respider` source tag and flow into dynamic assessment like any other traffic. Default on with deliberately tight caps, all configurable under `discovery.respider.*`: max 3 seeds per host / 10 total, 45s + 25 states + depth 3 per seed, and a 5-minute wall-clock cap on the whole step; the phase only rides along when spidering, ingestion, and an assessment phase are all enabled, so headless/stateless modes are unaffected.
- **Next.js route-manifest harvesting** — discovery now recognizes Next.js pages, derives the `buildId` (from a referenced manifest URL in the markup, falling back to the `__NEXT_DATA__` JSON blob), and fetches two manifests that enumerate the app's routes but are typically absent from the rendered HTML: `_buildManifest.js` — the full Pages Router route table, including dynamic routes like `/blog/[slug]` — and `_ssgManifest.js` — the concrete pre-rendered paths, which the client router loads at runtime and which fill in real values for those dynamic segments. Every harvested route flows through link extraction into observed paths (with trusted-source priority) and `http_records`, so dynamic assessment scans pages no link on the site points at. App Router routes, which appear in *neither* manifest, are recovered separately by decoding page/route-handler chunk paths (`app/<segments>/page-<hash>.js`) back into their addressable routes.
- **Shared login/SSO URL signatures (`pkg/spitolas/loginsig`)** — the spider's login-detection tables (auth-fronting host prefixes like `sso.`/`adfs.`, known IdP hosts like Okta/Auth0/`login.microsoftonline.com`, and OAuth/SAML path markers) moved out of the crawler internals into a reusable package, so the re-spider candidate screen and any future phase share one source of truth instead of growing divergent copies.

### Changed

- **Finding descriptions and tags overhauled across all 263 modules** — every module's description was rewritten from internal implementation notes (detection-logic walkthroughs, CLI flag requirements, reference-link lists) into a concise, operator-facing **What it means / How it's exploited / Fix** block: what the finding actually establishes, how an attacker leverages it, and the concrete remediation. Net effect on the tree: ~4,100 lines of boilerplate replaced by ~2,300 lines of substance. The executor now *composes* the stored description instead of letting one source overwrite the other — the module's per-finding context line (the specific header/param/endpoint it flagged) leads, followed by the static explanation block — so reports keep both the instance specifics and the explanation. Module classification tags (`xss`, `spring`, `injection`, `light`, …) now also propagate onto every native finding, which previously carried no tags at all (only known-issue-scan findings did); tags are copied, not aliased, so editing one finding's tags can't corrupt its siblings. This is the new convention for all future modules.
- **`traffic replay` is now `traffic --replay`** — the standalone `vigolium traffic replay` subcommand was removed and folded into the `traffic` command as a `--replay` mode, so the full filter surface (`--host`, `--method`, `--status`, fuzzy search, header/body search, …) applies identically to listing and replaying. New knobs: `-c/--concurrency` (default 10) replays the matched records concurrently — and lets you throttle down to avoid overwhelming an intercepting proxy like Burp; `--with-browser` replays each URL through a real browser routed via `--proxy`, so the proxy captures genuine browser traffic — real TLS fingerprint, JS execution, subresource and XHR loads — with the stored `Authorization`/`Cookie`/`User-Agent` headers forwarded so the navigation runs under the captured session, redirects/page titles/fired JS dialogs reported per record, and Chrome's implicit proxy bypass for loopback targets removed so even `localhost` traffic reaches the proxy (non-GET records are noted as replayed as GET navigations, since that's what a browser can do); and `-a/--all` lifts the `-n/--limit` cap (default 100) so `--replay --all` re-sends every stored record. `--in-replace` and `--timeout` carry over, and concurrent replays buffer their output so each original-vs-replay comparison block prints atomically rather than interleaved.
- **Live finding lines match the console format** — the stderr finding echo used when results are deferred to files (`--format jsonl,html`) previously had its own ad-hoc layout; it now renders the exact `[type] [module] [severity] METHOD URL [value]` shape of the console result writer (including the type/phase de-duplication and the grouped extracted-value suffix), so a finding reads identically whether it streams to the terminal via stdout or the stderr echo.

### Fixed

- **`bfla-detection` no longer flags empty-200 endpoints** — an endpoint whose "privileged" baseline is an empty (or whitespace-only) body carries no privileged content to compare, so every sub-test degenerated into matching nothing against nothing: fronting CDNs, XSRF/login bounces, and JSP `.jspa` action handlers that answer *any* request with an empty 200 were reported as unauthenticated-access or method-switch bypasses. The real-world trigger was an Atlassian `/secure/ConfigureReport.jspa` returning `Content-Length: 0` for both GET and POST — which also defeated the existing random-path method baseline, since the random path 404s while the action handler empty-200s, making the responses look "different enough" to pass the guard. The module now bails up front when the baseline body is empty and skips switched-method candidates whose bodies are empty, on the principle that an empty body is no-signal for both baseline and candidate. Covered by new regression tests alongside the existing positive cases.

## [v0.1.28-beta] - 2026-06-11

A detection-expansion and noise-reduction release: object-storage traversal and cloud-URL harvesting, value-based finding grouping that collapses one leaked secret seen on many URLs into a single finding, tech-fingerprint-gated extension fuzzing, a faster native-scan hot path, and continued module false-positive hardening.

### Added

- **Value-based finding grouping** — a secret that leaks on N different URLs now collapses to a single finding (and a single console line) keyed on the extracted value, instead of one finding per URL. Applied both live (the console `findingGrouper` suppresses repeats to file-only and prints a grouped summary with per-host rollups) and in the database dedup pass (`GroupFindingsByValue`, folded into `deduplicateFindings`, covering known-issue-scan secret templates and passive secret detection). Controlled by a new `known_issue_scan.group_by_value` config (`Enabled`/`PerHost`/`Tags`/`MaxURLs`; per-host grouping on by default), with an identical non-empty value required as the guardrail.
- **Tech-fingerprint-gated extension fuzzing** — discovery now wordlist-fuzzes server-side extensions (`.php`, `.aspx`, `.jsp`, `.action`, `.cgi`, `.jspx`, `.ashx`, `.asmx`, …) only after *confirming* the app actually serves them — via an observed URL, a technology-fingerprint match, or an active soft-404 probe — instead of always sweeping every extension. New `deparos/config` tech-signature table plus an `extension_confirm` pipeline; the previously always-on custom-list sweep is now gated behind a default-on confirmation step (with a console `ext-fuzz` notice when it engages).
- **Object-storage traversal & cloud-URL harvesting** — a new active `cdn-object-traversal-listing` module appends `..;`-family trailing payloads to object-storage fetches to turn a single-object read into a full bucket listing, and a new passive `cloud_storage_url_harvest` module collects S3/GCS/Azure Blob/OSS/TOS storage URLs from response bodies. Both are backed by a new `storagesig` package that fingerprints object-storage backends and listing responses behaviorally (storage response headers, `/obj/<bucket>/<object>` path shape, listing-XML bodies). Object-storage assets are now carved out of the static-file filter across the executor, CLI/JS/server ingest, and proxy paths and recorded metadata-only via HEAD/ranged-GET (new `WorkItem.StaticMeta`) instead of being dropped, so these modules can see them.
- **Concurrent triage batches** — `TriageLoopConfig.BatchConcurrency` runs disjoint triage batches concurrently within a round (default 3, mirroring master-agent batch concurrency), wired through `SwarmRunner.runTriageLoop`.

### Changed

- **Module false-positive hardening** — expanded FP defenses and test coverage across `nosqli-*`, `sqli-time-blind`, `path-normalization`, `xml-saml-security`, `bfla-detection`, `proxy-header-trust`, and other active/passive modules.
- **Trusted identity-header spoofing in `forbidden-bypass`** — the 403-bypass module now also replays the request with spoofed trusted identity/routing headers, catching gateways that authorize on a forwarded identity header an external client can set.
- **Faster native-scan hot path** — three independent optimizations to the deterministic pipeline: `ParameterInsertionPoint` caches the `Content-Length` byte offsets at construction so body/form/XML fuzzing patches the length in place instead of re-parsing every header per payload (~4.4× faster, 15→6 allocs/op); the per-host rate limiter's `Acquire` is now lock-free in steady state (drops the per-`Acquire` shard write-lock + `heap.Fix`), which matters most when a scan hammers a single host; and module workers enqueue findings through a new batched `FindingWriter`/`SaveFindingsBatch` instead of blocking on a synchronous per-finding save (coalesced into one transaction, retried per-finding, flushed on full/close so nothing is dropped — the linked HTTP record is still persisted synchronously first).
- **Autopilot prep overlapped with the background audit** — auth preparation and pre-flight discovery now run concurrently with the background vigolium-audit pass and are joined before the frozen context bundle is assembled, taking their latency off the critical path.
- **Richer report output & audit-platform refactor** — enriched HTML/console report output, plus an internal refactor of the embedded vigolium-audit harness (shared CLI-process adapter, retry/cost engine helpers, content loader).

### Fixed

- **`--external-harvest` now works on demand** — on `vigolium scan` the scanning-strategy baseline unconditionally overwrote the external-harvest phase toggle, so passing `--external-harvest` under the default `balanced` strategy had no effect. The flag is now a true per-phase override: when explicitly set it wins over the strategy (e.g. `--intensity balanced --external-harvest` enables harvesting while keeping balanced depth), and when unset the strategy's value still applies.

## [v0.1.27-beta] - 2026-06-10

A detection-expansion and false-positive-reduction release: two new modules (clickjacking detection and internal-header fuzzing), out-of-band findings that carry the request that triggered them, a stateless audit mode with an auto HTML report, and catch-all/reflection hardening across several modules.

### Added

- **Clickjacking (UI-redress) passive module** — a new `clickjacking-detect` module that flags a page only when it is both framable *and* worth hijacking, instead of every missing `X-Frame-Options`. It computes the framing verdict like a browser (enforced CSP `frame-ancestors` overrides `X-Frame-Options`; report-only, `ALLOW-FROM`, invalid/conflicting headers, and wildcard sources are treated as ineffective), requires sensitive/interactive content (credential form, authenticated session, or state-changing form), and downgrades when a `SameSite=Strict`/`Lax` session cookie would make the cross-site frame unauthenticated.
- **Internal header probe (active module)** — a new `internal-header-probe` module that mines a CORS preflight's `Access-Control-Allow-Headers`/`Access-Control-Expose-Headers` for gateway-injected custom headers (identity, routing, trust, feature-flag), re-sends the request with each set to a battery of probe values, and reports those whose response body reproducibly changes — reflection stripped, measured against a per-endpoint noise floor, with a per-host circuit breaker. Adds an OAST spray per header for blind SSRF. Severity Suspect/Tentative: a body change proves the backend reads the header, not that it is exploitable.
- **Out-of-band findings carry their originating request** — an OAST callback finding now embeds the request/response that planted the payload, the callback URL, the raw collaborator callback as evidence, and trace anchors, so it answers "which request caused this callback?" on its own. A new `GetRecordByRequestHash` lookup recovers the origin even for late callbacks, and the finding is saved even when the record can't be resolved.
- **Stateless audit with auto HTML report** — `-S`/`--stateless` on `vigolium agent audit` runs the whole audit into a throwaway temp DB (main DB untouched, mirroring `vigolium scan -S`) and auto-renders a self-contained HTML report via the `vigolium import --format html` generator. Defaults to `vigolium-result/vigolium-audit-report.html`; `-o`/`--output` overrides it (supports `gs://` and `{ts}`).
- **`vigolium audit` top-level alias** — a shortcut for `vigolium agent audit` with the same flags (mirroring `vigolium olium`).

### Changed

- **Audit `--keep-raw` now on by default (CLI)** — retains the `<source>/vigolium-results/` copy for review/re-import; new `--clean-raw` removes it after the run. Mutually exclusive, audit-leg only.
- **Catch-all false-positive hardening** — `bfla-detection` and `forbidden-bypass` now drop findings when a random unprivileged path returns the same response, catching empty-200 / reflected-shell edge gateways the existing wildcard guards missed.
- **ASP.NET false-positive hardening** — `crossdomain.xml` / `clientaccesspolicy.xml` are flagged only when actually wildcard-permissive (not merely present), and the OIDC discovery document (`/.well-known/openid-configuration`) is no longer double-reported; all downgraded Medium→Low (these are Flash/Silverlight/OIDC standards, not ASP.NET-specific).
- **Severity recalibration** — PDF-generation-injection's plain HTML-marker reflection drops High/Firm→Medium/Tentative (the JS/SSRF/file-read variants stay High/Firm), and `web-cache-poisoning` drops Firm→Tentative.

### Fixed

- **Console output no longer clipped to a file or pipe** — width-based truncation now applies only to an interactive TTY (new `terminal.IsTerminal()`). Redirected output — including the `-P`/`--parallel` per-target `.console.log` — previously clipped URLs and payloads mid-token; file/pipe consumers now get the full, greppable line.

## [v0.1.26-beta] - 2026-06-08

A false-positive-reduction release closing the "404 catch-all / SPA shell" and "reflected-but-not-executed" classes across the error-based injection and reflection modules: a shared error-surface status gate, structural (not bare-token) signatures, and a headless-browser confirmation tier for discovered-parameter XSS.

### Added

- **`infra.IsErrorSurfaceStatus`** — a shared status gate, companion to `IsBlockedResponse`. A genuine server-side leak (DBMS/driver error, reflected file contents, a stack trace) rides a 5xx or a 2xx/4xx that echoes the payload; a `404` means the route never resolved (no handler ran) and a `3xx` carries no handler output, so a signature substring in either body is page noise — a catch-all/SPA 404 shell or a redirect interstitial. Body-matching modules whose finding is not itself a status signal now reject a response failing *either* gate before matching.

### Changed

- **Error-based injection signatures hardened against catch-all 404 shells** — `sqli-error-based`, `nosqli-error-based`, `xxe-generic`, and `ws-injection` no longer match DBMS/driver/error tokens on a `404`/`3xx` body (via the new `IsErrorSurfaceStatus` gate), and their bare tokens are tightened to structural forms: the CockroachDB name is word-boundary-anchored (was firing on `userHasCockroachDBEnabled` in a Salesforce community 404 shell's feature-flag list), the MongoDB/`BSON` patterns now require genuine driver/error contexts instead of the bare 4–6-char token, XXE confirms `/etc/passwd` by the full `root:…:0:0:` line shape (not a `root:` substring that a `--dxp-g-root:` CSS var carries), and `ws-injection` requires a pattern to be absent from the baseline, match the body only (not headers), and — for the `{{7*7}}`/`${7*7}` template probes — proves evaluation by requiring the literal payload to be *gone* from the response.
- **`nosqli-error-based` re-confirmation** — a matched DBMS error must now reproduce when the payload is re-sent (a per-request random token that coincidentally matched won't recur) and be absent from a fresh control fetch of the original value, with `NoClustering` forcing a real origin round-trip so the request-clustering cache can't replay the captured hit. Fails open on transport errors.
- **`lfi-generic` reflection guards and file-shape confirmation** — the `php://filter/convert.base64-encode` read now discards base64 runs that are simply our own `data://` payload being reflected back (Salesforce-Aura-class echo endpoints) or that decode to carry our injection marker, the `/etc/passwd` rule requires the full `root:…:0:0:…` line shape (not the former greedy `root:.*:0:0:`), `win.ini` is confirmed by ≥2 distinct bracketed section headers (was the bare English words `fonts`/`extensions`), and `.env`/`.htaccess` are confirmed by ≥2 distinct file-shaped lines — sensitive `KEY=VALUE` assignments or recognised Apache directives — which both strengthens the evidence and broadens detection beyond the former rigid `DB_PASSWORD`+`APP_KEY`+`APP_SECRET` triple that real Laravel/Symfony files rarely carry.
- **`xss-light` discovered-parameter confirmation** — a reflected character-transform hit is now re-sent as a real, context-shaped executable payload and graded in tiers: dropped when the breakout signature never survives unescaped in the body (the reflection-only false positive this gate exists to suppress), reported Low/Tentative when it survives but no dialog fires (CSP-locked or non-executing context), and only raised to High/Certain once a headless browser actually pops `alert(marker)`. Browser probes are globally rate-limited and injectable so tests never spawn a real browser.

### Fixed

- **Spidering no longer crashes the whole scan on a cross-origin iframe** — go-rod's lazy `getJSCtxID()` dereferences a nil `ContentDocument` for cross-origin/detached frames, and the existing `frameAccessible()` pre-filter could not close the TOCTOU gap where a same-origin iframe navigates cross-origin (or detaches) between frame enumeration and the element query during extraction — common on SPAs. The nil-pointer panic propagated to the top-level `RunNativeScan` recover and aborted the entire scan (later phases skipped, zero findings). The browser wrappers that reach `getJSCtxID` (`Element`/`ElementX`/`Elements`/`ElementsX`/`EvalWithArgs`/`HTML`/`HasElement[X]`, plus the recursive frame-HTML builders) now convert such panics into ordinary errors so the bad frame is skipped, with a per-frame `recover()` backstop in the candidate-element extractor as a second line of defense.

## [v0.1.25-beta] - 2026-06-07

A false-positive-reduction release hardening the endpoint- and file-exposure modules against generic markers and reflected error pages.

### Changed

- **Rails Active Storage / Action Mailbox probe** — confirms OPTIONS endpoints only on a 2xx `Allow: POST` header (no longer body-matching `"Allow"`/`"POST"`, which forged findings from nginx `405 Not Allowed` pages), and rejects blanket-OPTIONS hosts, CORS preflights, and WAF/rate-limit pages.
- **Marker hardening** — `.env` files now require a real `KEY=VALUE` line (was bare `"="`), Magento `deployed_version.txt` a valid version token (was `"."`), and ASP.NET health checks an actual health-state word (was generic JSON keys).

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
