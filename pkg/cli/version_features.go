package cli

// versionFeatures are the capabilities `version -j` lists as items[0].features,
// so a caller gates on what this binary can do rather than on its version
// number or on scraping --help. A driver that pins an older release can still
// use a newer host's safety surface (`--no-redact`, `--require-scope`) when the
// name is present, and fall back when it is not.
//
// A name is stable once published: it is never renamed or reused for a
// different behaviour, and it is removed only with the capability. Each entry
// names the flag, variable, settings key, document field or command that
// embodies it, and TestVersionFeaturesExist checks that every one still exists,
// so the list cannot advertise something the binary no longer has.
var versionFeatures = []versionFeature{
	{Name: "no-redact", Flag: "no-redact"},
	{Name: "redact-env", Env: "VIGOLIUM_REDACT"},
	{Name: "offline", Flag: "offline", ConfigKey: "offline"},
	{Name: "resume-scan", Command: "scan", Flag: "resume-scan"},
	{Name: "redirect-in-scope", Command: "scan", Flag: "redirect-mode", FlagValue: "in-scope"},
	{Name: "replay-no-save", Command: "replay", Flag: "no-save"},
	{Name: "no-auth", Command: "scan", Flag: "no-auth"},
	{Name: "external-lookups-config", ConfigKey: "dynamic-assessment.external_lookups"},
	{Name: "oast-keep-session", ConfigKey: "oast.keep_session"},
	{Name: "require-scope", Command: "replay", Flag: "require-scope", Env: "VIGOLIUM_REQUIRE_SCOPE"},
	{Name: "claimed-severity", Command: "finding", Field: "claimed_severity"},
	{Name: "vuln-class", Command: "module ls", Field: "vuln_class"},
	{Name: "schema-traits", Command: "schema commands", Field: "writes_global"},
	{Name: "scan-finished-caveats", Event: "scan.finished", Field: "caveats"},
	{Name: "scan-finished-exit", Event: "scan.finished", Field: "exit_code"},
	{Name: "scan-finished-scope-dropped", Event: "scan.finished", Field: "scope_dropped"},
	{Name: "oast-sessions-kept", Event: "scan.finished", Field: "oast_sessions_kept"},
	{Name: "skipped-controls", Event: "scan.finished", Field: "skipped_controls"},
	{Name: "deny-click-extra", ConfigKey: "spidering.deny_click_extra"},
	{Name: "kit-cookies", Command: "kit cookies", Flag: "no-prompt"},
	{Name: "scan-stop", Command: "scan stop", Flag: "wait"},
	{Name: "safe", Command: "scan", Flag: "safe"},
	{Name: "max-module-tier", Command: "scan", Flag: "max-module-tier", ConfigKey: "dynamic-assessment.max_module_tier"},
	{Name: "finding-principals", Command: "finding", Field: "principals"},
	{Name: "browser-session-clearance-only", Command: "scan", Flag: "browser-session-file"},
	{Name: "include-stored", Command: "scan-url", Flag: "include-stored"},
	{Name: "init-with-deps", Command: "init", Flag: "with-deps"},
	{Name: "doctor-for", Command: "doctor", Flag: "for"},
	// --only narrows --for's report and verdict, and runs no OAST network probe
	// or database open the named checks do not need.
	{Name: "doctor-only-scoped", Command: "doctor", Flag: "only"},
	// VIGOLIUM_RATE_CEILING caps every rate and count dial (rate_ceiling.go).
	{Name: "rate-ceiling", Env: "VIGOLIUM_RATE_CEILING"},
	// Ingested and bridged bodies are stored decoded; a decoded record says
	// which content-coding the wire carried.
	{Name: "ingest-decoded-bodies", Command: "traffic", Field: "response_decoded_from"},
	// JSON request-body key paths per operation, types and counts only.
	{Name: "body-shapes", Command: "params", Flag: "paths"},
	// An SPA walk on forged client state: storage seeds, same-origin response
	// stubs, writes failed and reported by shape, real exchanges stored.
	{Name: "unlock-walk", Command: "kit unlock-walk", Flag: "profile"},
	// An unlock profile's rewrites change a real same-origin answer (status,
	// JSON members) in the browser; a rewritten exchange is never stored and
	// is reported per route as rewrites_hit.
	{Name: "unlock-rewrite", Command: "kit unlock-walk", Field: "rewrites_hit"},
	// The unlock walk clicks up to maxClicksPerRoute controls per rendered
	// route behind the destructive-label guard, one per trigger kind first,
	// and refuses to click under --allow-writes (clicks_refused).
	{Name: "unlock-click", Command: "kit unlock-walk", Field: "clicks_refused"},
	// Client routes carry the route record's literal meta (Vue `meta`,
	// Angular `data`), guards from every gating key, and data-route loaders.
	{Name: "route-meta", Command: "kit js-beautify", Field: "meta"},
	// A ViewState's legacy MAC is checked against published machineKeys,
	// passively (aspnet-viewstate-detect) and on demand.
	{Name: "viewstate-known-keys", Command: "kit viewstate-crack", Flag: "generator"},
	// `import <vigolium.sqlite> --host <pattern>` merges only that host's
	// records, findings and the rows that follow them; a non-SQLite path
	// source with --host is refused rather than imported whole.
	{Name: "import-sqlite-host", Command: "import", Flag: "host"},
	// `import <vigolium.sqlite> --skip-findings` merges the source without its
	// findings, their history and their OAST interactions.
	{Name: "import-skip-findings", Command: "import", Flag: "skip-findings"},
	// waf.block carries block_kind; a block the generic phrase rule alone
	// matched is block_kind "refused" with no vendor, never vendor "unknown".
	{Name: "waf-block-generic-unnamed", Event: "waf.block", Field: "block_kind"},
	// `--only discovery,spidering,targeted-respider` re-crawls the declared and
	// discovered client routes with no assessment.
	{Name: "respider-without-assessment", Command: "scan", Flag: "only", FlagValue: "targeted-respider"},
	// The discovery transport and the browser crawl classify blocks and report
	// them on the one notifier: waf.block carries transport
	// requester|discovery|spider, and their blocks count toward edge_blocked.
	{Name: "waf-block-transports", Event: "waf.block", Field: "transport"},
	// A vendor challenge page served on 200 or 202 (Cloudflare, AWS WAF,
	// Akamai, Imperva, Sucuri, DataDome, PerimeterX, Vercel) is a waf.block
	// with block_kind "challenge" and the vendor named.
	{Name: "waf-challenge-2xx", Event: "waf.block", Field: "block_kind"},
	// `kit param-mine --location header` mines request header names with the
	// same baselines, chunking, bisection and confirmation as parameters.
	{Name: "param-mine-header", Command: "kit param-mine", Flag: "location", FlagValue: "header"},
	// `kit param-mine --location cookie` mines cookie names, each merged into
	// the request's Cookie header beside the cookies it already sends.
	{Name: "param-mine-cookie", Command: "kit param-mine", Flag: "location", FlagValue: "cookie"},
	// --browser-session-file writes the spider's harvested cookies, the
	// browser's User-Agent and a harvested token after spidering (0600) and
	// carries them into every phase of the next invocation.
	{Name: "browser-session-file", Command: "scan", Flag: "browser-session-file"},
	// grpc-surface-audit asks a present server-reflection service (v1, then
	// v1alpha) for ListServices and each service's file descriptor, and puts
	// the decoded services and methods on its finding as metadata.services.
	{Name: "grpc-reflection-catalog", Module: "grpc-surface-audit"},
	// The browser crawl records each in-scope WebSocket frame (url, direction,
	// opcode, payload length and a 4 KiB head) in the websocket_frames table.
	{Name: "websocket-frames", Table: "websocket_frames"},
	// `kit h2-probe` writes one HTTP/2 request's frames by hand (a declared
	// content-length the DATA disagrees with, a stream left open) and times
	// the answer or the timeout: the oracle of an HTTP/2 desync probe.
	{Name: "h2-raw-probe", Command: "kit h2-probe", Flag: "open-stream"},
	// `--set <dotted.key>=<value>` (repeatable) overlays one config key for
	// the invocation; an unknown key is exit 2 naming it.
	{Name: "config-overlay", Flag: "set"},
	// VIGOLIUM_PINNED=1: a flag that widens the env pins exits 2
	// refused_by_policy with error.hint carrying the corrected command line.
	{Name: "pinned-env", Env: "VIGOLIUM_PINNED"},
	// A command-line (phase, dial) pace pair the phase does not enforce exits
	// 2 pace_unsupported; `schema pace` publishes the pairs; a config pair
	// warns and rides on scan.started as pace_ignored.
	{Name: "enforced-pace", Command: "schema pace", Event: "scan.started", Field: "pace_ignored"},
	// `schema storage --ddl` prints the SQLite DDL of the current schema.
	{Name: "schema-ddl", Command: "schema storage", Flag: "ddl"},
	// scan.finished (and `scan status -j`) carry the per-module ledger.
	{Name: "module-stats-event", Event: "scan.finished", Field: "module_stats"},
	// `scan coverage <scan> -j`: (record, module) cells of the coverage ledger.
	{Name: "scan-coverage", Command: "scan coverage", Field: "done"},
	// A scan invocation with --events that ends before its stream began (usage
	// error, unknown flag, config refusal, preflight failure) still writes
	// exactly one scan.finished: status failed, exit_code, error_code, zero
	// records_written.
	{Name: "terminal-always", Command: "scan", Flag: "events", Event: "scan.finished", Field: "error_code"},
	// A phase that did no work ends skipped (phase.finished status skipped):
	// dynamic assessment that admitted zero inputs is skipped/no_inputs, a
	// coverage gap when the phase was named with --only. scan.finished.caveats
	// name the capabilities configuration switched off: oast_disabled,
	// module_tier_capped and risky_payloads_disabled (with their modules).
	{Name: "honest-phase-state", Event: "scan.finished", Field: "caveats"},
	// `finding -j` and `traffic -j` state truncated, and a page that stops
	// short carries next_cursor, which --cursor resumes (keyset, stable while
	// a scan writes).
	{Name: "list-cursors", Command: "finding", Flag: "cursor", Field: "next_cursor"},
	// VIGOLIUM_STATE_DIR relocates every path vigolium writes (config, default
	// DB, presets, active-project, native-sessions, replay jars, caches, Chrome
	// for Testing, nuclei templates, the embedded nuclei libraries' config
	// dirs): nothing is written under HOME.
	{Name: "state-dir", Env: "VIGOLIUM_STATE_DIR"},
	// `init` exits 1 not_ready when a dependency install it ran failed, even
	// when a dependency check afterwards passes.
	{Name: "init-strict-exit", Command: "init", Flag: "with-deps"},
	// With no Chrome for Testing build (linux/arm64) the browser is the system
	// chromium, chromium-browser or google-chrome, in that order; doctor names
	// the binary it resolved.
	{Name: "arm64-system-chromium", Command: "doctor"},
	// scan, scan-url and scan-request refuse an out-of-scope target at entry
	// (exit 2 out_of_scope, VIGOLIUM_REQUIRE_SCOPE honoured) like every
	// sender, and the requester judges every request and redirect hop against
	// the scope at send time, with a private-address and instance-metadata
	// block only an explicit scope entry lifts.
	{Name: "send-scope-all", Command: "scan-url", Flag: "ignore-scope", Env: "VIGOLIUM_REQUIRE_SCOPE"},
	// scope.cidr.include/exclude (prefixes or addresses) and
	// scope.port.include/exclude (ports or ranges) apply at entry, at send
	// time, on redirect hops and to fuzz --resolve addresses.
	{Name: "scope-cidr-port", ConfigKey: "scope.cidr.include"},
	// The dynamic assessment re-sends a stored POST/PUT/PATCH/DELETE only when
	// that record was first stored with a real response; write templates
	// (first stored request-only) are skipped and counted in the
	// templates_skipped_unsafe_method caveat unless --allow-writes.
	{Name: "da-method-gate", Command: "scan", Flag: "allow-writes"},
	// `ingest` sends nothing by default: request-only inputs are stored as
	// templates; --fetch-responses sends them.
	{Name: "ingest-no-fetch-default", Command: "ingest", Flag: "fetch-responses"},
	// No open migrates a store an older vigolium wrote: it is refused with
	// schema_outdated naming `vigolium db migrate --db <path>`, unless
	// VIGOLIUM_AUTO_MIGRATE=1 (database.auto_migrate_on_read).
	{Name: "no-migrate-on-read", Env: "VIGOLIUM_AUTO_MIGRATE", ConfigKey: "database.auto_migrate_on_read"},
	// --caller-tag k=v / VIGOLIUM_CALLER_TAG land in scans.tags and on
	// scan.started as caller_tags; replay, fuzz --save, kit unlock-walk,
	// ingest and bridge imports store their records under a scans row of
	// their own that carries them.
	{Name: "caller-tag", Flag: "caller-tag", Env: "VIGOLIUM_CALLER_TAG", Event: "scan.started", Field: "caller_tags"},
	// Write-time dedup keys a body-less request on the hash of its
	// Authorization and Cookie values (http_records.request_identity_hash),
	// and replay, fuzz and param-mining records on their exact bytes, so one
	// principal's exchange never lands on another's row.
	{Name: "dedup-identity-aware", Command: "traffic"},
	// A bridge import stores the capture time the listener reported in
	// sent_at; created_at stays the insert time.
	{Name: "bridge-capture-time", Command: "import", Flag: "burp-bridge-url"},
	// `import --tag k=v` labels the records an import writes (record_tags);
	// `traffic --tag` selects them and -j rows carry them as tags.
	{Name: "import-tag", Command: "import", Flag: "tag", Table: "record_tags"},
	// `import --redact credentials` masks credential headers, cookie values and
	// sensitive query parameters in the records and findings an import writes.
	{Name: "import-redact", Command: "import", Flag: "redact", FlagValue: "credentials"},
	// Header names a caller declares as credentials, masked beside vigolium's own.
	{Name: "import-redact-header", Command: "import", Flag: "redact-header"},
	// A SQLite import skips the records the destination holds before reading
	// their bodies, and says how many (records_skipped_present).
	{Name: "import-delta", Command: "import", Field: "records_skipped_present"},
	// `db clean --tag k=v` deletes the labelled records, their labels and the
	// findings only they evidence.
	{Name: "db-clean-tag", Command: "db clean", Flag: "tag", Table: "record_tags"},
	// `scan --only-new-since <scan>` assesses only the stored records added
	// after that scan finished (the incremental cursor mode).
	{Name: "scan-incremental", Command: "scan", Flag: "only-new-since"},
	// A finding may carry proof: the attack request, a control, a closed-set
	// oracle and preconditions, {{marker}} where the caller's marker goes
	// (`schema proof`). Opted in: reflected XSS (body_contains) and time-based
	// SQLi (timing_delta).
	{Name: "proof-recipes", Command: "finding", Field: "proof"},
	// Under VIGOLIUM_PINNED=1, --help, --usage (-j) and `skills get` show only
	// the flags and commands the pin admits and end with one line naming it.
	{Name: "policy-help", Env: "VIGOLIUM_PINNED"},
	// `skills get vigolium-scanner --profile embedded`: the safe verb set,
	// generated from the command tree and stamped with version and commit.
	{Name: "skill-profile-embedded", Command: "skills get", Flag: "profile", FlagValue: "embedded"},
	// `schema block-signatures -j` publishes the one WAF/CDN signature table
	// every block classifier reads: stable ids, vendor, kind
	// (challenge|block|refused|presence), match and requires.
	{Name: "block-signatures", Command: "schema block-signatures", Field: "requires"},
	// `schema commands -j` rows carry aliases (every spelling, `run <phase>`
	// included), targets (flag or positional, and kind) and reach
	// (none|line|store|unbounded) with the reach_flags that change it.
	{Name: "schema-reach", Command: "schema commands", Field: "reach"},
	// `explain-argv -j -- <argv...>`: one line's canonical command, targets,
	// reach and the VIGOLIUM_PINNED refusals, without running it.
	{Name: "explain-argv", Command: "explain-argv", Field: "refusals"},
	// --request-transform applies a declared transform (hmac-header,
	// set-header, set-query, nonce, timestamp, hash, truncate, encrypt-body)
	// to every matching request's final bytes, never its scheme, host or port.
	{Name: "request-transform", Flag: "request-transform"},
	// `traffic request <uuid> -j`: one stored request whole - method, url,
	// target, ordered headers, body, body_encoding, complete.
	{Name: "traffic-request", Command: "traffic request"},
}

// versionFeature is one entry of versionFeatures and the evidence that it
// exists. Every set evidence field must hold:
//
//   - Command: a command path (without `vigolium`); "" with Flag means a root
//     flag.
//   - Flag: a flag of Command (local or inherited); FlagValue: a value that
//     flag's help names as accepted.
//   - Env: a registered environment variable (config.EnvRegistry).
//   - ConfigKey: a settings key `config ls` lists.
//   - Field: a key of Command's -j item vocabulary, or of Event's payload.
//   - Module: a registered module id (`module ls`) whose behaviour is the
//     capability.
//   - Table: a table the store's schema creates.
type versionFeature struct {
	Name      string
	Command   string
	Flag      string
	FlagValue string
	Env       string
	ConfigKey string
	Event     string
	Field     string
	Module    string
	Table     string
}

// versionFeatureNames is the published list, in table order.
func versionFeatureNames() []string {
	out := make([]string, len(versionFeatures))
	for i, f := range versionFeatures {
		out[i] = f.Name
	}
	return out
}
