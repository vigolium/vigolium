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
type versionFeature struct {
	Name      string
	Command   string
	Flag      string
	FlagValue string
	Env       string
	ConfigKey string
	Event     string
	Field     string
}

// versionFeatureNames is the published list, in table order.
func versionFeatureNames() []string {
	out := make([]string, len(versionFeatures))
	for i, f := range versionFeatures {
		out[i] = f.Name
	}
	return out
}
