package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func init() {
	cobra.AddTemplateFunc("styleHeading", terminal.BoldYellow)
	cobra.AddTemplateFunc("styleCyan", terminal.Cyan)
	cobra.AddTemplateFunc("styleMagenta", terminal.Magenta)
	cobra.AddTemplateFunc("styleGray", terminal.Gray)
	cobra.AddTemplateFunc("groupedFlagUsages", groupedFlagUsages)
	cobra.AddTemplateFunc("localFlagUsages", localFlagUsages)

	rootCmd.SetUsageTemplate(coloredUsageTemplate)
	rootCmd.SetHelpTemplate(coloredHelpTemplate)

	// Set examples on all commands
	rootCmd.Example = rootExamples
	scanCmd.Example = scanExamples
	serverCmd.Example = serverExamples
	ingestCmd.Example = ingestExamples
	moduleCmd.Example = moduleExamples
	moduleLsCmd.Example = moduleLsExamples
	moduleEnableCmd.Example = moduleEnableExamples
	moduleDisableCmd.Example = moduleDisableExamples
	// config command group examples are injected via configcmd.NewCommand in wire.go
	dbCmd.Example = dbExamples
	dbListCmd.Example = dbListExamples
	dbStatsCmd.Example = dbStatsExamples
	dbExportCmd.Example = dbExportExamples
	dbCleanCmd.Example = dbCleanExamples
	dbSeedCmd.Example = dbSeedExamples
	trafficCmd.Example = trafficExamples
	scopeCmd.Example = scopeExamples
	scopeViewCmd.Example = scopeViewExamples
	scopeSetCmd.Example = scopeSetExamples
	runCmd.Example = runExamples
	agentCmd.Example = agentExamples
	agentQueryCmd.Example = agenticScanExamples
	agentSessionCmd.Example = agentSessionExamples
	agentAuditCmd.Example = agentAuditExamples
	auditCmd.Example = agentAuditExamples
	agentAutopilotCmd.Example = agentAutopilotExamples
	agentSwarmCmd.Example = agentSwarmExamples
	agentTriageCmd.Example = agentTriageExamples
	agentOliumCmd.Example = oliumExamples
	oliumCmd.Example = oliumExamples
	scanURLCmd.Example = scanURLExamples
	scanRequestCmd.Example = scanRequestExamples
	replayCmd.Example = replayExamples
	fuzzCmd.Example = fuzzExamples
	updateCmd.Example = updateExamples
	jsCmd.Example = jsExamples
	importCmd.Example = importExamples
	initCmd.Example = initExamples
	extensionsEvalCmd.Example = extensionsEvalExamples
	extensionsLintCmd.Example = extensionsLintExamples
	sessionLintCmd.Example = sessionLintExamples
	sessionLoadCmd.Example = sessionLoadExamples
	projectCmd.Example = projectExamples
	exportCmd.Example = exportExamples
	doctorCmd.Example = doctorExamples
	skillsCmd.Example = skillsExamples
	skillsListCmd.Example = skillsListExamples
	skillsGetCmd.Example = skillsGetExamples
	skillsInstallCmd.Example = skillsInstallExamples
	extensionsCmd.Example = extensionsParentExamples
	extensionsLsCmd.Example = extensionsLsExamples
	extensionsDocsCmd.Example = extensionsDocsExamples
	extensionsPresetCmd.Example = extensionsPresetExamples
	extensionsExampleCmd.Example = extensionsExampleExamples
	findingCmd.Example = findingExamples
	findingLoadCmd.Example = findingLoadExamples
	logCmd.Example = logExamples
	logLsCmd.Example = logLsExamples
	projectCreateCmd.Example = projectCreateExamples
	projectListCmd.Example = projectListExamples
	projectUseCmd.Example = projectUseExamples
	projectConfigCmd.Example = projectConfigExamples
	projectDeleteCmd.Example = projectDeleteExamples
	authCmd.Example = sessionExamples
	sessionLsCmd.Example = sessionLsExamples
	sessionTotpCmd.Example = sessionTotpExamples
	strategyCmd.Example = strategyExamples
	versionCmd.Example = versionExamples
	storageCmd.Example = storageExamples
	storageLsCmd.Example = storageLsExamples
	storageUploadCmd.Example = storageUploadExamples
	storageDownloadCmd.Example = storageDownloadExamples
	storageResultsCmd.Example = storageResultsExamples
	storagePresignCmd.Example = storagePresignExamples
	storageRmCmd.Example = storageRmExamples
}

// flagGroup defines a section of related flags for help display.
type flagGroup struct {
	Name  string
	Flags []string // flag names (long form, no --)
}

// globalFlagGroups categorizes the root command's persistent flags. It is
// rendered as the "Global Flags:" block inherited by every subcommand (and only
// ever receives those persistent flags — the scan-local names of the past no
// longer appear here). Every persistent flag registered in root.go should live
// in exactly one group so no persistent flag falls into an "Other:" section.
var globalFlagGroups = []flagGroup{
	{"Output", []string{"verbose", "silent", "debug", "dump-traffic", "log-file", "json", "pretty", "format", "ci-output-format", "color", "no-color", "width"}},
	{"Network", []string{"proxy", "offline"}},
	{"Extensions", []string{"ext", "ext-dir", "ext-allow-failures"}},
	{"Project", []string{"project-uuid", "project-name"}},
	{"Info", []string{"list-modules", "list-input-mode", "full-example", "usage"}},
	{"Configuration", []string{"config", "db", "read-only", "force", "scan-uuid", "mem-limit", "skip-dependency-check", "soft-fail"}},
}

// groupedFlagSet flattens a group table into the set of flag names it covers.
// Shared by renderGroupedFlags (to decide what falls into "Other:") and the
// help-coverage tests, so both agree on what "grouped" means.
func groupedFlagSet(groups []flagGroup) map[string]bool {
	grouped := make(map[string]bool)
	for _, g := range groups {
		for _, name := range g.Flags {
			grouped[name] = true
		}
	}
	return grouped
}

// renderGroupedFlags renders flags organized by section with styled sub-headings.
// The outerHeading is printed first (e.g. "Global Flags:" or "Flags:").
func renderGroupedFlags(fs *pflag.FlagSet, outerHeading string, groups []flagGroup) string {
	grouped := groupedFlagSet(groups)

	var sections []string
	sections = append(sections, terminal.BoldYellow(outerHeading))

	for _, g := range groups {
		tmp := pflag.NewFlagSet("tmp", pflag.ContinueOnError)
		for _, name := range g.Flags {
			if f := fs.Lookup(name); f != nil {
				tmp.AddFlag(f)
			}
		}
		usage := tmp.FlagUsages()
		if usage == "" {
			continue
		}
		heading := "\n  " + terminal.BoldYellow(g.Name+":")
		sections = append(sections, heading+"\n"+strings.TrimRight(usage, "\n"))
	}

	// Collect any ungrouped flags into an "Other" section
	other := pflag.NewFlagSet("other", pflag.ContinueOnError)
	fs.VisitAll(func(f *pflag.Flag) {
		if !grouped[f.Name] {
			other.AddFlag(f)
		}
	})
	if usage := other.FlagUsages(); usage != "" {
		heading := "\n  " + terminal.BoldYellow("Other:")
		sections = append(sections, heading+"\n"+strings.TrimRight(usage, "\n"))
	}

	return strings.Join(sections, "\n")
}

// terseGlobalFlagHints are the handful of global flags surfaced inline in the
// piped/agent one-liner. The rest stay reachable via `vigolium --help`.
var terseGlobalFlagHints = []string{"verbose", "json", "proxy", "format", "config", "db", "force"}

// groupedFlagUsages renders inherited (global) flags for a subcommand's help.
// On an interactive TTY it prints the full grouped block, unchanged. When stdout
// is piped or redirected (coding agents, CI, `cmd | less`) it collapses to a
// single-line pointer so the identical block isn't repeated on every
// subcommand's help. The full list always remains reachable via `vigolium
// --help`, where the persistent flags render as the root's own local flags via
// localFlagUsages (root has no inherited flags, so this path never runs for it).
func groupedFlagUsages(fs *pflag.FlagSet) string {
	if !terminal.IsTerminal() {
		return terseGlobalFlags(fs)
	}
	return renderGroupedFlags(fs, "Global Flags:", globalFlagGroups)
}

// terseGlobalFlags renders the compact, one-line replacement for the full global
// flags block: the heading, a few high-traffic flags, and a pointer to the full
// list. Only hint flags actually inherited by this command are shown. Every hint
// is a root persistent flag, so a real subcommand always yields at least one.
func terseGlobalFlags(fs *pflag.FlagSet) string {
	var hints []string
	for _, name := range terseGlobalFlagHints {
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if f.Shorthand != "" {
			hints = append(hints, "-"+f.Shorthand+"/--"+f.Name)
		} else {
			hints = append(hints, "--"+f.Name)
		}
	}
	return terminal.BoldYellow("Global Flags:") + " " +
		strings.Join(hints, "  ") + "  " +
		terminal.Gray("(+more — run 'vigolium --help')")
}

// scanFlagGroups categorizes the local flags of the native-scan commands (scan,
// run, scan-url, scan-request — all detected via their shared `spider` flag).
// It is the union of every local flag those commands register; flags absent on a
// given command are silently skipped by renderGroupedFlags, so one table serves
// all four. Every non-hidden local flag should live in exactly one group here so
// the "Other:" section only ever holds cobra's auto-added --help.
var scanFlagGroups = []flagGroup{
	{"Target & Input", []string{"target", "target-file", "all-records", "record-uuid", "input-only", "include-stored", "input", "input-mode", "input-read-timeout", "no-scheme-probe"}},
	{"Input Format", []string{"required-only", "skip-format-validation"}},
	{"Spec Options", []string{"spec-url", "spec-header", "spec-var", "spec-default"}},
	{"Module Selection", []string{"modules", "module-tag", "module-id", "passive-only", "no-passive", "no-tech-filter", "allow-risky-payloads", "no-param-dedup", "header-fuzz", "resume-scan"}},
	{"Scanning", []string{"only", "skip", "dry-run", "intensity", "safe", "max-time", "scope-origin", "ignore-scope", "heuristics-check", "skip-heuristics", "oast-url"}},
	{"Advanced presets (prefer --intensity)", []string{"strategy", "scanning-profile"}},
	{"Discovery", []string{"discover", "discover-max-time", "discovery-wordlist", "discovery-extensions", "discovery-max-depth", "no-discovery-fuzz", "no-prefix-breaker", "follow-subdomains", "port-sweep-ports", "param-mining"}},
	{"Spidering", []string{"spider", "spider-max-time", "browser-engine", "browsers", "headless", "headed", "no-cdp", "no-forms", "browser-insecure", "require-auth", "no-carry-browser-session"}},
	{"Probe (host sweep)", []string{"probe", "tls-probe", "favicon", "redirect-mode", "record-redirect-chain", "depth", "fingerprint-depth"}},
	{"Harvest", []string{"external-harvest"}},
	{"KnownIssueScan", []string{"known-issue-scan", "known-issue-scan-tags", "known-issue-scan-exclude-tags", "known-issue-scan-severities", "known-issue-scan-templates-dir", "known-issue-scan-templates"}},
	{"Request", []string{"method", "body", "header", "advanced-options", "retries", "stream"}},
	{"Authentication", []string{"auth", "auth-file", "no-auth"}},
	{"Speed Control", []string{"timeout", "concurrency", "rate-limit", "max-per-host", "max-requests", "max-requests-per-host", "no-waf-pacing", "max-host-error", "max-findings-per-module", "no-clustering"}},
	{"Output", []string{"output", "stats", "fail-on", "fail-on-partial", "baseline", "ignore-file", "events", "include-response", "omit-response", "export-only", "report-url", "max-body-bytes", "pdf-timeout", "no-redact", "upload-results", "print-finding", "print-traffic", "print-traffic-tree"}},
	{"Scan Document (-j)", []string{"limit", "fields", "compact", "full-body", "max-output-bytes"}},
	{"Stateless & Parallel", []string{"stateless", "keep-db-on-error", "split-by-host", "db-isolate", "parallel", "resume"}},
}

// --- Agent-subcommand flag groups ---
//
// Each table mirrors scanFlagGroups: it is the union of one agent subcommand's
// visible local flags, rendered as titled sub-sections in that command's
// "Flags:" block. A flag absent on the command is skipped by renderGroupedFlags,
// so a shared table serves both an `agent <cmd>` and its top-level alias
// (olium/audit). Every visible local flag must land in exactly one group — guarded
// by TestFlagGroups_CoverAllVisibleFlags — so the trailing "Other:" section only
// ever holds cobra's auto-added --help.

// agentQueryFlagGroups categorizes `vigolium agent query`.
var agentQueryFlagGroups = []flagGroup{
	{"Prompt & Input", []string{"prompt", "stdin", "prompt-template", "prompt-file", "append", "instruction", "instruction-file"}},
	{"Source Code", []string{"source", "files", "source-label"}},
	{"AI Provider", []string{"provider", "model", "oauth-cred", "oauth-token", "llm-api-key", "gcp-project", "gcp-location", "base-url"}},
	{"Execution", []string{"agent-label", "max-duration", "dry-run", "show-prompt", "preflight-timeout", "no-preflight"}},
	{"Output", []string{"output", "verbose", "upload-results"}},
}

// agentAutopilotFlagGroups categorizes `vigolium agent autopilot`.
var agentAutopilotFlagGroups = []flagGroup{
	{"Target & Input", []string{"prompt", "prompt-file", "target", "input", "record-uuid", "burp-bridge-url", "prior-context", "knowledge-base", "knowledge-base-raw", "knowledge-base-no-traffic", "plan-file"}},
	{"Source & Audit", []string{"source", "files", "audit", "piolium", "diff", "last-commits"}},
	{"Authentication", []string{"auth-file"}},
	{"AI Provider", []string{"provider", "model", "oauth-cred", "oauth-token", "llm-api-key"}},
	{"Scan Behavior", []string{"intensity", "skill", "skill-tag", "no-skill-filter", "no-prescan", "no-preflight-discovery", "no-post-halt-verify", "post-halt-gap-threshold", "triage", "disable-guardrail"}},
	{"Budgets & Preflight", []string{"max-duration", "max-commands", "token-budget", "max-cost-usd", "preflight-timeout", "no-preflight"}},
	{"Execution", []string{"dry-run", "show-prompt", "system-prompt", "system-prompt-file", "resume", "headed"}},
	{"Output", []string{"stateless", "output", "verbose", "upload-results", "session-dir", "transcript", "db-isolate"}},
}

// agentSwarmFlagGroups categorizes `vigolium agent swarm`.
var agentSwarmFlagGroups = []flagGroup{
	{"Target & Input", []string{"prompt", "prompt-file", "target", "input", "record-uuid", "all-records", "records-from", "plan-file"}},
	{"Source & Audit", []string{"source", "files", "audit", "piolium", "diff", "last-commits", "code-audit", "source-analysis-only"}},
	{"AI Provider", []string{"provider", "model", "oauth-cred", "oauth-token", "llm-api-key", "gcp-project", "gcp-location", "base-url"}},
	{"Module & Phase Selection", []string{"modules", "vuln-type", "skill", "skill-tag", "no-skill-filter", "only", "skip", "start-from", "profile", "discover", "with-extensions"}},
	{"Scan Behavior", []string{"intensity", "triage", "max-iterations", "disable-guardrail"}},
	{"Budgets & Preflight", []string{"max-duration", "max-commands", "token-budget", "max-cost-usd", "preflight-timeout", "no-preflight"}},
	{"Authentication", []string{"browser-auth", "cookie", "header", "login-curl", "auth-config", "auth-file"}},
	{"Concurrency & Probing", []string{"batch-concurrency", "max-master-retries", "sub-agent-concurrency", "max-plan-records", "master-batch-size", "probe-concurrency", "probe-timeout", "max-probe-body"}},
	{"Execution", []string{"agent-label", "dry-run", "show-prompt", "headed"}},
	{"Output", []string{"verbose", "upload-results", "db-isolate"}},
}

// agentOliumFlagGroups categorizes `vigolium agent olium` and its `vigolium
// olium` alias (shared flag set via registerOliumFlags).
var agentOliumFlagGroups = []flagGroup{
	{"AI Provider", []string{"provider", "model", "oauth-cred", "oauth-token", "llm-api-key", "claude-bin", "bridge-bin", "gcp-project", "gcp-location", "base-url"}},
	{"Prompt", []string{"system", "prompt", "stdin"}},
}

// agentAuditFlagGroups categorizes `vigolium agent audit` and its `vigolium
// audit` alias (shared flag set via registerAuditFlags).
var agentAuditFlagGroups = []flagGroup{
	{"Source & Driver", []string{"source", "driver", "commit-depth"}},
	{"Mode & Intensity", []string{"intensity", "mode", "modes", "list-modes"}},
	{"Agent (audit leg)", []string{"provider", "agent"}},
	{"Piolium Leg", []string{"pi-provider", "pi-model", "plm-scan-limit", "plm-scan-since", "plm-phase-retries", "plm-command-retries", "plm-longshot-limit", "plm-longshot-timeout", "plm-longshot-langs"}},
	{"Authentication (BYOK)", []string{"api-key", "oauth-token", "oauth-cred-file"}},
	{"Preflight", []string{"no-preflight", "preflight-timeout"}},
	{"Execution", []string{"interactive", "no-stream", "show-thinking", "no-dedup", "keep-raw", "clean-raw", "dry-run", "max-duration"}},
	{"Output", []string{"stateless", "output", "output-dir", "upload-results"}},
}

// agentTriageFlagGroups categorizes `vigolium agent triage`.
var agentTriageFlagGroups = []flagGroup{
	{"AI Provider", []string{"provider", "model", "oauth-cred", "oauth-token", "llm-api-key", "gcp-project", "gcp-location", "base-url"}},
	{"Verdict", []string{"no-write", "report-only", "no-probe"}},
	{"Execution", []string{"max-duration", "dry-run", "show-prompt", "verbose", "preflight-timeout", "no-preflight"}},
}

// agentSessionFlagGroups categorizes `vigolium agent session`.
var agentSessionFlagGroups = []flagGroup{
	{"Filter", []string{"mode", "limit", "offset"}},
	{"Output", []string{"tail", "full", "tui", "no-tui", "fields", "compact", "max-output-bytes"}},
}

// --- Data-command flag groups ---
//
// These follow the same union-table pattern as scanFlagGroups: each table is the
// union of one (or a family of) command's visible local flags, and TestFlagGroups_
// CoverAllVisibleFlags guards that every visible flag lands in a group. Global
// flags (--json, --db, …) render in the separate "Global Flags:" block, so they
// are not listed here even when a description mentions them.

// listQueryFlagGroups categorizes the record/finding browse commands — `vigolium
// finding`, `vigolium traffic`, and `vigolium db ls`. It is the union of their
// local flags; a flag absent on a given command is skipped, so one table serves
// all three (e.g. the Replay group only materializes for traffic, the schema
// flags only for db ls).
var listQueryFlagGroups = []flagGroup{
	{"Filter", []string{"uuid", "url", "host", "method", "status", "path", "source", "scan-uuid", "module-type", "finding-source", "record-kind", "severity", "min-severity", "confidence", "agentic-scan", "id", "min-risk", "min-surface", "remark"}},
	{"Lifecycle", []string{"verdict", "new-since", "include-dismissed"}},
	{"Search", []string{"search", "header", "body", "exclude-search", "exclude-header", "exclude-body", "exclude-not-found"}},
	{"Date Range", []string{"from", "to"}},
	{"Display", []string{"tree", "raw", "burp", "markdown", "group-by", "group-limit", "columns", "exclude-columns", "tui", "no-tui"}},
	{"Output", []string{"fields", "compact", "full-body", "max-output-bytes", "output", "with-records", "record-fields", "record-limit", "no-header"}},
	{"Pagination & Sort", []string{"limit", "offset", "sort", "asc", "pick", "all"}},
	{"Data Source", []string{"stateless", "glob-db", "glob-strict", "table", "list-tables", "list-columns"}},
	{"Replay", []string{"replay", "ignore-scope", "concurrency", "with-browser", "burp-bridge-url", "save-to-vigolium-db", "save-to-burp", "in-replace", "timeout"}},
	{"Burp Push", []string{"push-to-burp", "to-repeater", "send-via-burp", "http-mode"}},
	{"Curl", []string{"curl", "curl-all", "redact-auth"}},
}

// inventoryFlagGroups categorizes `vigolium endpoints` and `vigolium params`
// (the union of their local flags).
var inventoryFlagGroups = []flagGroup{
	{"Filter", []string{"host", "method", "status", "path", "source", "remark", "scan-uuid", "endpoint", "location", "type"}},
	{"Date Range", []string{"from", "to"}},
	{"Aggregate", []string{"min-records", "min-occurrences", "collapse", "show-values"}},
	{"Pagination & Sort", []string{"limit", "offset", "sort"}},
	{"Output", []string{"output", "fields", "compact", "max-output-bytes", "no-header"}},
	{"Data Source", []string{"stateless", "glob-db", "glob-strict"}},
}

// fuzzFlagGroups categorizes `vigolium fuzz`. Every visible local flag must land
// in exactly one group (guarded by TestFlagGroups_CoverAllVisibleFlags) so the
// trailing "Other:" section only ever holds cobra's auto-added --help.
var fuzzFlagGroups = []flagGroup{
	{"Source", []string{"input", "input-file", "record-uuid", "target"}},
	{"Request Builder", []string{
		"request", "header", "data", "data-raw", "data-binary", "data-urlencode",
		"form", "form-string", "get", "head", "cookie", "user", "user-agent", "referer"}},
	{"Positions", []string{"fuzz", "point", "fuzz-header", "keyword", "mode"}},
	{"Payloads", []string{"class", "wordlist", "payload", "suffix"}},
	{"Anomaly Detection", []string{"anomaly", "anomaly-threshold", "anomaly-min-population", "baseline-samples"}},
	{"Matchers", []string{
		"match-status-code", "match-size", "match-words", "match-lines",
		"match-regex", "match-time", "match-time-z", "match-header", "match-mode"}},
	{"Exclude", []string{
		"exclude-status-code", "exclude-size", "exclude-words", "exclude-lines",
		"exclude-regex", "exclude-time", "exclude-time-z", "exclude-header", "exclude-mode"}},
	{"Network", []string{
		"insecure", "verify-tls", "cacert", "cert", "key", "location", "max-redirs",
		"connect-timeout", "max-time", "compressed", "http-version", "http1.1", "http2", "http3", "http3-only",
		"resolve", "path-as-is"}},
	{"Session & Auth", []string{"auth-session", "session-id", "no-cookies"}},
	{"Speed & Behaviour", []string{
		"no-calibrate", "allow-baseline-error", "concurrency", "rate-limit", "max-requests", "delay", "timeout", "no-redirects",
		"dry-run", "ignore-scope", "keep-host"}},
	{"Output", []string{"output", "all-results", "limit", "fail-on-match", "save", "fields", "compact", "max-output-bytes"}},
	{"Burp Bridge", []string{"send-via-burp", "burp-bridge-url", "http-mode", "send-timeout", "matches-to-organizer"}},
}

// replayFlagGroups categorizes `vigolium replay`.
var replayFlagGroups = []flagGroup{
	{"Input & Selection", []string{"input", "input-file", "raw-request", "raw-request-file", "record-uuid", "finding-id", "target"}},
	{"Bulk Filter", []string{"host", "method", "status", "path", "source", "search", "header-search", "body", "exclude-search", "exclude-header-search", "exclude-body", "from", "to", "sort", "asc", "offset", "limit", "all", "all-matches"}},
	{"Request Options", []string{"header", "ignore-scope", "keep-host", "auth-session", "session-id", "no-cookies", "no-redirects", "baseline", "timeout", "concurrency", "with-browser"}},
	{"Output", []string{"output", "once", "save", "no-save", "dry-run", "in-replace", "stateless", "fields", "compact", "max-output-bytes", "excerpt-bytes"}},
	{"Burp Bridge", []string{"burp-bridge-url", "save-to-burp", "send-via-burp", "http-mode", "send-timeout", "to-repeater", "repeater-tab", "to-organizer", "notes", "highlight"}},
}

// ingestFlagGroups categorizes `vigolium ingest`.
var ingestFlagGroups = []flagGroup{
	{"Target & Input", []string{"target", "target-file", "input", "input-mode", "input-read-timeout"}},
	{"Spec Options", []string{"spec-url", "spec-header", "spec-var", "spec-default"}},
	{"Module Selection", []string{"modules", "module-tag", "no-tech-filter"}},
	{"Ingestion", []string{"server", "scan-on-receive", "full-native-scan-on-receive", "disable-fetch-response", "keep-blocked", "scope-origin", "intensity", "dir", "dir-glob", "dry-run"}},
	{"Speed Control", []string{"timeout", "concurrency", "rate-limit", "max-per-host", "max-host-error", "max-findings-per-module", "no-clustering", "no-waf-pacing"}},
}

// serverFlagGroups categorizes `vigolium server`.
var serverFlagGroups = []flagGroup{
	{"Network", []string{"host", "service-port", "ingest-proxy-port", "ingest-proxy-host", "timeout"}},
	{"Ingestion", []string{"scan-on-receive", "full-native-scan-on-receive", "passive-only", "mem-buffer", "discard-queued", "catchup-threads", "disable-catchup", "disable-warm-session"}},
	{"Proxy & Bridge", []string{"burp-bridge-url", "proxy-token", "proxy-allow", "proxy-insecure", "proxy-mitm"}},
	{"Access Control", []string{"no-auth", "allow-unauthenticated-bind", "alternative-ingest-key", "view-only", "demo-only", "no-agent", "no-swagger"}},
	{"Output", []string{"output", "mirror-fs", "events"}},
}

// exportFlagGroups categorizes `vigolium export`.
var exportFlagGroups = []flagGroup{
	{"Output Format", []string{"format", "output", "omit-response", "no-url-dedup"}},
	{"Filter", []string{"search", "exclude", "severity", "scan-uuid", "only", "limit", "all-projects", "from", "to"}},
	{"Report Metadata", []string{"report-title", "report-target", "report-duration", "report-generated-at", "report-url", "max-body-bytes", "pdf-timeout", "no-redact"}},
	{"Data Source", []string{"db", "stateless", "glob-db", "glob-strict"}},
}

// importFlagGroups categorizes `vigolium import`.
var importFlagGroups = []flagGroup{
	{"Output Format", []string{"format", "output"}},
	{"Filter", []string{"search", "severity"}},
	{"Report Metadata", []string{"report-title", "report-target", "report-duration", "report-generated-at", "report-url", "max-body-bytes", "pdf-timeout", "no-redact"}},
	{"Source & Upload", []string{"glob-db", "upload", "upload-key", "burp-bridge-url", "include-scopes", "glob-strict", "dry-run"}},
	// Bridge-pull narrowing. An unfiltered -B pull copies the operator's entire
	// proxy history — every host they have browsed, with its cookies — so these
	// get their own titled block rather than being buried under "Filter".
	{"Bridge Pull Filter", []string{"host", "path", "method", "status", "exclude-search", "from", "to", "limit", "all-hosts", "yes"}},
}

// commandFlagGroups maps a command to the flag-group table used to render its
// local "Flags:" block. Commands absent from the map render a flat, ungrouped
// list (the default for simple read/list commands). Keying by command pointer
// (rather than sniffing a signature flag out of the flag set) means help
// rendering can't misattribute a command whose local flags overlap another's;
// the shared tables (olium/audit and their top-level aliases, the scan and
// list-query families) let several commands point at one table.
//
// This is a package-level literal: Go initializes it after the command vars and
// group-table vars it references (dependency order), and it only stores pointers,
// so the commands' flags need not be registered yet — they're resolved to flag
// sets lazily at render time. TestFlagGroups_CoverAllVisibleFlags iterates this
// map, so it also guards the wiring itself, not just the tables.
var commandFlagGroups = map[*cobra.Command][]flagGroup{
	scanCmd:        scanFlagGroups,
	runCmd:         scanFlagGroups,
	fingerprintCmd: scanFlagGroups,
	scanURLCmd:     scanFlagGroups,
	scanRequestCmd: scanFlagGroups,

	agentQueryCmd:     agentQueryFlagGroups,
	agentAutopilotCmd: agentAutopilotFlagGroups,
	agentSwarmCmd:     agentSwarmFlagGroups,
	agentOliumCmd:     agentOliumFlagGroups,
	oliumCmd:          agentOliumFlagGroups,
	agentAuditCmd:     agentAuditFlagGroups,
	auditCmd:          agentAuditFlagGroups,
	agentTriageCmd:    agentTriageFlagGroups,
	agentSessionCmd:   agentSessionFlagGroups,

	findingCmd:   listQueryFlagGroups,
	trafficCmd:   listQueryFlagGroups,
	dbListCmd:    listQueryFlagGroups,
	endpointsCmd: inventoryFlagGroups,
	paramsCmd:    inventoryFlagGroups,
	replayCmd:    replayFlagGroups,
	fuzzCmd:      fuzzFlagGroups,
	ingestCmd:    ingestFlagGroups,
	serverCmd:    serverFlagGroups,
	exportCmd:    exportFlagGroups,
	importCmd:    importFlagGroups,
}

// localFlagUsages renders a command's local flags. Commands registered in
// commandFlagGroups (the native-scan family and the agent subcommands) get their
// flags grouped into titled sub-sections; every other command renders a flat
// list. Keying off the command itself avoids the old flag-set sniffing, which
// mis-grouped agent subcommands that happen to register a local target/verbose.
func localFlagUsages(cmd *cobra.Command) string {
	fs := cmd.LocalFlags()
	if groups, ok := commandFlagGroups[cmd]; ok {
		return renderGroupedFlags(fs, "Flags:", groups)
	}
	return terminal.BoldYellow("Flags:") + "\n" + strings.TrimRight(fs.FlagUsages(), "\n")
}

// FormatExamples builds a colored example block for cobra commands.
// Lines starting with "#" are rendered as gray comments.
// All other lines are rendered as cyan commands.
func FormatExamples(examples ...string) string {
	var lines []string
	for _, ex := range examples {
		if strings.HasPrefix(strings.TrimSpace(ex), "#") {
			lines = append(lines, "  "+terminal.Gray(ex))
		} else {
			lines = append(lines, "  "+terminal.Green(ex))
		}
	}
	return strings.Join(lines, "\n")
}

// --- Colored help and usage templates ---
//
// Cobra's default help template prints `Long` first, then `.UsageString`.
// We override both so the layout becomes:
//
//   Global Flags
//   Usage / Aliases / Available Commands / Flags (local)
//   Description (Long, falls back to Short)
//   Examples
//   Additional help topics / footer / website banner
//
// Rationale: Global Flags are rendered first so the shared, noisy block is
// scrolled past immediately. Command-specific context (Usage, local Flags,
// Description) is grouped together so the user can read the command's own
// surface in one glance. Examples remain at the bottom so the terminal scroll
// lands on them after the command finishes.

// coloredHelpTemplate replaces cobra's default help template so the `Long`
// description is rendered by the usage template (at the bottom) instead of
// being printed before it.
var coloredHelpTemplate = `{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

var coloredUsageTemplate = `{{if .HasAvailableInheritedFlags}}{{.InheritedFlags | groupedFlagUsages}}

{{end}}{{ styleHeading "Usage:" }}{{if .Runnable}}
  {{ .UseLine | styleCyan }}{{end}}{{if .HasAvailableSubCommands}}
  {{ .CommandPath | styleCyan }} [command]{{end}}{{if gt (len .Aliases) 0}}

{{ styleHeading "Aliases:" }}
  {{.NameAndAliases}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

{{ styleHeading "Available Commands:" }}{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

{{ styleHeading "Additional Commands:" }}{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{. | localFlagUsages}}{{end}}{{with (or .Long .Short)}}

{{ styleHeading "Description:" }}
{{. | trimTrailingWhitespaces}}{{end}}{{if .HasExample}}

{{ styleHeading "Examples:" }}
{{.Example}}{{end}}{{if .HasHelpSubCommands}}

{{ styleHeading "Additional help topics:" }}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

{{ "Use" | styleGray }} "{{.CommandPath | styleCyan}} [command] --help" {{ "for more information about a command." | styleGray }}{{end}}

` + terminal.Cyan(terminal.SymbolDiamondSm) + ` {{ "Website:" | styleGray }} {{ "https://www.vigolium.com" | styleMagenta }} {{ "·" | styleGray }} ` + terminal.Cyan(terminal.SymbolMenu) + ` {{ "Docs:" | styleGray }} {{ "https://docs.vigolium.com" | styleMagenta }}
`
