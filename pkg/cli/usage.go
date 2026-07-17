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
	{"Output", []string{"verbose", "silent", "debug", "dump-traffic", "log-file", "json", "format", "ci-output-format", "no-color", "width"}},
	{"Network", []string{"proxy"}},
	{"Extensions", []string{"ext", "ext-dir"}},
	{"Project", []string{"project-uuid", "project-name"}},
	{"Info", []string{"list-modules", "list-input-mode", "full-example"}},
	{"Configuration", []string{"config", "db", "force", "scan-uuid", "mem-limit", "skip-dependency-check", "soft-fail"}},
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
	{"Target & Input", []string{"target", "target-file", "input", "input-mode", "input-read-timeout"}},
	{"Input Format", []string{"required-only", "skip-format-validation"}},
	{"Spec Options", []string{"spec-url", "spec-header", "spec-var", "spec-default"}},
	{"Module Selection", []string{"modules", "module-tag", "module-id", "passive-only", "no-passive", "no-tech-filter"}},
	{"Scanning", []string{"only", "skip", "strategy", "scanning-profile", "intensity", "scope-origin", "scanning-max-duration", "heuristics-check", "skip-heuristics", "oast-url"}},
	{"Discovery", []string{"discover", "discover-max-time", "fuzz-wordlist", "no-prefix-breaker", "follow-subdomains", "port-sweep-ports"}},
	{"Spidering", []string{"spider", "spider-max-time", "browser-engine", "browsers", "headless", "headed", "no-cdp", "no-forms", "no-carry-browser-session"}},
	{"Harvest", []string{"external-harvest"}},
	{"KnownIssueScan", []string{"known-issue-scan", "known-issue-scan-tags", "known-issue-scan-exclude-tags", "known-issue-scan-severities", "known-issue-scan-templates-dir"}},
	{"Request", []string{"method", "body", "header", "advanced-options", "retries", "stream"}},
	{"Authentication", []string{"auth", "auth-file"}},
	{"Speed Control", []string{"timeout", "concurrency", "rate-limit", "max-per-host", "no-waf-pacing", "max-host-error", "max-findings-per-module", "no-clustering"}},
	{"Output", []string{"output", "stats", "fail-on", "include-response", "omit-response", "report-url", "upload-results", "print-finding", "print-traffic", "print-traffic-tree"}},
	{"Stateless & Parallel", []string{"stateless", "split-by-host", "db-isolate", "parallel", "resume"}},
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
	{"Execution", []string{"agent-label", "max-duration", "dry-run", "show-prompt"}},
	{"Output", []string{"output", "verbose", "upload-results"}},
}

// agentAutopilotFlagGroups categorizes `vigolium agent autopilot`.
var agentAutopilotFlagGroups = []flagGroup{
	{"Target & Input", []string{"prompt", "target", "input", "record-uuid", "burp-bridge-url", "prior-context", "knowledge-base", "knowledge-base-raw", "knowledge-base-no-traffic", "plan-file"}},
	{"Source & Audit", []string{"source", "files", "audit", "piolium", "diff", "last-commits"}},
	{"AI Provider", []string{"provider", "model", "oauth-cred", "oauth-token", "llm-api-key"}},
	{"Scan Behavior", []string{"intensity", "skill", "skill-tag", "no-skill-filter", "no-prescan", "no-preflight-discovery", "no-post-halt-verify", "post-halt-gap-threshold", "triage", "disable-guardrail", "max-duration"}},
	{"Execution", []string{"dry-run", "show-prompt", "system-prompt", "system-prompt-file", "resume", "headed"}},
	{"Output", []string{"verbose", "upload-results", "session-dir", "transcript", "db-isolate"}},
}

// agentSwarmFlagGroups categorizes `vigolium agent swarm`.
var agentSwarmFlagGroups = []flagGroup{
	{"Target & Input", []string{"prompt", "target", "input", "record-uuid", "all-records", "records-from", "plan-file"}},
	{"Source & Audit", []string{"source", "files", "audit", "piolium", "diff", "last-commits", "code-audit", "source-analysis-only"}},
	{"AI Provider", []string{"provider", "model", "oauth-cred", "oauth-token", "llm-api-key", "gcp-project", "gcp-location", "base-url"}},
	{"Module & Phase Selection", []string{"modules", "vuln-type", "skill", "skill-tag", "no-skill-filter", "only", "skip", "start-from", "profile", "discover", "with-extensions"}},
	{"Scan Behavior", []string{"intensity", "triage", "max-iterations", "max-duration", "disable-guardrail"}},
	{"Authentication", []string{"browser-auth", "cookie", "header", "login-curl", "auth-config"}},
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
	{"Execution", []string{"interactive", "no-stream", "show-thinking", "no-dedup", "keep-raw", "clean-raw"}},
	{"Output", []string{"stateless", "output", "output-dir", "upload-results"}},
}

// agentTriageFlagGroups categorizes `vigolium agent triage`.
var agentTriageFlagGroups = []flagGroup{
	{"AI Provider", []string{"provider", "model", "oauth-cred", "oauth-token", "llm-api-key", "gcp-project", "gcp-location", "base-url"}},
	{"Execution", []string{"max-duration", "dry-run", "show-prompt", "verbose"}},
}

// agentSessionFlagGroups categorizes `vigolium agent session`.
var agentSessionFlagGroups = []flagGroup{
	{"Filter", []string{"mode", "limit", "offset"}},
	{"Output", []string{"tail", "full", "tui", "no-tui"}},
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
	{"Filter", []string{"host", "method", "status", "path", "source", "scan-uuid", "module-type", "finding-source", "record-kind", "severity", "min-severity", "confidence", "agentic-scan", "id", "min-risk", "remark"}},
	{"Search", []string{"search", "header", "body", "exclude-search", "exclude-header", "exclude-body"}},
	{"Date Range", []string{"from", "to"}},
	{"Display", []string{"tree", "raw", "burp", "markdown", "columns", "exclude-columns", "tui", "no-tui"}},
	{"Output", []string{"fields", "compact", "full-body", "with-records"}},
	{"Pagination & Sort", []string{"limit", "offset", "sort", "asc", "pick", "all"}},
	{"Data Source", []string{"stateless", "glob-db", "table", "list-tables", "list-columns"}},
	{"Replay", []string{"replay", "concurrency", "with-browser", "burp-bridge-url", "save-to-vigolium-db", "save-to-burp", "in-replace", "timeout"}},
}

// replayFlagGroups categorizes `vigolium replay`.
var replayFlagGroups = []flagGroup{
	{"Input & Selection", []string{"input", "input-file", "raw-request", "raw-request-file", "record-uuid", "finding-id", "target"}},
	{"Bulk Filter", []string{"host", "method", "status", "path", "source", "search", "body", "limit", "all"}},
	{"Mutation", []string{"mutate"}},
	{"Request Options", []string{"header", "auth-session", "session-id", "no-cookies", "no-redirects", "timeout", "concurrency"}},
	{"Output", []string{"output", "pretty", "in-replace", "save-to-burp", "burp-bridge-url", "stateless"}},
}

// ingestFlagGroups categorizes `vigolium ingest`.
var ingestFlagGroups = []flagGroup{
	{"Target & Input", []string{"target", "target-file", "input", "input-mode", "input-read-timeout"}},
	{"Spec Options", []string{"spec-url", "spec-header", "spec-var", "spec-default"}},
	{"Module Selection", []string{"modules", "module-tag", "no-tech-filter"}},
	{"Ingestion", []string{"server", "scan-on-receive", "full-native-scan-on-receive", "disable-fetch-response", "scope-origin", "intensity"}},
	{"Speed Control", []string{"timeout", "concurrency", "rate-limit", "max-per-host", "max-host-error", "max-findings-per-module", "no-clustering", "no-waf-pacing"}},
}

// serverFlagGroups categorizes `vigolium server`.
var serverFlagGroups = []flagGroup{
	{"Network", []string{"host", "service-port", "ingest-proxy-port", "timeout"}},
	{"Ingestion", []string{"scan-on-receive", "full-native-scan-on-receive", "passive-only", "mem-buffer", "catchup-threads", "disable-catchup", "disable-warm-session"}},
	{"Proxy & Bridge", []string{"burp-bridge-url", "proxy-insecure", "proxy-mitm", "export-ca"}},
	{"Access Control", []string{"no-auth", "alternative-ingest-key", "view-only", "demo-only", "no-agent", "no-swagger"}},
	{"Output", []string{"output", "mirror-fs"}},
}

// exportFlagGroups categorizes `vigolium export`.
var exportFlagGroups = []flagGroup{
	{"Output Format", []string{"format", "output", "omit-response"}},
	{"Filter", []string{"search", "exclude", "severity", "scan-uuid", "only", "limit"}},
	{"Report Metadata", []string{"report-title", "report-target", "report-duration", "report-generated-at", "report-url"}},
	{"Data Source", []string{"db", "stateless", "glob-db"}},
}

// importFlagGroups categorizes `vigolium import`.
var importFlagGroups = []flagGroup{
	{"Output Format", []string{"format", "output"}},
	{"Filter", []string{"search", "severity"}},
	{"Report Metadata", []string{"report-title", "report-target", "report-duration", "report-generated-at", "report-url"}},
	{"Source & Upload", []string{"glob-db", "upload", "upload-key", "burp-bridge-url"}},
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

	findingCmd: listQueryFlagGroups,
	trafficCmd: listQueryFlagGroups,
	dbListCmd:  listQueryFlagGroups,
	replayCmd:  replayFlagGroups,
	ingestCmd:  ingestFlagGroups,
	serverCmd:  serverFlagGroups,
	exportCmd:  exportFlagGroups,
	importCmd:  importFlagGroups,
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
