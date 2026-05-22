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
	configCmd.Example = configExamples
	configLsCmd.Example = configLsExamples
	configSetCmd.Example = configSetExamples
	configCleanCmd.Example = configCleanExamples
	dbCmd.Example = dbExamples
	dbListCmd.Example = dbListExamples
	dbStatsCmd.Example = dbStatsExamples
	dbExportCmd.Example = dbExportExamples
	dbCleanCmd.Example = dbCleanExamples
	dbSeedCmd.Example = dbSeedExamples
	trafficCmd.Example = trafficExamples
	trafficReplayCmd.Example = trafficReplayExamples
	scopeCmd.Example = scopeExamples
	scopeViewCmd.Example = scopeViewExamples
	scopeSetCmd.Example = scopeSetExamples
	runCmd.Example = runExamples
	agentCmd.Example = agentExamples
	agentQueryCmd.Example = agenticScanExamples
	agentSessionCmd.Example = agentSessionExamples
	agentAuditCmd.Example = agentAuditExamples
	agentPioliumCmd.Example = agentPioliumExamples
	agentAutopilotCmd.Example = agentAutopilotExamples
	agentSwarmCmd.Example = agentSwarmExamples
	agentOliumCmd.Example = oliumExamples
	oliumCmd.Example = oliumExamples
	scanURLCmd.Example = scanURLExamples
	scanRequestCmd.Example = scanRequestExamples
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
	findingCmd.Example = findingExamples
	findingLoadCmd.Example = findingLoadExamples
	logCmd.Example = logExamples
	logLsCmd.Example = logLsExamples
	projectCreateCmd.Example = projectCreateExamples
	projectListCmd.Example = projectListExamples
	projectUseCmd.Example = projectUseExamples
	projectConfigCmd.Example = projectConfigExamples
	authCmd.Example = sessionExamples
	sessionLsCmd.Example = sessionLsExamples
	sessionTotpCmd.Example = sessionTotpExamples
	strategyCmd.Example = strategyExamples
	strategyLsCmd.Example = strategyLsExamples
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

var globalFlagGroups = []flagGroup{
	{"Target", []string{"target", "target-file"}},
	{"Ingest Input", []string{"input", "input-mode", "input-read-timeout", "disable-fetch-response"}},
	{"Spec Options", []string{"spec-url", "spec-header", "spec-var", "spec-default"}},
	{"Module Selection", []string{"modules", "list-modules", "list-input-mode"}},
	{"Scanning", []string{"scan-on-receive", "scan-uuid", "scanning-profile", "strategy", "only", "skip", "scope-origin", "source", "scanning-max-duration"}},
	{"Network", []string{"proxy", "timeout"}},
	{"Speed Control", []string{"concurrency", "rate-limit", "max-per-host", "max-host-error", "max-findings-per-module"}},
	{"Output", []string{"verbose", "silent", "debug", "json", "format", "width"}},
	{"Configuration", []string{"config", "db", "force"}},
}

// renderGroupedFlags renders flags organized by section with styled sub-headings.
// The outerHeading is printed first (e.g. "Global Flags:" or "Flags:").
func renderGroupedFlags(fs *pflag.FlagSet, outerHeading string, groups []flagGroup) string {
	// Build a set of all flag names that belong to a group
	grouped := make(map[string]bool)
	for _, g := range groups {
		for _, name := range g.Flags {
			grouped[name] = true
		}
	}

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

// groupedFlagUsages renders inherited (global) flags grouped by section.
func groupedFlagUsages(fs *pflag.FlagSet) string {
	return renderGroupedFlags(fs, "Global Flags:", globalFlagGroups)
}

var scanFlagGroups = []flagGroup{
	{"Spidering", []string{"spider", "spider-max-time", "browser-engine", "browsers", "headless", "no-cdp", "no-forms"}},
	{"Discovery", []string{"discover", "discover-max-time"}},
	{"Harvest", []string{"external-harvest"}},
	{"KnownIssueScan", []string{"known-issue-scan-tags", "known-issue-scan-exclude-tags", "known-issue-scan-severities", "known-issue-scan-templates-dir"}},
	{"Input Format", []string{"required-only", "skip-format-validation"}},
	{"Request", []string{"header", "advanced-options", "retries", "stream"}},
	{"Output", []string{"output", "stats", "include-response", "stateless"}},
}

// localFlagUsages renders local flags. For the root command (which contains
// global flags), it applies grouping. For subcommands, it renders a flat list.
func localFlagUsages(fs *pflag.FlagSet) string {
	// Detect root command by checking for well-known global flags
	if fs.Lookup("verbose") != nil && fs.Lookup("target") != nil {
		return renderGroupedFlags(fs, "Flags:", globalFlagGroups)
	}
	// Detect scan command by checking for a well-known scan-only flag
	if fs.Lookup("spider") != nil {
		return renderGroupedFlags(fs, "Flags:", scanFlagGroups)
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

{{.LocalFlags | localFlagUsages}}{{end}}{{with (or .Long .Short)}}

{{ styleHeading "Description:" }}
{{. | trimTrailingWhitespaces}}{{end}}{{if .HasExample}}

{{ styleHeading "Examples:" }}
{{.Example}}{{end}}{{if .HasHelpSubCommands}}

{{ styleHeading "Additional help topics:" }}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

{{ "Use" | styleGray }} "{{.CommandPath | styleCyan}} [command] --help" {{ "for more information about a command." | styleGray }}{{end}}

` + terminal.Cyan(terminal.SymbolDiamondSm) + ` {{ "Website:" | styleGray }} {{ "https://www.vigolium.com" | styleMagenta }} {{ "·" | styleGray }} ` + terminal.Cyan(terminal.SymbolMenu) + ` {{ "Docs:" | styleGray }} {{ "https://docs.vigolium.com" | styleMagenta }}
`
