package cli

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func init() {
	cobra.AddTemplateFunc("styleHeading", terminal.BoldYellow)
	cobra.AddTemplateFunc("styleCyan", terminal.Cyan)
	cobra.AddTemplateFunc("styleGray", terminal.Gray)
	cobra.AddTemplateFunc("groupedFlagUsages", groupedFlagUsages)
	cobra.AddTemplateFunc("localFlagUsages", localFlagUsages)

	rootCmd.SetUsageTemplate(coloredUsageTemplate)

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
	dbListCmd.Example = dbListExamples
	dbStatsCmd.Example = dbStatsExamples
	dbExportCmd.Example = dbExportExamples
	dbCleanCmd.Example = dbCleanExamples
	trafficCmd.Example = trafficExamples
	trafficReplayCmd.Example = trafficReplayExamples
	scopeViewCmd.Example = scopeViewExamples
	scopeSetCmd.Example = scopeSetExamples
	runCmd.Example = runExamples
	agentCmd.Example = agentExamples
	agentQueryCmd.Example = agentRunExamples
	exportCmd.Example = exportExamples
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
	{"Scanning", []string{"scan-on-receive", "scan-id", "scanning-profile", "strategy", "only", "skip", "scope-origin", "source", "scanning-max-duration"}},
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
	{"SAST", []string{"rule", "sast-adhoc"}},
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
			lines = append(lines, "  "+terminal.Cyan(ex))
		}
	}
	return strings.Join(lines, "\n")
}

// --- Example blocks for each command ---

var rootExamples = FormatExamples(
	"# Scan a single URL for vulnerabilities",
	"vigolium scan -t https://example.com",
	"# Scan targets from a file with specific modules",
	"vigolium scan -T targets.txt -m xss-reflected,sqli-error",
	"# Scan an OpenAPI specification",
	"vigolium scan -T openapi.yaml -I openapi",
	"# Pipe URLs from stdin",
	"cat urls.txt | vigolium scan",
	"# Use a scanning strategy preset",
	"vigolium scan -t https://example.com --strategy deep",
	"# Run content discovery before scanning",
	"vigolium scan -t https://example.com --discover",
	"# Source-aware scanning with local source code",
	"vigolium scan -t https://example.com --source /path/to/app --strategy whitebox",
	"",
	"# Start the API server (uses auto-generated key from config)",
	"vigolium server",
	"# Start the server without authentication (local use only)",
	"vigolium server -A",
	"",
	"# Ingest HTTP traffic into the database",
	"cat urls.txt | vigolium ingest",
	"# Ingest an OpenAPI spec to a remote server",
	"vigolium ingest -s http://server:9002 -i api.yaml -I openapi",
	"",
	"# List all scanner modules",
	"vigolium module ls",
	"# Search modules by keyword",
	"vigolium module ls xss",
	"",
	"# View configuration",
	"vigolium config ls",
	"# Browse recorded HTTP traffic",
	"vigolium traffic",
	"# Database statistics",
	"vigolium db stats --detailed",
)

var scanExamples = FormatExamples(
	"# Scan a single URL",
	"vigolium scan -t https://example.com",
	"# Scan multiple targets from file",
	"vigolium scan -T targets.txt",
	"# Read targets from stdin",
	"cat urls.txt | vigolium scan",
	"",
	"# Run specific modules only (fuzzy match on ID/name)",
	"vigolium scan -t https://example.com -m xss-reflected,sqli-error",
	"# Filter modules by tag",
	"vigolium scan -t https://example.com --module-tag spring --module-tag injection",
	"# With custom headers and proxy",
	`vigolium scan -t https://example.com -H "Authorization: Bearer token" --proxy http://127.0.0.1:8080`,
	"",
	"# Scan OpenAPI spec (auto-detects format)",
	"vigolium scan -i openapi.yaml -t https://api.example.com",
	"# Scan Burp Suite export",
	"vigolium scan -i burp-export.xml -I burp",
	"# Scan HAR file",
	"vigolium scan -i traffic.har -I har",
	"",
	"# Use a scanning strategy preset (lite, balanced, deep, whitebox)",
	"vigolium scan -t https://example.com --strategy deep",
	"# Use a scanning profile (quick, standard, full)",
	"vigolium scan -t https://example.com --scanning-profile quick",
	"# Override max scan duration",
	"vigolium scan -t https://example.com --scanning-max-duration 2h",
	"# Adjust concurrency and rate limit",
	"vigolium scan -T targets.txt -c 100 --rate-limit 200 --max-per-host 5",
	"",
	"# Phase isolation: run only one phase",
	"vigolium scan -t https://example.com --only discovery",
	"vigolium scan -t https://example.com --only known-issue-scan",
	"vigolium scan -t https://example.com --only audit",
	"# Skip specific phases",
	"vigolium scan -t https://example.com --skip discovery,spidering",
	"",
	"# Run content discovery before scanning",
	"vigolium scan -t https://example.com --discover",
	"# Run browser-based spidering",
	"vigolium scan -t https://example.com --spider --browsers 2",
	"# External intelligence harvesting",
	"vigolium scan -t https://example.com --external-harvest",
	"",
	"# KnownIssueScan phase: filter Nuclei templates by tags and severity",
	"vigolium scan -t https://example.com --known-issue-scan-tags cve,misconfig --known-issue-scan-severities critical,high",
	"# KnownIssueScan with custom templates directory",
	"vigolium scan -t https://example.com --known-issue-scan-templates-dir ~/my-templates",
	"",
	"# Source-aware scanning with local source code",
	"vigolium scan -t https://example.com --source /path/to/app --strategy whitebox",
	"# Source-aware scanning with git URL",
	"vigolium scan -t https://example.com --source-url https://github.com/org/repo",
	"# Ad-hoc SAST scan on a local path",
	"vigolium scan --sast-adhoc /path/to/app --only sast",
	"# Ad-hoc SAST scan with rule filter",
	"vigolium scan --sast-adhoc /path/to/app --only sast --rule gin",
	"",
	"# Load custom JavaScript extensions",
	"vigolium scan -t https://example.com --ext custom-check.js",
	"# Load all extensions from a directory",
	"vigolium scan -t https://example.com --ext-dir ./my-extensions",
	"# Run only extensions (skip built-in modules)",
	"vigolium scan -t https://example.com --only extension --ext custom-check.js",
	"",
	"# Output as JSONL",
	"vigolium scan -t https://example.com -j",
	"# Generate HTML report",
	"vigolium scan -t https://example.com --format html -o report.html",
	"# Write findings to file",
	"vigolium scan -t https://example.com -o findings.jsonl",
	"# Stateless scan with JSONL and HTML output",
	"vigolium scan --stateless -t https://example.com --format jsonl,html -o scan-output",
	"",
	"# Scope all operations to a project",
	"vigolium scan -t https://example.com --project-name my-project",
	"# Use OAST callback URL for out-of-band detection",
	"vigolium scan -t https://example.com --oast-url https://interact.sh/abc123",
)

var serverExamples = FormatExamples(
	"# Start server (uses auto-generated API key from config)",
	"vigolium server",
	"# Start server without authentication (local use only)",
	"vigolium server -A",
	"# Start on a custom port",
	"vigolium server --service-port 8080",
	"# Enable the transparent HTTP ingestion proxy",
	"vigolium server --ingest-proxy-port 9003",
	"# Auto-scan ingested traffic as it arrives",
	"vigolium server --scan-on-receive",
	"# Run specific modules when scanning",
	"vigolium server --scan-on-receive -m xss-reflected,sqli-error",
	"# Bind to localhost only",
	"vigolium server --host 127.0.0.1",
	"# Add a secondary ingest key",
	"vigolium server --alternative-ingest-key my-secondary-key",
)

var ingestExamples = FormatExamples(
	"# Set API key for remote server",
	"export VIGOLIUM_API_KEY=my-key",
	"# Submit URLs from stdin",
	"cat urls.txt | vigolium ingest -s http://localhost:8080",
	"# Submit URLs from file",
	"vigolium ingest -s http://localhost:8080 -i targets.txt",
	"# Submit OpenAPI spec",
	"vigolium ingest -s http://localhost:8080 -i api.yaml -I openapi -t https://api.example.com",
	"# Local ingestion (stores directly to database)",
	"cat urls.txt | vigolium ingest",
)

var moduleExamples = FormatExamples(
	"# List all available modules",
	"vigolium module ls",
	"# Search modules by keyword",
	"vigolium module ls xss",
	"# List only active (fuzzing) modules",
	"vigolium module ls --type active",
	"# Show only enabled modules",
	"vigolium module ls --list-enabled",
	"# Enable modules matching a keyword",
	"vigolium module enable sqli",
	"# Disable a specific module by exact ID",
	"vigolium module disable sqli-error-based --id",
)

var moduleLsExamples = FormatExamples(
	"# List all modules",
	"vigolium module ls",
	"# List active modules only",
	"vigolium module ls --type active",
	"# List passive modules only",
	"vigolium module ls --type passive",
	"# Show only enabled modules",
	"vigolium module ls --list-enabled",
)

var moduleEnableExamples = FormatExamples(
	"# Enable all modules matching 'xss'",
	"vigolium module enable xss",
	"# Enable a specific module by exact ID",
	"vigolium module enable sqli-error-based --id",
)

var moduleDisableExamples = FormatExamples(
	"# Disable all modules matching 'xss'",
	"vigolium module disable xss",
	"# Disable a specific module by exact ID",
	"vigolium module disable sqli-error-based --id",
)

var configExamples = FormatExamples(
	"# View all current settings",
	"vigolium config ls",
	"# Filter settings by section",
	"vigolium config ls server",
	"vigolium config ls database",
	"# Set a configuration value",
	"vigolium config set notify.enabled true",
	"vigolium config set database.driver postgres",
	"vigolium config set server.service_port 8080",
	"# Reset everything to defaults",
	"vigolium config clean",
)

var configLsExamples = FormatExamples(
	"# Show all settings",
	"vigolium config ls",
	"# Use 'view' alias",
	"vigolium config view",
	"# Filter by section",
	"vigolium config ls notify",
	"vigolium config ls database.sqlite",
)

var configSetExamples = FormatExamples(
	"# Enable notifications",
	"vigolium config set notify.enabled true",
	"# Change database driver",
	"vigolium config set database.driver postgres",
	"# Set notification severities",
	"vigolium config set notify.severities high,critical",
)

var configCleanExamples = FormatExamples(
	"# Reset Vigolium to clean state (with confirmation)",
	"vigolium config clean",
	"# Skip confirmation prompt",
	"vigolium config clean -F",
)

var dbListExamples = FormatExamples(
	"# List recent records",
	"vigolium db list",
	"# Filter by host",
	"vigolium db list --host example.com",
	"# Filter by method and status",
	"vigolium db list --method GET,POST --status 200,302",
	"# Tree view",
	"vigolium db list --tree",
	"# Show raw HTTP request/response",
	"vigolium db list --raw --host example.com -n 5",
	"# Search across URLs and headers",
	`vigolium db list --search "admin" --from 2025-01-01`,
	"# Filter by scan session",
	"vigolium db list --scan-id my-scan",
	"# List all database tables",
	"vigolium db list --list-tables",
	"# Show columns for a table",
	"vigolium db list findings --list-columns",
	"# List findings table",
	"vigolium db list findings",
	"# List any table by name",
	"vigolium db list scopes -n 10",
)

var dbStatsExamples = FormatExamples(
	"# Show database statistics",
	"vigolium db stats",
	"# Detailed stats with top hosts",
	"vigolium db stats --detailed",
	"# Stats for a specific scan",
	"vigolium db stats --scan-id my-scan",
)

var dbExportExamples = FormatExamples(
	"# Export findings as JSONL (default)",
	"vigolium db export",
	"# Export as CSV to file",
	"vigolium db export -f csv -o findings.csv",
	"# Export specific host as JSON",
	"vigolium db export -f json --host example.com",
	"# Export raw HTTP traffic",
	"vigolium db export -f raw --host example.com -o traffic.txt",
)

var dbCleanExamples = FormatExamples(
	"# Preview what would be deleted (dry run)",
	"vigolium db clean --host example.com --dry-run",
	"# Delete records older than a date",
	"vigolium db clean --before 2025-01-01",
	"# Delete records for a specific scan",
	"vigolium db clean --scan-id old-scan -F",
	"# Delete all records and reclaim space",
	"vigolium db clean --all -F --vacuum",
	"# Clean orphaned findings",
	"vigolium db clean --orphans -F",
)

var trafficExamples = FormatExamples(
	"# Browse recent traffic",
	"vigolium traffic",
	"# Fuzzy search across URLs, hosts, methods",
	"vigolium traffic admin",
	`vigolium traffic "api/v2"`,
	"# Tree view",
	"vigolium traffic tree",
	"vigolium traffic --tree",
	"# Filter by status and method",
	"vigolium traffic --status 200,302 --method GET",
	"# Select specific columns",
	"vigolium traffic --columns uuid,method,path,status,size",
	"# Exclude columns from default set",
	"vigolium traffic --exclude-columns scan_id,time",
	"# Show raw request/response",
	"vigolium traffic --raw --host example.com -n 5",
	"# JSON output",
	"vigolium traffic -j",
)

var trafficReplayExamples = FormatExamples(
	"# Replay requests matching a search term",
	"vigolium traffic replay admin",
	"# Replay filtered by host",
	"vigolium traffic replay --host example.com --limit 5",
	"# Replay and replace stored responses",
	"vigolium traffic replay --host example.com --in-replace",
	"# Replay through a proxy",
	"vigolium traffic replay admin --proxy http://127.0.0.1:8080",
)

var scopeViewExamples = FormatExamples(
	"# Show all scope rules",
	"vigolium scope view",
	"# Filter by component",
	"vigolium scope view host",
	"vigolium scope view status_code",
)

var runExamples = FormatExamples(
	"# Run content discovery phase",
	"vigolium run discover -t https://example.com",
	"# Run browser-based spidering",
	"vigolium run spidering -t https://example.com",
	"# Run known-issue-scan phase",
	"vigolium run known-issue-scan -t https://example.com",
	"# Run known-issue-scan with custom Nuclei template tags",
	"vigolium run known-issue-scan -t https://example.com --known-issue-scan-tags cve,misconfig --known-issue-scan-severities critical,high",
	"# Run audit with specific modules",
	"vigolium run audit -t https://example.com -m xss-reflected",
	"# Run audit with module tag filter",
	"vigolium run audit -t https://example.com --module-tag spring",
	"# Run external intelligence harvesting",
	"vigolium run external-harvest -t https://example.com",
	"# Run ad-hoc SAST on a local path",
	"vigolium run sast --sast-adhoc /path/to/app",
	"# Run SAST with rule filter",
	"vigolium run sast --sast-adhoc /path/to/app --rule route",
	"# Run only JavaScript extensions",
	"vigolium run extension -t https://example.com --ext custom-check.js",
	"",
	"# Use a scanning profile for the phase",
	"vigolium run discover -t https://example.com --scanning-profile full",
	"# Override scan duration",
	"vigolium run discover -t https://example.com --scanning-max-duration 2h",
	"# Run with custom headers",
	`vigolium run audit -t https://example.com -H "Authorization: Bearer token"`,
	"# Scope to a specific project",
	"vigolium run known-issue-scan -t https://example.com --project-name my-project",
	"",
	"# Short alias",
	"vigolium r discovery -t https://example.com",
	"# Phase aliases: deparos=discovery, discover=discovery, spitolas=spidering, audit=audit, ext=extension",
	"vigolium run deparos -t https://example.com",
	"vigolium run audit -t https://example.com",
)

var agentExamples = FormatExamples(
	"# List configured agent backends",
	"vigolium agent --list-agents",
	"# List available prompt templates",
	"vigolium agent --list-templates",
	"# Security code review of a repo (dry run)",
	"vigolium agent query --source ./myapp --prompt-template security-code-review --dry-run",
	"# Run code review with specific files",
	"vigolium agent query --source ./myapp --files main.go,handler.go --prompt-template security-code-review",
	"# Use a custom prompt file",
	"vigolium agent query --source ./myapp --prompt-file custom-review.md",
	"# Use a different agent backend",
	"vigolium agent query --source ./myapp --prompt-template security-code-review --agent gemini",
)

var agentRunExamples = FormatExamples(
	"# Send a prompt to the agent",
	`vigolium agent query --prompt "Analyze this code for SQL injection: SELECT * FROM users WHERE id = $input"`,
	"# Pipe prompt from stdin",
	`echo "Find XSS vulnerabilities in this JavaScript" | vigolium agent query --stdin`,
	"# Use a specific agent",
	`vigolium agent query --prompt "hello" --agent claude`,
	"# Save output to file",
	`vigolium agent query --prompt "Review this code" --output review.json`,
)

var exportExamples = FormatExamples(
	"# Export all data (HTTP records, findings, scans, modules, etc.)",
	"vigolium export --format jsonl -o full-export.jsonl",
	"# Export only findings",
	"vigolium export --format jsonl --only findings",
	"# Export only HTTP records",
	"vigolium export --format jsonl --only http",
	"# Export findings and HTTP records",
	"vigolium export --format jsonl --only findings,http",
	"# Export HTTP records as HTML report",
	"vigolium export --format html -o report.html",
)

var scopeSetExamples = FormatExamples(
	"# Exclude internal hosts",
	`vigolium scope set host.exclude "*.internal.com,admin.*"`,
	"# Only scan API paths",
	`vigolium scope set path.include "/api/*,/v2/*"`,
	"# Exclude static file responses",
	`vigolium scope set response_content_type.exclude "image/*,font/*"`,
	"# Exclude error status codes from scanning",
	`vigolium scope set status_code.exclude "404,500,502,503"`,
)

// --- Colored usage template ---

var coloredUsageTemplate = `{{ styleHeading "Usage:" }}{{if .Runnable}}
  {{ .UseLine | styleCyan }}{{end}}{{if .HasAvailableSubCommands}}
  {{ .CommandPath | styleCyan }} [command]{{end}}{{if gt (len .Aliases) 0}}

{{ styleHeading "Aliases:" }}
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

{{ styleHeading "Examples:" }}
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

{{ styleHeading "Available Commands:" }}{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

{{ styleHeading "Additional Commands:" }}{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{.LocalFlags | localFlagUsages}}{{end}}{{if .HasAvailableInheritedFlags}}

{{.InheritedFlags | groupedFlagUsages}}{{end}}{{if .HasHelpSubCommands}}

{{ styleHeading "Additional help topics:" }}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

{{ "Use" | styleGray }} "{{.CommandPath | styleCyan}} [command] --help" {{ "for more information about a command." | styleGray }}{{end}}

{{ "Website: https://www.vigolium.com | Docs: https://docs.vigolium.com" | styleGray }}
`
