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
	agentArchonCmd.Example = agentArchonExamples
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
	"# Use a scanning strategy preset (lite, balanced, deep)",
	"vigolium scan -t https://example.com --strategy deep",
	"# Use native scan intensity presets (quick, balanced, deep)",
	"vigolium scan -t https://example.com --intensity quick",
	"vigolium scan -t https://example.com --intensity balanced",
	"vigolium scan -t https://example.com --intensity deep",
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
	"vigolium scan -t https://example.com --only dynamic-assessment",
	"# Skip specific phases",
	"vigolium scan -t https://example.com --skip discovery,spidering",
	"",
	"# Run content discovery before scanning",
	"vigolium scan -t https://example.com --discover",
	"# Discovery with custom fuzz wordlist",
	"vigolium scan -t https://example.com --discover --fuzz-wordlist ~/.vigolium/wordlists/fuzz.txt",
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
	"# Bind to localhost only",
	"vigolium server --host 127.0.0.1",
	"",
	"# Enable the transparent HTTP ingestion proxy",
	"vigolium server --ingest-proxy-port 9003",
	"# Add a secondary ingest key",
	"vigolium server --alternative-ingest-key my-secondary-key",
	"",
	"# Auto-scan ingested traffic as it arrives",
	"vigolium server --scan-on-receive",
	"# Scan on receive with specific modules and concurrency",
	"vigolium server --scan-on-receive -m xss-reflected,sqli-error -c 50",
	"# Scan on receive with more catchup workers",
	"vigolium server --scan-on-receive --catchup-threads 8",
	"# Scan on receive without background catchup scan",
	"vigolium server --scan-on-receive --disable-catchup",
	"",
	"# Write findings to a file",
	"vigolium server --scan-on-receive -o findings.jsonl",
	"# Increase in-memory queue capacity",
	"vigolium server --mem-buffer 50000",
	"",
	"# Read-only mode (no scanning, ingestion, or agent endpoints)",
	"vigolium server --view-only",
	"# Disable agent endpoints and warm session pooling",
	"vigolium server --no-agent",
	"# Disable only warm session pooling",
	"vigolium server --disable-warm-session",
	"# Disable Swagger UI",
	"vigolium server --no-swagger",
	"",
	"# Production-like setup: localhost, proxy, scan on receive, custom port",
	"vigolium server --host 127.0.0.1 --service-port 8080 --ingest-proxy-port 8081 --scan-on-receive",
)

var ingestExamples = FormatExamples(
	"# --- URL inputs ---",
	"# URL list via stdin (line-by-line, streamed)",
	"cat urls.txt | vigolium ingest",
	"# URL list via -i file",
	"vigolium ingest -i targets.txt",
	"# Single URL via -t",
	"vigolium ingest -t https://example.com/api/v1",
	"",
	"# --- Raw HTTP request (auto-detected; response is fetched live) ---",
	"# Stdin",
	"cat request.txt | vigolium ingest",
	"# File",
	"vigolium ingest -i request.txt",
	"# Skip the live refetch entirely — store the request as-is",
	"cat request.txt | vigolium ingest --disable-fetch-response",
	"",
	"# --- Burp request+response pair (auto-detected by '***' separator) ---",
	"# Stdin: response is preserved as-is, no refetch",
	"cat burp-pair.txt | vigolium ingest",
	"# File",
	"vigolium ingest -i burp-pair.txt",
	"# Pin the format explicitly to skip auto-detect",
	"vigolium ingest -i capture.txt -I burpraw",
	"",
	"# --- curl command (auto-detected) ---",
	"# Piped from a file (a leading '$ ' prompt is stripped)",
	"cat command.sh | vigolium ingest",
	"# Inline",
	"echo \"curl -X POST https://api.example.com/login -d 'u=a'\" | vigolium ingest",
	"",
	"# --- Spec & structured formats ---",
	"# OpenAPI (uses spec server URLs)",
	"vigolium ingest -i openapi.yaml --spec-url",
	"# OpenAPI with custom base URL and headers",
	"vigolium ingest -i api.yaml -I openapi -t https://api.example.com --spec-header 'Authorization: Bearer xxx'",
	"# HAR / Burp XML / Postman / Nuclei output",
	"vigolium ingest -i traffic.har",
	"vigolium ingest -i burp-state.xml -I burpxml",
	"",
	"# --- Pipelines ---",
	"# Ingest then scan the new records (-S = scan-on-receive)",
	"cat burp-pair.txt | vigolium ingest -S -m xss,sqli",
	"# JSON summary for scripting",
	"cat burp-pair.txt | vigolium ingest --json",
	"",
	"# --- Remote ingestion (push to a running vigolium server) ---",
	"export VIGOLIUM_API_KEY=my-key",
	"cat urls.txt | vigolium ingest -s https://vigolium.example.com",
	"vigolium ingest -s https://vigolium.example.com -i api.yaml -I openapi -t https://api.example.com",
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
	"# Show all settings (sensitive values are redacted)",
	"vigolium config ls",
	"# Use 'view' alias",
	"vigolium config view",
	"# Filter by section",
	"vigolium config ls notify",
	"vigolium config ls database.sqlite",
	"# Reveal redacted secrets (API keys, tokens, passwords)",
	"vigolium config ls --force",
	"vigolium config ls notify -F",
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
	"vigolium db list --scan-uuid my-scan",
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
	"vigolium db stats --scan-uuid my-scan",
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
	"vigolium db clean --scan-uuid old-scan -F",
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
	"# Discovery with custom fuzz wordlist",
	"vigolium run discover -t https://example.com --fuzz-wordlist ~/.vigolium/wordlists/fuzz.txt",
	"# Run browser-based spidering",
	"vigolium run spidering -t https://example.com",
	"# Run known-issue-scan phase",
	"vigolium run known-issue-scan -t https://example.com",
	"# Run known-issue-scan with custom Nuclei template tags",
	"vigolium run known-issue-scan -t https://example.com --known-issue-scan-tags cve,misconfig --known-issue-scan-severities critical,high",
	"# Run dynamic-assessment with specific modules",
	"vigolium run dynamic-assessment -t https://example.com -m xss-reflected",
	"# Run dynamic-assessment with module tag filter",
	"vigolium run dynamic-assessment -t https://example.com --module-tag spring",
	"# Run external intelligence harvesting",
	"vigolium run external-harvest -t https://example.com",
	"# Run only JavaScript extensions",
	"vigolium run extension -t https://example.com --ext custom-check.js",
	"",
	"# Use a scanning profile for the phase",
	"vigolium run discover -t https://example.com --scanning-profile full",
	"# Use native scan intensity for the phase",
	"vigolium run dynamic-assessment -t https://example.com --intensity deep",
	"# Override scan duration",
	"vigolium run discover -t https://example.com --scanning-max-duration 2h",
	"# Run with custom headers",
	`vigolium run dynamic-assessment -t https://example.com -H "Authorization: Bearer token"`,
	"# Scope to a specific project",
	"vigolium run known-issue-scan -t https://example.com --project-name my-project",
	"",
	"# Short alias",
	"vigolium r discovery -t https://example.com",
	"# Phase aliases: deparos=discovery, discover=discovery, spitolas=spidering, audit/dast/assessment=dynamic-assessment, ext=extension",
	"vigolium run deparos -t https://example.com",
	"vigolium run dast -t https://example.com",
)

var agentExamples = FormatExamples(
	"# List configured agent backends",
	"vigolium agent --list-agents",
	"# List available prompt templates",
	"vigolium agent --list-templates",
	"# Olium — direct interactive (TUI) access to the in-process agent",
	"vigolium agent olium",
	`vigolium agent olium -p "list the routes in pkg/server"`,
	"# Autopilot — agentic scan, autonomous end-to-end",
	"vigolium agent autopilot -t https://example.com/api",
	"vigolium agent autopilot -t https://example.com --source ./src",
	`vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"`,
	"# Swarm — AI-guided scanning with module selection and triage",
	`vigolium agent swarm --input "https://example.com/api/users?id=1"`,
	"vigolium agent swarm -t https://example.com --source ./src --discover",
	"# Audit — unified driver: archon then piolium under one AgenticScan",
	"vigolium agent audit --source .",
	"vigolium agent audit --driver piolium --source ./backend --mode lite",
	"# Archon — foreground source-code security audit (single driver)",
	"vigolium agent archon --mode deep --source .",
	"vigolium agent archon --mode lite --source https://github.com/org/repo",
	"# Piolium — Pi-native foreground security audit (single driver)",
	"vigolium agent piolium --mode balanced --source .",
	"# Query — single-shot prompt (code review, secret detection, etc.)",
	"vigolium agent query --source ./myapp --prompt-template security-code-review",
)

var agenticScanExamples = FormatExamples(
	"# Send a prompt to the agent",
	`vigolium agent query --prompt "Analyze this code for SQL injection: SELECT * FROM users WHERE id = $input"`,
	"# Pipe prompt from stdin",
	`echo "Find XSS vulnerabilities in this JavaScript" | vigolium agent query --stdin`,
	"# Tag the AgenticScan DB row with a custom label",
	`vigolium agent query --prompt "hello" --agent-label code-review`,
	"# Save output to file",
	`vigolium agent query --prompt "Review this code" --output review.json`,
)

var exportExamples = FormatExamples(
	"# Export all data (HTTP records, findings, scans, modules, etc.)",
	"vigolium export --format jsonl -o full-export.jsonl",
	"# Export findings and HTTP records",
	"vigolium export --format jsonl --only findings,http",
	"# Export HTTP records as HTML report",
	"vigolium export --format html -o report.html",
	"# Export a bundle archive (.tar.gz with export.jsonl, report.html, manifest.json)",
	"vigolium export --format bundle -o results.tar.gz",
	"# Bundle and include a specific agentic scan's session directory",
	"vigolium export --format bundle --scan-uuid <scan-uuid> -o results.tar.gz",
	"# Bundle multiple agentic scan sessions into one archive",
	"vigolium export --format bundle --scan-uuid <uuid-1> --scan-uuid <uuid-2> -o bundle.tar.gz",
	"# Bundle and upload directly to cloud storage with {ts} placeholder",
	"vigolium export --format bundle --scan-uuid <scan-uuid> -o gs://<project-uuid>/bundles/run-{ts}.tar.gz",
	"# Scope export to a specific project (overrides active project / $VIGOLIUM_PROJECT_UUID)",
	"vigolium export --project-uuid <project-uuid> --format jsonl -o project-export.jsonl",
	"# Bundle a specific project's data alongside its agent session",
	"vigolium export --project-uuid <project-uuid> --format bundle --scan-uuid <scan-uuid> -o project-bundle.tar.gz",
	"# Export findings only for a specific project as HTML",
	"vigolium export --project-uuid <project-uuid> --format html --only findings -o findings.html",
	"# Export directly to cloud storage (gs:// URL)",
	"vigolium export --format jsonl -o gs://<project-uuid>/exports/full.jsonl",
	"# Use {ts} for an automatic UTC timestamp (e.g. 2026-04-26T14-05-30Z)",
	"vigolium export --format html -o gs://<project-uuid>/reports/scan-{ts}.html",
	"vigolium export --format jsonl -o gs://<project-uuid>/exports/data-{ts}.jsonl",
	"# {project-uuid} expands to the active project; combine with {ts}",
	"vigolium export --format html -o gs://{project-uuid}/reports/scan-{ts}.html",
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

var dbExamples = FormatExamples(
	"# Show database statistics",
	"vigolium db stats",
	"# List recent HTTP records",
	"vigolium db list",
	"# List findings",
	"vigolium db list findings",
	"# Export findings as JSONL",
	"vigolium db export -f jsonl -o findings.jsonl",
	"# Preview a clean by host (dry-run)",
	"vigolium db clean --host example.com --dry-run",
	"# Seed sample data for development",
	"vigolium db seed",
)

var dbSeedExamples = FormatExamples(
	"# Insert sample hosts, scans, records, and findings",
	"vigolium db seed",
	"# Seed against a specific SQLite file",
	"vigolium db seed --db /tmp/playground.sqlite",
)

var scopeExamples = FormatExamples(
	"# View all scope rules (default action)",
	"vigolium scope",
	"# View only a specific component",
	"vigolium scope view host",
	"# Set a rule via the set subcommand",
	`vigolium scope set host.exclude "*.internal.com"`,
)

var agentSessionExamples = FormatExamples(
	"# List recent agent run sessions",
	"vigolium agent session",
	"# List only autopilot runs, max 20",
	"vigolium agent session --mode autopilot -n 20",
	"# Show details of a specific session",
	"vigolium agent session 9b2f...",
	"# Show full raw output instead of the tail",
	"vigolium agent session 9b2f... --full",
)

var doctorExamples = FormatExamples(
	"# Run all readiness checks",
	"vigolium doctor",
	"# Verbose mode with full diagnostics",
	"vigolium doctor -v",
)

var extensionsParentExamples = FormatExamples(
	"# List loaded extensions",
	"vigolium extensions",
	"# Filter by substring",
	"vigolium extensions xss",
	"# Show extension API reference",
	"vigolium extensions docs",
	"# Install starter presets into ~/.vigolium/extensions/",
	"vigolium extensions preset",
	"# Lint an extension file",
	"vigolium extensions lint ./my-check.js",
)

var extensionsLsExamples = FormatExamples(
	"# List every extension",
	"vigolium extensions ls",
	"# Filter by id/name/description",
	"vigolium extensions ls auth",
	"# Active extensions only",
	"vigolium extensions ls --type active",
	"# Verbose: include long description and confirmation criteria",
	"vigolium extensions ls -v",
)

var extensionsDocsExamples = FormatExamples(
	"# List every namespace and function",
	"vigolium extensions docs",
	"# Drill into a specific function",
	"vigolium extensions docs http.request",
	"# Include full usage examples",
	"vigolium extensions docs --example",
)

var extensionsPresetExamples = FormatExamples(
	"# Install all starter presets",
	"vigolium extensions preset",
	"# Install only a single named preset",
	"vigolium extensions preset jwt-none",
)

var findingExamples = FormatExamples(
	"# Browse all findings interactively",
	"vigolium finding",
	"# Fuzzy search by term",
	"vigolium finding xss",
	"# Filter by host and severity",
	"vigolium finding --host example.com --severity high,critical",
	"# Show raw request/response for matched findings",
	"vigolium finding --raw -n 5",
	"# JSONL output",
	"vigolium finding -j",
)

var findingLoadExamples = FormatExamples(
	"# Import findings from a JSONL file",
	"vigolium finding load findings.jsonl",
	"# Pipe agent output (markdown-wrapped JSON) from stdin",
	"vigolium agent query --prompt-template review | vigolium finding load",
	"# Import a single JSON object",
	"vigolium finding load report.json",
)

var logExamples = FormatExamples(
	"# List recent scan and agent sessions",
	"vigolium log",
	"# Stream logs for a specific session UUID",
	"vigolium log 9b2f...",
	"# Open the interactive picker",
	"vigolium log --tui",
)

var logLsExamples = FormatExamples(
	"# List every available session log",
	"vigolium log ls",
)

var projectCreateExamples = FormatExamples(
	"# Create a project",
	`vigolium project create my-app --description "Main web app"`,
	"# Create with access control in one line",
	"vigolium project create my-app --allow @acme.com --allow alice@partner.io",
)

var projectListExamples = FormatExamples(
	"# List all projects (interactive picker if a TTY)",
	"vigolium project ls",
	"# Machine-readable output",
	"vigolium project ls --json",
)

var projectUseExamples = FormatExamples(
	"# Set the active project for the current shell",
	"eval $(vigolium project use 9b2f-...)",
)

var projectConfigExamples = FormatExamples(
	"# Show the active project's config file path",
	"vigolium project config",
	"# Show config path for a specific project",
	"vigolium project config 9b2f-...",
)

var sessionExamples = FormatExamples(
	"# List session auth configs",
	"vigolium auth list",
	"# Load session configs from a YAML file",
	"vigolium auth load sessions.yaml",
	"# Lint a session config file",
	"vigolium auth lint sessions.yaml",
	"# Generate a TOTP code for 2FA flows",
	"vigolium auth totp --secret JBSWY3DPEHPK3PXP",
)

var sessionLsExamples = FormatExamples(
	"# List all session configs for the active project",
	"vigolium auth list",
	"# Filter by hostname",
	"vigolium auth list --host api.example.com",
	"# JSON output",
	"vigolium auth list -j",
)

var sessionTotpExamples = FormatExamples(
	"# Generate a code from a base32 secret",
	"vigolium auth totp --secret JBSWY3DPEHPK3PXP",
)

var strategyExamples = FormatExamples(
	"# List strategies and phases (default action)",
	"vigolium strategy",
	"# Same, via the explicit ls subcommand",
	"vigolium strategy ls",
	"# Use a strategy in a scan",
	"vigolium scan -t https://example.com --strategy deep",
	"# Set the default strategy in config",
	"vigolium config set scanning_strategy.default_strategy balanced",
)

var strategyLsExamples = FormatExamples(
	"# List every strategy and the phases it enables",
	"vigolium strategy ls",
)

var versionExamples = FormatExamples(
	"# Show version, build, and license info",
	"vigolium version",
	"# JSON output for tooling",
	"vigolium version -j",
)

var oliumExamples = FormatExamples(
	"# Empty interactive session",
	"vigolium agent olium",
	"# Seed the session with a first prompt, stay interactive",
	`vigolium agent olium "audit pkg/auth for hardcoded secrets"`,
	"# Pipe a prompt in, stay interactive",
	"cat task.txt | vigolium agent olium",
	"# One-shot, non-interactive",
	`vigolium agent olium -p "list the routes in pkg/server"`,
)

var agentAuditExamples = FormatExamples(
	"# Default: archon then piolium under one AgenticScan, balanced mode",
	"vigolium agent audit --source .",
	"",
	"# Just piolium (single driver — equivalent to `agent piolium`)",
	"vigolium agent audit --driver piolium --source ./backend --mode lite",
	"",
	"# Just archon (single driver — equivalent to `agent archon`)",
	"vigolium agent audit --driver archon --source ./backend --agent claude",
	"",
	"# Both drivers, deep mode, on a remote git URL with full commit history",
	"vigolium agent audit --source git@github.com:org/repo.git --intensity deep",
	"",
	"# Override pi's provider/model for the piolium leg (vertex-anthropic)",
	"vigolium agent audit --source ./backend \\",
	"  --pi-provider vertex-anthropic --pi-model claude-opus-4-6",
	"",
	"# Driver-specific mode requires --driver=piolium (or =archon for mock)",
	"vigolium agent audit --driver piolium --source ./mono-repo --mode longshot \\",
	"  --plm-longshot-langs python,go --plm-longshot-limit 200",
	"",
	"# Skip the post-pass project-wide findings dedup",
	"vigolium agent audit --source ./backend --no-dedup",
	"",
	"# Pull source from a cloud-storage archive",
	"vigolium agent audit --source gs://my-bucket/snapshots/repo.tar.gz",
	"",
	"# Interactive — drop into the coding agent with the archon harness",
	"# installed and drive the audit yourself (archon's -i)",
	"vigolium agent audit --source . --interactive",
	"# Afterward, import the on-disk archon results and write an HTML report in one step",
	"vigolium import ./archon --format html -o archon-report.html",
)

var agentPioliumExamples = FormatExamples(
	"# Quick balanced piolium audit on the current directory",
	"vigolium agent piolium --source .",
	"",
	"# Lite triage on a checked-out repo",
	"vigolium agent piolium --source ./backend --mode lite",
	"",
	"# Deep audit on a remote git URL with full commit history",
	"vigolium agent piolium --source git@github.com:org/repo.git --intensity deep",
	"",
	"# Override pi's provider/model for this run",
	"vigolium agent piolium --source ./backend \\",
	"  --pi-provider vertex-anthropic --pi-model claude-opus-4-6",
	"",
	"# Hail-mary longshot scoped to Python and Go, capped at 200 files",
	"vigolium agent piolium --source ./mono-repo --mode longshot \\",
	"  --plm-longshot-langs python,go --plm-longshot-limit 200",
	"",
	"# Skip the preflight check (e.g. running offline against a stub provider)",
	"vigolium agent piolium --source ./backend --no-preflight",
)

var agentArchonExamples = FormatExamples(
	"# Deep audit of the current directory",
	"vigolium agent archon --mode deep --source .",
	"# Lite audit by cloning a remote repo",
	"vigolium agent archon --mode lite --source https://github.com/org/repo",
	"# Balanced audit using the codex backend",
	"vigolium agent archon --mode balanced --agent codex --source ~/code/myapp",
	"# Deep audit using an intensity preset",
	"vigolium agent archon --source . --intensity deep",
	"# Re-visit an existing audit tree (Nth-pass)",
	"vigolium agent archon --mode revisit --source ./prior-audit-tree",
	"# Build PoCs for confirmed findings",
	"vigolium agent archon --mode confirm --source ./audit-with-findings",
)

var agentAutopilotExamples = FormatExamples(
	"# Natural language prompt — target, source, and focus auto-extracted",
	`vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"`,
	`vigolium agent autopilot "test auth bypass on https://app.example.com"`,
	"# Scan a target URL",
	"vigolium agent autopilot -t https://example.com/api",
	"# Scan with application source code (triggers archon-audit automatically)",
	"vigolium agent autopilot -t https://example.com --source ./src",
	"# Pipe a curl command or raw HTTP request via stdin",
	"curl -s https://example.com/api/users | vigolium agent autopilot",
	"cat request.txt | vigolium agent autopilot -t https://example.com",
	"# Pass a curl command or raw HTTP as input",
	`vigolium agent autopilot --input "curl -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' https://example.com/api/login"`,
	"# Focus on specific vulnerability types",
	`vigolium agent autopilot -t https://example.com --focus "auth bypass and IDOR"`,
	"# Deep scan with browser and extended limits",
	"vigolium agent autopilot -t https://example.com --intensity deep",
	"# Quick CI/PR scan with short timeout",
	"vigolium agent autopilot -t https://example.com --source ./src --intensity quick",
	"# Source-aware scan with specific files and custom instructions",
	`vigolium agent autopilot -t https://example.com --source ./src --files "routes/api.js,controllers/auth.js" --instruction "Focus on the new payment endpoint"`,
	"# Scan a PR diff for security regressions",
	`vigolium agent autopilot -t https://example.com --source ./src --diff "main...feature-branch"`,
	"vigolium agent autopilot -t https://example.com --source ./src --last-commits 3",
	"# Use a specific agent backend",
	"vigolium agent autopilot -t https://example.com --provider anthropic-api-key",
	"# Enable browser-based auth flow",
	`vigolium agent autopilot -t https://example.com --browser --credentials "admin/admin123"`,
	"# Preview the rendered prompt without executing",
	"vigolium agent autopilot -t https://example.com --source ./src --dry-run",
	"# Disable archon-audit when using --source",
	"vigolium agent autopilot -t https://example.com --source ./src --archon=off",
)

var agentSwarmExamples = FormatExamples(
	"# Swarm a single URL",
	`vigolium agent swarm --input "https://example.com/api/users?id=1"`,
	"# Swarm a curl command",
	`vigolium agent swarm --input "curl -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' https://example.com/api/login"`,
	"# Pipe a raw HTTP request from stdin",
	"cat request.txt | vigolium agent swarm",
	"# Swarm with source code for route discovery",
	"vigolium agent swarm -t https://example.com --source ./src",
	"# Source-aware swarm with specific files",
	`vigolium agent swarm -t https://example.com --source ./src --files "routes/api.js,controllers/auth.js"`,
	"# Only run source analysis (no scanning)",
	"vigolium agent swarm -t https://example.com --source ./src --source-analysis-only",
	"# Focus on a specific vulnerability type",
	`vigolium agent swarm --input "https://example.com/search?q=test" --vuln-type sqli`,
	"# Use specific scanner modules",
	`vigolium agent swarm --input "https://example.com/api" -m sqli -m xss -m ssti`,
	"# Run discovery+spidering before planning",
	"vigolium agent swarm -t https://example.com --discover",
	"# Tag the AgenticScan DB row with a custom label",
	`vigolium agent swarm --input "https://example.com" --agent-label api-pentest`,
	"# Swarm a database record",
	"vigolium agent swarm --record-uuid abc123-def456",
	"# Add custom instructions to guide the agent",
	`vigolium agent swarm --input "https://example.com" --instruction "Focus on auth bypass and IDOR"`,
	"# Load instructions from a file",
	`vigolium agent swarm --input "https://example.com" --instruction-file ./pentest-notes.md`,
	"# Skip specific scan phases",
	"vigolium agent swarm -t https://example.com --source ./src --skip discovery,spidering",
	"# Limit triage-rescan iterations",
	`vigolium agent swarm --input "https://example.com" --max-iterations 1`,
	"# Dry run — render prompts without executing",
	"vigolium agent swarm -t https://example.com --source ./src --dry-run",
	"# Show rendered prompts on stderr while executing",
	`vigolium agent swarm --input "https://example.com" --show-prompt`,
	"# Quick intensity — fast scan for CI/CD pipelines",
	`vigolium agent swarm --input "https://example.com/api/users?id=1" --intensity quick`,
	"# Deep intensity — full discovery, triage, browser, extended duration",
	"vigolium agent swarm -t https://example.com --source ./src --intensity deep",
	"# Override a specific setting within an intensity preset",
	"vigolium agent swarm -t https://example.com --intensity deep --triage=false",
)

var scanURLExamples = FormatExamples(
	"# Scan a URL directly",
	"vigolium scan-url https://example.com/api/users?id=1",
	"# Scan with a specific HTTP method and body",
	`vigolium scan-url --method POST --body '{"user":"admin"}' -H 'Content-Type: application/json' https://example.com/api/login`,
	"# Scan with custom headers",
	`vigolium scan-url -H 'Authorization: Bearer tok123' -H 'X-Custom: value' https://example.com/api/data`,
	"# Pipe a URL from stdin",
	"echo 'https://example.com/search?q=test' | vigolium scan-url",
	"# Pipe a curl command from stdin",
	`echo "curl -X POST -d 'user=admin' https://example.com/login" | vigolium scan-url`,
	"# Pipe a raw HTTP request from stdin",
	`printf 'GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n' | vigolium scan-url`,
	"# Run only specific modules",
	"vigolium scan-url -m sqli -m xss https://example.com/search?q=test",
	"# Skip passive analysis",
	"vigolium scan-url --no-passive https://example.com/api/users",
	"# Enable content discovery before scanning",
	"vigolium scan-url --discover https://example.com/",
	"# JSON output for scripting",
	"vigolium scan-url --json https://example.com/api/users?id=1",
)

var scanRequestExamples = FormatExamples(
	"# Read a raw HTTP request from a file",
	"vigolium scan-request -i request.txt",
	"# Pipe a raw HTTP request from stdin",
	`printf 'POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=secret' | vigolium scan-request`,
	"# Pipe a curl command from stdin (auto-detected)",
	`echo "curl -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' https://example.com/api/login" | vigolium scan-request`,
	"# Override the target host (useful for raw requests without full URL)",
	"vigolium scan-request -i request.txt --target https://staging.example.com",
	"# Scan with specific modules only",
	`printf 'GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n' | vigolium scan-request -m sqli -m xss`,
	"# Skip passive modules",
	"vigolium scan-request -i request.txt --no-passive",
	"# Read from a Burp Suite saved request file",
	"vigolium scan-request -i burp-request.txt --target https://example.com",
	"# JSON output for scripting",
	"cat request.txt | vigolium scan-request --json",
)

var jsExamples = FormatExamples(
	"# From stdin (default — ideal for agent mode)",
	`echo 'vigolium.http.get("https://example.com")' | vigolium js`,
	"# Inline code",
	`vigolium js --code 'vigolium.http.get("https://example.com/api/users")'`,
	"# From a file",
	"vigolium js --code-file script.js",
	"# With target context",
	`vigolium js --target https://example.com --code 'vigolium.http.get(TARGET + "/api")'`,
	"# With timeout",
	"vigolium js --timeout 60s --code-file long_running.js",
)

var storageExamples = FormatExamples(
	"# List objects in cloud storage for the active project",
	"vigolium storage ls",
	"# Upload a local file (default key: ugc/<basename>)",
	"vigolium storage upload ./scan-bundle.tar.gz",
	"# Download an object",
	"vigolium storage download ugc/scan-bundle.tar.gz -o ./local.tar.gz",
	"# Download a scan result bundle by scan UUID",
	"vigolium storage results <scan-uuid>",
	"# Generate a presigned download URL valid for 30 minutes",
	"vigolium storage presign --key ugc/scan-bundle.tar.gz --expiry 30m",
	"# Delete one or more objects (skip prompt with -F)",
	"vigolium storage rm imports/old-bundle.tar.gz -F",
)

var storageLsExamples = FormatExamples(
	"# List every object stored for the active project",
	"vigolium storage ls",
	"# Limit to a sub-prefix (e.g. ugc/, native-scans/, agentic-scans/)",
	"vigolium storage ls --prefix ugc/",
	"# Render keys as a directory tree",
	"vigolium storage ls --tree",
	"# Machine-readable output",
	"vigolium storage ls --json",
)

var storageUploadExamples = FormatExamples(
	"# Upload a local file (stored at ugc/<basename>)",
	"vigolium storage upload ./scan-bundle.tar.gz",
	"# Upload with an explicit storage key",
	"vigolium storage upload ./report.html --key reports/quarterly.html",
	"# Upload with a Content-Type header set on the object",
	"vigolium storage upload ./data.json --content-type application/json",
)

var storageDownloadExamples = FormatExamples(
	"# Stream an object to stdout",
	"vigolium storage download ugc/scan-bundle.tar.gz > local.tar.gz",
	"# Write directly to a file",
	"vigolium storage download reports/quarterly.html -o ./quarterly.html",
)

var storageResultsExamples = FormatExamples(
	"# Download the result bundle for a scan UUID",
	"vigolium storage results 9c1f5e0d-...",
	"# Save to a custom path",
	"vigolium storage results 9c1f5e0d-... -o ./results.tar.gz",
)

var storagePresignExamples = FormatExamples(
	"# Generate a download URL (default: GET, 1h validity)",
	"vigolium storage presign --key ugc/scan-bundle.tar.gz",
	"# Generate an upload URL valid for 15 minutes",
	"vigolium storage presign --key ugc/incoming.bin --method PUT --expiry 15m",
	"# JSON output for scripting",
	"vigolium storage presign --key reports/quarterly.html --json",
)

var storageRmExamples = FormatExamples(
	"# Delete a single object (will prompt for confirmation)",
	"vigolium storage rm imports/old-bundle.tar.gz",
	"# Delete several objects, skipping the confirmation prompt",
	"vigolium storage rm imports/a.tar.gz imports/b.tar.gz -F",
)

var importExamples = FormatExamples(
	"# Import a folder produced by archon-audit",
	"vigolium import /path/to/archon-output-harbor/",
	"# Import a folder and also archive it to cloud storage afterwards",
	"vigolium import /path/to/archon-output-harbor/ --upload",
	"# Import a folder and upload to a custom storage key",
	"vigolium import /path/to/archon-output-harbor/ --upload-key imports/harbor.tar.gz",
	"# Import a JSONL file produced by 'vigolium export'",
	"vigolium import /tmp/demo/juice-shop.jsonl",
	"# Import a generic JSONL scan-results file",
	"vigolium import scan-results.jsonl",
	"# Import a compressed archive (.tar.gz, .tgz, or .zip)",
	"vigolium import scan-bundle.tar.gz",
	"vigolium import findings.zip",
	"# Import directly from cloud storage",
	"vigolium import gs://<project-uuid>/imports/harbor.tar.gz",
)

var initExamples = FormatExamples(
	"# First-time setup",
	"vigolium init",
	"# Reinitialize: regenerate config (with new API key) and re-extract presets",
	"vigolium init --force",
)

var extensionsEvalExamples = FormatExamples(
	"# Inline code",
	`vigolium ext eval 'vigolium.log.info("hello")'`,
	"# From a file",
	"vigolium ext eval --ext-file script.js",
	"# From stdin",
	`echo 'vigolium.utils.md5("hello")' | vigolium ext eval --stdin`,
)

var extensionsLintExamples = FormatExamples(
	"# Lint a single JS file",
	"vigolium extensions lint my-extension.js",
	"# Lint a YAML extension",
	"vigolium extensions lint auth-hook.vgm.yaml",
	"# Lint all extensions in a directory",
	"vigolium extensions lint ~/.vigolium/extensions/",
	"# Lint from stdin",
	"cat my-extension.js | vigolium extensions lint --stdin",
	"# Lint a TypeScript extension",
	"vigolium extensions lint my-extension.ts",
)

var sessionLintExamples = FormatExamples(
	"# Lint a session config file",
	"vigolium auth lint auth-config.yaml",
	"# Lint a JSON session config",
	"vigolium auth lint session-config.json",
	"# Lint from stdin",
	"cat auth-config.yaml | vigolium auth lint --stdin",
)

var sessionLoadExamples = FormatExamples(
	"# Load a YAML session config bound to a host",
	"vigolium auth load auth-config.yaml --host example.com",
	"# Load an agent-produced session-config.json",
	"vigolium auth load ~/.vigolium/agent-sessions/<uuid>/session-config.json",
	"# Load without re-validating login flows",
	"vigolium auth load sessions.json --no-validate",
	"# Pipe a session config from stdin",
	"cat session-config.json | vigolium auth load",
	"# Pipe a raw HTTP login request from stdin",
	"cat login-req.txt | vigolium auth load",
	"# Same, but force a name and host",
	"cat login-req.txt | vigolium auth load --name admin --host juice-shop.example.com",
)

var projectExamples = FormatExamples(
	"# Create a project",
	`vigolium project create my-app --description "Main web app"`,
	"# Create with access control in one line",
	"vigolium project create my-app --allow @acme.com --allow alice@partner.io",
	"# List projects",
	"vigolium project ls",
	"vigolium project ls --json",
	"# Set active project",
	"eval $(vigolium project use <uuid>)",
	"# Add/remove access later",
	"vigolium project allow <uuid> @newdomain.com user@example.com",
	"vigolium project remove-access <uuid> @olddomain.com",
)

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
