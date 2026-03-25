package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/work"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var scanOpts = types.DefaultOptions()

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a native scan — deterministic multi-phase vulnerability scanning",
	Example: `  # Full scan with verbose output, JSONL + HTML report, skipping spidering phase
  vigolium scan -t http://localhost:3000 --verbose --stateless --format jsonl,html --skip spidering -o sample`,
	RunE: runScanCmd,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	flags := scanCmd.Flags()

	// Target-Format group
	flags.BoolVar(&scanOpts.FormatUseRequiredOnly, "required-only", false, "Parse only required fields from input format (ignore optional)")
	flags.BoolVar(&scanOpts.SkipFormatValidation, "skip-format-validation", false, "Skip validation of input file format")

	// Output group
	flags.StringVarP(&scanOpts.Output, "output", "o", "", "Write findings to specified output file")
	flags.BoolVar(&scanOpts.ShowStats, "stats", false, "Show live progress stats during scanning")
	flags.BoolVar(&scanOpts.IncludeResponseInOutput, "include-response", false, "Include full HTTP response body in output")

	// Optimizations group
	flags.IntVar(&scanOpts.Retries, "retries", 1, "Number of retry attempts for failed requests")
	flags.BoolVar(&scanOpts.Stream, "stream", false, "Process targets as a stream without buffering or deduplication")

	// Database group
	flags.StringSliceVarP(&scanOpts.Headers, "header", "H", nil, "Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token')")
	flags.StringToStringVarP(&scanOpts.AdvancedOptions, "advanced-options", "a", nil, "Module-specific options as key=value (e.g. -a xss.dom=true)")

	// Content discovery flags
	flags.BoolVar(&scanOpts.DiscoverEnabled, "discover", false, "Enable content discovery phase before scanning")
	flags.DurationVar(&scanOpts.DiscoverMaxDuration, "discover-max-time", 1*time.Hour, "Max time for content discovery per target")

	// Browser-based spidering flags
	flags.BoolVar(&scanOpts.SpideringEnabled, "spider", false, "Enable browser-based spidering phase before scanning")
	flags.DurationVar(&scanOpts.SpideringMaxDuration, "spider-max-time", 30*time.Minute, "Max time for spidering per target")
	flags.StringVarP(&scanOpts.SpideringBrowserEngine, "browser-engine", "E", "chromium", "Browser engine: 'chromium', 'ungoogled', or 'fingerprint'")
	flags.IntVarP(&scanOpts.SpideringBrowserCount, "browsers", "b", 1, "Number of parallel browser instances for spidering")
	flags.BoolVar(&scanOpts.SpideringHeadless, "headless", true, "Run browser in headless mode")
	flags.BoolVar(&scanOpts.SpideringNoCDP, "no-cdp", false, "Disable Chrome DevTools Protocol event listener detection")
	flags.BoolVar(&scanOpts.SpideringNoForms, "no-forms", false, "Disable automatic form detection and filling during spidering")
	flags.BoolVar(&scanOpts.SpideringPilotMode, "pilot", false, "Enable AI pilot-driven crawling (ACP agent controls browser)")

	// External intelligence harvesting flags
	flags.BoolVar(&scanOpts.ExternalHarvestEnabled, "external-harvest", false, "Enable external intelligence gathering phase (Wayback, CT logs, etc.)")

	// KnownIssueScan flags
	flags.StringSliceVar(&scanOpts.KnownIssueScanTags, "known-issue-scan-tags", nil, "Nuclei template tags to include (comma-separated)")
	flags.StringSliceVar(&scanOpts.KnownIssueScanExcludeTags, "known-issue-scan-exclude-tags", nil, "Nuclei template tags to exclude (comma-separated)")
	flags.StringSliceVar(&scanOpts.KnownIssueScanSeverities, "known-issue-scan-severities", nil, "Filter Nuclei templates by severity (critical,high,medium,low,info)")
	flags.StringVar(&scanOpts.KnownIssueScanTemplatesDir, "known-issue-scan-templates-dir", "", "Custom Nuclei templates directory")

	// SAST flags
	flags.StringVar(&scanOpts.SASTRuleFilter, "rule", "", "Filter SAST rules by fuzzy name match (e.g. 'gin', 'route')")
	flags.StringVar(&scanOpts.SASTAdhoc, "sast-adhoc", "", "Local path or git URL for ad-hoc SAST scan (auto-detected, results not saved to database)")

	// OAST flags
	flags.StringVar(&scanOpts.OastURL, "oast-url", "", "Fixed out-of-band callback URL (overrides auto-generated interactsh URL)")

	// Stateless mode
	flags.BoolVar(&globalStateless, "stateless", false, "Use a temporary database, export results to --output, then discard the database")

	// Multi-session authentication flags
	flags.StringSliceVar(&scanOpts.Sessions, "session", nil, "Inline session for IDOR/BOLA testing (repeatable, format: name:Header:value)")
	flags.StringVar(&scanOpts.AuthConfigPath, "auth-config", "", "Path to auth-config file with session definitions (YAML or JSON)")
	flags.StringSliceVar(&scanOpts.SessionFiles, "session-file", nil, "Path to individual session file (YAML or JSON, repeatable)")
}

func runScanCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Copy global flags into scan options
	scanOpts.ScanUUID = globalScanID
	scanOpts.Modules = resolveModules()
	scanOpts.PassiveModules = []string{"all"}
	scanOpts.Targets = globalTargets
	scanOpts.TargetsFilePath = globalTargetFile
	scanOpts.InputFileMode = globalInputMode
	scanOpts.InputReadTimeout = globalInputReadTimeout
	scanOpts.Timeout = globalTimeout
	scanOpts.Concurrency = globalConcurrency
	scanOpts.MaxPerHost = globalMaxPerHost
	scanOpts.ConcurrencyExplicitlySet = rootCmd.PersistentFlags().Changed("concurrency")
	scanOpts.MaxPerHostExplicitlySet = rootCmd.PersistentFlags().Changed("max-per-host")
	scanOpts.MaxHostError = globalMaxHostError
	scanOpts.MaxFindingsPerModule = globalMaxFindingsPerModule
	scanOpts.Verbose = globalVerbose
	scanOpts.Silent = globalSilent
	scanOpts.Debug = globalDebug
	scanOpts.DumpTraffic = globalDumpTraffic
	scanOpts.JSONOutput = globalJSON
	scanOpts.ProxyURL = globalProxy
	scanOpts.ConfigPath = globalConfig
	scanOpts.Stdin = fileutil.HasStdin()
	scanOpts.OnlyPhase = globalOnly
	scanOpts.SkipPhases = globalSkipPhases
	scanOpts.ScopeOriginMode = globalScopeOrigin
	scanOpts.SourcePath = globalSourcePath
	scanOpts.OutputFormats = parseFormats(globalFormat)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	scanOpts.ProjectUUID = projectUUID

	// Resolve --sast-adhoc: auto-detect URL vs local path
	if scanOpts.SASTAdhoc != "" && looksLikeGitURL(scanOpts.SASTAdhoc) {
		clonedPath, cloneErr := cloneGitRepo(scanOpts.SASTAdhoc)
		if cloneErr != nil {
			return fmt.Errorf("failed to clone --sast-adhoc URL: %w", cloneErr)
		}
		scanOpts.SASTAdhoc = clonedPath
	}

	// Resolve --source-url: clone the git repo and set SourcePath
	if scanOpts.SourceURL != "" {
		if globalSourcePath != "" {
			return fmt.Errorf("cannot use both --source and --source-url")
		}
		clonedPath, cloneErr := cloneGitRepo(scanOpts.SourceURL)
		if cloneErr != nil {
			return fmt.Errorf("failed to clone --source-url: %w", cloneErr)
		}
		globalSourcePath = clonedPath
		scanOpts.SourcePath = clonedPath
	}

	if err := reconcileOutputFormats(scanOpts); err != nil {
		return err
	}

	// Stateless mode validation
	scanOpts.Stateless = globalStateless
	if scanOpts.Stateless {
		if scanOpts.Output == "" {
			return fmt.Errorf("--stateless requires -o/--output to specify the export file path")
		}
		if globalDB != "" {
			return fmt.Errorf("--stateless and --db are mutually exclusive")
		}
	}

	// Initialize database (always enabled)
	var repo *database.Repository
	var db *database.DB

	// Load settings from config file
	settings, err := config.LoadSettings(scanOpts.ConfigPath)
	if err != nil {
		if !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "%s Config file not found, using defaults\n",
				terminal.Gray(terminal.SymbolPending))
		}
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// Override scope origin mode if --scope-origin flag is set
	if scanOpts.ScopeOriginMode != "" {
		settings.Scope.CLIOriginMode = scanOpts.ScopeOriginMode
	}

	// Override OAST URL if --oast-url flag is set
	if scanOpts.OastURL != "" {
		settings.OAST.OastURL = scanOpts.OastURL
	}

	// Override SQLite path if --db flag is set
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	// Stateless mode: create a temporary SQLite database
	var statelessDBPath string
	if scanOpts.Stateless {
		tmpFile, tmpErr := os.CreateTemp("", "vigolium-stateless-*.sqlite")
		if tmpErr != nil {
			return fmt.Errorf("failed to create temporary database: %w", tmpErr)
		}
		statelessDBPath = tmpFile.Name()
		_ = tmpFile.Close()
		// Cleanup temp DB and WAL/SHM sidecar files on exit
		defer func() {
			_ = os.Remove(statelessDBPath)
			_ = os.Remove(statelessDBPath + "-wal")
			_ = os.Remove(statelessDBPath + "-shm")
		}()

		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = statelessDBPath
		if !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "%s Stateless mode: using temporary database\n", terminal.InfoSymbol())
		}
	}

	// Validate database config
	if err := settings.Database.Validate(); err != nil {
		return fmt.Errorf("invalid database configuration: %w", err)
	}

	// Apply --ext / --ext-dir overrides before validation
	if len(globalExtScripts) > 0 {
		settings.Audit.Extensions.Enabled = true
		settings.Audit.Extensions.CustomDir = append(
			settings.Audit.Extensions.CustomDir,
			globalExtScripts...,
		)
	}
	if globalExtDir != "" {
		settings.Audit.Extensions.Enabled = true
		settings.Audit.Extensions.ExtensionDir = globalExtDir
	}

	// Validate extensions config
	if err := settings.Audit.Extensions.Validate(); err != nil {
		return fmt.Errorf("invalid extensions configuration: %w", err)
	}

	// Validate scanning strategy config
	if err := settings.ScanningStrategy.Validate(); err != nil {
		return fmt.Errorf("invalid scanning strategy configuration: %w", err)
	}

	// Determine scanning profile: CLI --scanning-profile > config scanning_strategy.scanning_profile
	profileName := globalScanningProfile
	if profileName == "" {
		profileName = settings.ScanningStrategy.ScanningProfile
	}

	// Load and apply scanning profile before strategy resolution
	if profileName != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(profileName)
		profile, profileErr := config.LoadProfile(profilePath)
		if profileErr != nil {
			return fmt.Errorf("failed to load scanning profile %q: %w", profileName, profileErr)
		}
		if err := config.ApplyProfile(settings, profile); err != nil {
			return fmt.Errorf("failed to apply scanning profile %q: %w", profileName, err)
		}
		scanOpts.ScanningProfile = profileName
		zap.L().Info("Applied scanning profile", zap.String("profile", profileName), zap.String("path", profilePath))
	}

	// Apply scanning strategy as baseline before per-phase overrides
	scanOpts.ScanningStrategy = globalStrategy
	strategyName := globalStrategy
	if strategyName == "" {
		strategyName = settings.ScanningStrategy.DefaultStrategy
	}
	if strategyName != "" {
		phases, ok := settings.ScanningStrategy.GetStrategy(strategyName)
		if !ok {
			return fmt.Errorf("unknown scanning strategy %q; valid names: %v", strategyName, settings.ScanningStrategy.StrategyNames())
		}
		scanOpts.ExternalHarvestEnabled = phases.ExternalHarvesting
		scanOpts.DiscoverEnabled = phases.Discovery
		scanOpts.SpideringEnabled = phases.Spidering
		scanOpts.KnownIssueScanEnabled = phases.KnownIssueScan
		if phases.SourceAware {
			scanOpts.SASTEnabled = true
		}
		if !phases.Audit {
			scanOpts.SkipAudit = true
		}
		zap.L().Debug("Applied scanning strategy", zap.String("strategy", strategyName))
	}

	// Resolve heuristics check level
	// Precedence: --skip-heuristics > --heuristics-check > config default > "basic"
	scanOpts.HeuristicsCheck = "basic"
	if settings.ScanningStrategy.HeuristicsCheck != "" {
		scanOpts.HeuristicsCheck = settings.ScanningStrategy.HeuristicsCheck
	}
	if globalHeuristicsCheck != "" {
		scanOpts.HeuristicsCheck = globalHeuristicsCheck
	}
	if globalSkipHeuristics {
		scanOpts.HeuristicsCheck = "none"
	}

	// --only and --skip are mutually exclusive
	if scanOpts.OnlyPhase != "" && len(scanOpts.SkipPhases) > 0 {
		return fmt.Errorf("--only and --skip are mutually exclusive; use one or the other")
	}

	// Normalize phase aliases (deparos→discover, spitolas→spidering)
	scanOpts.OnlyPhase = normalizePhase(scanOpts.OnlyPhase)

	// --only overrides strategy and individual phase flags
	if scanOpts.OnlyPhase != "" {
		switch scanOpts.OnlyPhase {
		case "ingestion":
			scanOpts.DiscoverEnabled = false
			scanOpts.ExternalHarvestEnabled = false
			scanOpts.SpideringEnabled = false
			scanOpts.KnownIssueScanEnabled = false
			scanOpts.SkipAudit = true
		case "discovery":
			scanOpts.DiscoverEnabled = true
			scanOpts.ExternalHarvestEnabled = false
			scanOpts.SpideringEnabled = false
			scanOpts.KnownIssueScanEnabled = false
			scanOpts.SkipAudit = true
		case "external-harvest":
			scanOpts.ExternalHarvestEnabled = true
			scanOpts.DiscoverEnabled = false
			scanOpts.SpideringEnabled = false
			scanOpts.KnownIssueScanEnabled = false
			scanOpts.SkipIngestion = true
			scanOpts.SkipAudit = true
		case "spidering":
			scanOpts.SpideringEnabled = true
			scanOpts.DiscoverEnabled = false
			scanOpts.ExternalHarvestEnabled = false
			scanOpts.KnownIssueScanEnabled = false
			scanOpts.SkipIngestion = true
			scanOpts.SkipAudit = true
		case "known-issue-scan":
			scanOpts.KnownIssueScanEnabled = true
			scanOpts.DiscoverEnabled = false
			scanOpts.ExternalHarvestEnabled = false
			scanOpts.SpideringEnabled = false
			scanOpts.SkipIngestion = true
			scanOpts.SkipAudit = true
		case "audit":
			scanOpts.DiscoverEnabled = false
			scanOpts.ExternalHarvestEnabled = false
			scanOpts.SpideringEnabled = false
			scanOpts.KnownIssueScanEnabled = false
			scanOpts.SkipIngestion = true
			scanOpts.SkipAudit = false
		case "sast":
			scanOpts.SASTEnabled = true
			scanOpts.DiscoverEnabled = false
			scanOpts.ExternalHarvestEnabled = false
			scanOpts.SpideringEnabled = false
			scanOpts.KnownIssueScanEnabled = false
			scanOpts.SkipIngestion = true
			scanOpts.SkipAudit = true
		case "extension":
			scanOpts.DiscoverEnabled = false
			scanOpts.ExternalHarvestEnabled = false
			scanOpts.SpideringEnabled = false
			scanOpts.KnownIssueScanEnabled = false
			scanOpts.SkipIngestion = true
			scanOpts.SkipAudit = false
			scanOpts.ExtensionsOnly = true
			settings.Audit.Extensions.Enabled = true
		default:
			return fmt.Errorf("invalid --only value %q; valid phases: ingestion, discovery (deparos), spidering (spitolas), external-harvest, known-issue-scan, sast, audit, extension (ext)", scanOpts.OnlyPhase)
		}
		scanOpts.HeuristicsCheck = "none"
		zap.L().Info("Phase isolation active", zap.String("only", scanOpts.OnlyPhase))
	}

	// --skip disables specific phases while keeping all others
	if len(scanOpts.SkipPhases) > 0 {
		for _, phase := range scanOpts.SkipPhases {
			phase = normalizePhase(phase)
			switch phase {
			case "discovery", "ingestion":
				scanOpts.SkipIngestion = true
			case "external-harvest":
				scanOpts.ExternalHarvestEnabled = false
			case "spidering":
				scanOpts.SpideringEnabled = false
			case "known-issue-scan":
				scanOpts.KnownIssueScanEnabled = false
			case "sast":
				scanOpts.SASTEnabled = false
			case "audit":
				scanOpts.SkipAudit = true
			default:
				return fmt.Errorf("invalid --skip value %q; valid phases: discovery (deparos), external-harvest, spidering (spitolas), known-issue-scan, sast, audit", phase)
			}
		}
		zap.L().Info("Phases skipped", zap.Strings("skip", scanOpts.SkipPhases))
	}

	// Validate HTML output format constraints
	if scanOpts.HasFormat("html") {
		if scanOpts.Output == "" {
			return fmt.Errorf("--format html requires -o/--output to specify the report file path")
		}
		if scanOpts.OnlyPhase != "" &&
			scanOpts.OnlyPhase != "discovery" && scanOpts.OnlyPhase != "spidering" {
			return fmt.Errorf("--format html is only supported for discovery and spidering phases")
		}
	}

	// Multi-format requires -o/--output for file-based formats
	if len(scanOpts.OutputFormats) > 1 && scanOpts.Output == "" {
		return fmt.Errorf("multiple --format values require -o/--output to specify the base output path")
	}

	// Override scanning_pace.max_duration if --scanning-max-duration flag is set
	if rootCmd.PersistentFlags().Changed("scanning-max-duration") && globalScanningMaxDuration > 0 {
		settings.ScanningPace.MaxDuration = globalScanningMaxDuration.String()
	}

	// Validate and apply scanning_pace centralized speed control
	if err := settings.ScanningPace.Validate(); err != nil {
		return fmt.Errorf("invalid scanning_pace configuration: %w", err)
	}

	// Apply scanning_pace common values (precedence 4 — lowest after built-in defaults)
	pace := &settings.ScanningPace
	if !scanOpts.ConcurrencyExplicitlySet && pace.Concurrency > 0 {
		scanOpts.Concurrency = pace.Concurrency
	}
	if !scanOpts.MaxPerHostExplicitlySet && pace.MaxPerHost > 0 {
		scanOpts.MaxPerHost = pace.MaxPerHost
	}

	// Apply scanning_pace.discovery.max_duration (precedence 3) to scanOpts
	discoveryPace := pace.ResolvePhase("discovery")
	if !cmd.Flags().Changed("discover-max-time") && discoveryPace.MaxDuration > 0 {
		scanOpts.DiscoverMaxDuration = discoveryPace.MaxDuration
	}

	// Apply scanning_pace.spidering.max_duration to scanOpts
	spideringPace := pace.ResolvePhase("spidering")
	if !cmd.Flags().Changed("spider-max-time") && spideringPace.MaxDuration > 0 {
		scanOpts.SpideringMaxDuration = spideringPace.MaxDuration
	}

	// Validate per-phase configs when enabled (strategy + CLI flags are the only sources)
	if scanOpts.DiscoverEnabled {
		if err := settings.Discovery.Validate(); err != nil {
			return fmt.Errorf("invalid discovery configuration: %w", err)
		}
	}
	if scanOpts.KnownIssueScanEnabled {
		// Apply CLI overrides for KnownIssueScan config
		if cmd.Flags().Changed("known-issue-scan-tags") {
			settings.KnownIssueScan.Tags = scanOpts.KnownIssueScanTags
		}
		if cmd.Flags().Changed("known-issue-scan-exclude-tags") {
			settings.KnownIssueScan.ExcludeTags = scanOpts.KnownIssueScanExcludeTags
		}
		if cmd.Flags().Changed("known-issue-scan-severities") {
			settings.KnownIssueScan.Severities = scanOpts.KnownIssueScanSeverities
		}
		if cmd.Flags().Changed("known-issue-scan-templates-dir") {
			settings.KnownIssueScan.TemplatesDir = scanOpts.KnownIssueScanTemplatesDir
		}
		if err := settings.KnownIssueScan.Validate(); err != nil {
			return fmt.Errorf("invalid known-issue-scan configuration: %w", err)
		}
	}
	if scanOpts.SpideringEnabled {
		// Apply CLI overrides for spidering config
		if cmd.Flags().Changed("browser-engine") {
			settings.Spidering.BrowserEngine = scanOpts.SpideringBrowserEngine
		}
		if cmd.Flags().Changed("browsers") {
			settings.Spidering.BrowserCount = scanOpts.SpideringBrowserCount
		}
		if cmd.Flags().Changed("headless") {
			settings.Spidering.Headless = scanOpts.SpideringHeadless
		}
		if cmd.Flags().Changed("no-cdp") {
			settings.Spidering.NoCDP = scanOpts.SpideringNoCDP
		}
		if cmd.Flags().Changed("no-forms") {
			settings.Spidering.NoForms = scanOpts.SpideringNoForms
		}
		if cmd.Flags().Changed("pilot") {
			settings.Spidering.PilotMode = scanOpts.SpideringPilotMode
		}
		if err := settings.Spidering.Validate(); err != nil {
			return fmt.Errorf("invalid spidering configuration: %w", err)
		}
	}
	if scanOpts.ExternalHarvestEnabled {
		if len(settings.ExternalHarvester.Sources) == 0 {
			defaults := config.DefaultExternalHarvesterConfig()
			settings.ExternalHarvester.Sources = defaults.Sources
		}
		if err := settings.ExternalHarvester.Validate(); err != nil {
			return fmt.Errorf("invalid external harvester configuration: %w", err)
		}
	}

	// Create database connection
	db, err = database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create database connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create database schema: %w", err)
	}

	// Create repository
	repo = database.NewRepository(db)
	zap.L().Debug("Database initialized successfully",
		zap.String("driver", db.Driver()))

	// Print scan summary banner (after DB init so we can show HTTP record count)
	printScanSummary(scanOpts, settings, strategyName, repo)
	scanOpts.ScanConfigPrinted = true

	// Auto-create source repo if --source or --source-url is provided
	if globalSourcePath != "" {
		if err := upsertSourceRepo(ctx, repo, scanOpts.Targets, globalSourcePath); err != nil {
			zap.L().Warn("Failed to link source repo", zap.Error(err))
		}
	}

	// Warn about source_aware only when no --source and no existing repos in DB
	if strategyName != "" && globalSourcePath == "" {
		if phases, ok := settings.ScanningStrategy.GetStrategy(strategyName); ok && phases.SourceAware {
			hasSourceRepos := false
			for _, t := range scanOpts.Targets {
				if u, parseErr := url.Parse(t); parseErr == nil && u.Hostname() != "" {
					if existing, _ := repo.GetSourceReposByHostname(ctx, scanOpts.ProjectUUID, u.Hostname()); len(existing) > 0 {
						hasSourceRepos = true
						break
					}
				}
			}
			if !hasSourceRepos {
				zap.L().Info("Strategy enables source_aware scanning; provide --source <path> for full coverage")
			}
		}
	}

	// For stateless + jsonl/html: suppress StandardWriter file output; we export the full DB post-scan.
	// For stateless + console-only: let StandardWriter write to --output normally (findings-only is fine).
	var statelessOutputPath string
	hasFileFormats := scanOpts.HasFormat("jsonl") || scanOpts.HasFormat("html")
	if scanOpts.Stateless && hasFileFormats {
		statelessOutputPath = scanOpts.Output
		scanOpts.Output = "" // prevent StandardWriter from creating the output file
	}
	// Defer stateless export so all exit paths are covered automatically.
	defer func() { finishStatelessExport(db, scanOpts, statelessOutputPath) }()

	// If -i was explicitly provided, use two-phase ingest-then-scan
	hasInputFile := globalInput != "" && globalInput != "-"
	if hasInputFile {
		return runScanWithIngest(settings, db, repo)
	}

	// If no targets/input/stdin, fall back to scanning DB records
	hasTargets := len(scanOpts.Targets) > 0
	hasTargetFile := scanOpts.TargetsFilePath != ""
	hasStdin := scanOpts.Stdin
	if !hasTargets && !hasTargetFile && !hasStdin {
		return runDBScan(settings, db, repo)
	}

	// Smart stdin detection: if stdin is present and -I was not explicitly set,
	// peek at the content to detect raw HTTP or curl format
	if hasStdin && !cmd.Flags().Changed("input-mode") {
		raw, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return fmt.Errorf("failed to read stdin: %w", readErr)
		}
		content := strings.TrimSpace(string(raw))
		if content != "" {
			detected := detect.DetectStdinFormat(content)
			if detected != detect.FormatURLs {
				// Raw HTTP or curl — parse eagerly and use SliceSource
				items, parseErr := detect.ParseStdinContent(content, detected)
				if parseErr != nil {
					return fmt.Errorf("failed to parse stdin as %s: %w", detected, parseErr)
				}
				inputSrc := source.NewSliceSource(items, scanOpts.Modules)
				scanOpts.Stdin = false

				scanRunner, runnerErr := runner.NewWithInputSource(scanOpts, inputSrc)
				if runnerErr != nil {
					return fmt.Errorf("failed to create scan runner: %w", runnerErr)
				}
				defer scanRunner.Close()

				scanRunner.SetSettings(settings)
				if repo != nil {
					scanRunner.SetRepository(repo)
				}

				setupScanSignalHandler(scanRunner)

				if err := scanRunner.RunNativeScan(); err != nil {
					zap.L().Info("Could not run scanner", zap.Error(err))
				}

				maybeGenerateHTMLReport(db, scanOpts)

				if !scanOpts.Silent {
					fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Aqua(terminal.SymbolSparkle), terminal.BoldAqua("Native scan completed"))
					printScanCompletionSummary(repo)
				}
				return nil
			}
		}
		// URLs detected — fall through to existing runner.New() which handles stdin streaming.
		// However, we already consumed stdin, so we need to pass the content as targets instead.
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				scanOpts.Targets = append(scanOpts.Targets, line)
			}
		}
		scanOpts.Stdin = false
	}

	scanRunner, err := runner.New(scanOpts)
	if err != nil {
		zap.L().Fatal("Could not create runner", zap.Error(err))
	}
	if scanRunner == nil {
		return nil
	}

	// Set settings and repository on runner
	scanRunner.SetSettings(settings)
	if repo != nil {
		scanRunner.SetRepository(repo)
	}

	setupScanSignalHandler(scanRunner)

	if err := scanRunner.RunNativeScan(); err != nil {
		zap.L().Info("Could not run scanner", zap.Error(err))
	}
	scanRunner.Close()

	// Generate HTML report if requested
	maybeGenerateHTMLReport(db, scanOpts)

	// Print completion message with summary stats
	if !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Aqua(terminal.SymbolSparkle), terminal.BoldAqua("Native scan completed"))
		printScanCompletionSummary(repo)
	}

	return nil
}

// runScanWithIngest delegates to the Runner's 3-phase pipeline when -i is provided.
// The Runner's Phase 1 ingests the input file, Phase 2 runs KnownIssueScan if enabled,
// and Phase 3 scans from DB with all modules.
func runScanWithIngest(settings *config.Settings, db *database.DB, repo *database.Repository) error {
	// Auto-detect format from file extension
	inputFormat := globalInputMode
	if inputFormat == "urls" {
		if detected := detectInputFormat(globalInput); detected != "" {
			inputFormat = detected
			zap.L().Info("Auto-detected input format", zap.String("format", inputFormat))
		}
	}

	// OpenAPI defaults: auto-enable UseSpecServers when no -t given
	useSpecServers := globalSpecURL
	if (inputFormat == "openapi" || inputFormat == "swagger") &&
		len(globalTargets) == 0 && !useSpecServers {
		useSpecServers = true
		zap.L().Info("Auto-enabled --spec-url (no -t provided)")
	}

	// Create InputSource from the input file
	inputSource, err := source.NewInputSource(source.SourceConfig{
		Targets:       globalTargets,
		FilePath:      globalInput,
		Format:        inputFormat,
		BufferSize:    100,
		EnableModules: scanOpts.Modules,
	})
	if err != nil {
		return fmt.Errorf("failed to create input source: %w", err)
	}

	// Configure OpenAPI options if applicable
	if inputFormat == "openapi" || inputFormat == "swagger" {
		if fs, ok := inputSource.(*source.FileSource); ok {
			if openapiFormat, ok := fs.Format().(*openapi.Format); ok {
				var targetURL string
				if len(globalTargets) > 0 {
					targetURL = globalTargets[0]
				}
				openapiFormat.SetOpenAPIOptions(openapi.Options{
					BaseURL:              targetURL,
					UseSpecServers:       useSpecServers,
					Headers:              ingestParseHeaders(globalSpecHeader),
					Variables:            ingestParseVariables(globalSpecVar),
					DefaultFallbackValue: globalSpecDefault,
				})
			}
		}
	}

	// Create Runner with the input source — RunNativeScan handles all 3 phases
	scanRunner, err := runner.NewWithInputSource(scanOpts, inputSource)
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	setupScanSignalHandler(scanRunner)

	if err := scanRunner.RunNativeScan(); err != nil {
		zap.L().Info("Could not run scanner", zap.Error(err))
	}

	// Generate HTML report if requested
	maybeGenerateHTMLReport(db, scanOpts)

	if !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Aqua(terminal.SymbolSparkle), terminal.BoldAqua("Native scan completed"))
		printScanCompletionSummary(repo)
	}

	return nil
}

// runDBScan scans records already in the database (no explicit targets).
// Delegates to RunNativeScan(): Phase 1 is a no-op (empty source),
// Phase 2 runs KnownIssueScan if enabled, Phase 3 reads existing DB records.
func runDBScan(settings *config.Settings, db *database.DB, repo *database.Repository) error {
	// Create Runner with an empty input source — Phase 1 becomes a no-op
	scanRunner, err := runner.NewWithInputSource(scanOpts, &emptySource{})
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	setupScanSignalHandler(scanRunner)

	if err := scanRunner.RunNativeScan(); err != nil {
		zap.L().Info("Could not run scanner", zap.Error(err))
	}

	// Generate HTML report if requested
	maybeGenerateHTMLReport(db, scanOpts)

	if !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Aqua(terminal.SymbolSparkle), terminal.BoldAqua("Native scan completed"))
		printScanCompletionSummary(repo)
	}

	return nil
}

// emptySource is an InputSource that immediately returns io.EOF.
// Used when no external input is provided (DB-only scan mode).
type emptySource struct{}

func (e *emptySource) Next(_ context.Context) (*work.WorkItem, error) { return nil, io.EOF }
func (e *emptySource) Close() error                                   { return nil }


// upsertSourceRepo links application source code to the first target's hostname.
// If a source repo already exists for the same hostname+path, it is a no-op.
func upsertSourceRepo(ctx context.Context, repo *database.Repository, targets []string, sourcePath string) error {
	absPath, err := filepath.Abs(sourcePath)
	if err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("source path does not exist: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", absPath)
	}

	// Resolve hostname from the first target
	hostname := ""
	for _, t := range targets {
		if u, parseErr := url.Parse(t); parseErr == nil && u.Hostname() != "" {
			hostname = u.Hostname()
			break
		}
	}
	if hostname == "" {
		return fmt.Errorf("cannot determine hostname from targets for --source")
	}

	// Check for existing link with the same hostname+path
	existing, _ := repo.GetSourceReposByHostname(ctx, scanOpts.ProjectUUID, hostname)
	for _, sr := range existing {
		if sr.RootPath == absPath {
			zap.L().Debug("Source repo already linked", zap.String("hostname", hostname), zap.String("path", absPath))
			return nil
		}
	}

	sr := &database.SourceRepo{
		ProjectUUID: scanOpts.ProjectUUID,
		Hostname:    hostname,
		Name:        filepath.Base(absPath),
		RootPath:    absPath,
		RepoType:    "folder",
	}
	if err := repo.CreateSourceRepo(ctx, sr); err != nil {
		return err
	}

	if !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "%s Source repo linked: %s -> %s\n",
			terminal.InfoSymbol(),
			terminal.Cyan(hostname),
			terminal.Gray(absPath))
	}
	return nil
}

// generateHTMLFromDB queries all data from the database (HTTP records, scans,
// findings, modules) and generates an HTML report at the specified output path.
func generateHTMLFromDB(ctx context.Context, db *database.DB, outputPath string) error {
	items, err := queryExportData(ctx, db)
	if err != nil {
		return err
	}
	meta := output.HTMLReportMeta{
		Title:        "Vigolium Scan Report",
		Version:      getVersion(),
		ScanDuration: computeScanDuration(ctx, db),
	}
	return output.GenerateHTMLReport(items, outputPath, meta)
}

// normalizePhase maps phase aliases to their canonical names.
func normalizePhase(phase string) string {
	switch phase {
	case "deparos", "discover":
		return "discovery"
	case "spitolas":
		return "spidering"
	case "dynamic-assessment":
		return "audit"
	case "ext":
		return "extension"
	default:
		return phase
	}
}

// parseFormats splits a comma-separated format string, defaulting to "console".
func parseFormats(raw string) []string {
	parts := strings.Split(raw, ",")
	formats := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			formats = append(formats, p)
		}
	}
	if len(formats) == 0 {
		return []string{"console"}
	}
	return formats
}

// reconcileOutputFormats applies --json and --ci-output-format overrides to
// OutputFormats and validates the result. Shared by scan and scan-url commands.
func reconcileOutputFormats(opts *types.Options) error {
	if globalJSON && len(opts.OutputFormats) == 1 && opts.OutputFormats[0] == "console" {
		opts.OutputFormats = []string{"jsonl"}
	}
	if opts.HasFormat("jsonl") {
		opts.JSONOutput = true
	}
	if globalCIOutput {
		opts.CIOutput = true
		opts.OutputFormats = []string{"jsonl"}
		opts.JSONOutput = true
		opts.Silent = true
	}
	for _, f := range opts.OutputFormats {
		switch f {
		case "console", "jsonl", "html":
		default:
			return fmt.Errorf("invalid --format value %q; valid formats: console, jsonl, html", f)
		}
	}
	return nil
}

// maybeGenerateHTMLReport generates an HTML report post-scan when html format is requested.
func maybeGenerateHTMLReport(db *database.DB, opts *types.Options) {
	if !opts.HasFormat("html") || opts.Output == "" {
		return
	}
	outPath := opts.OutputPathForFormat("html")
	if err := generateHTMLFromDB(context.Background(), db, outPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to generate HTML report: %v\n", terminal.ErrorPrefix(), err)
	} else if !opts.Silent {
		fmt.Fprintf(os.Stderr, "%s HTML report: %s\n", terminal.InfoSymbol(), terminal.Cyan(outPath))
	}
}

// finishStatelessExport writes the full database export to the output file(s)
// when running in stateless mode with jsonl or html format.
// For console format, StandardWriter already handles the output file.
// (with scanOpts.Output cleared, it's a no-op), so we handle it here.
func finishStatelessExport(db *database.DB, opts *types.Options, outputPath string) {
	if !opts.Stateless || outputPath == "" {
		return
	}

	ctx := context.Background()
	basePath := types.StripFormatExtension(outputPath)

	for _, format := range opts.OutputFormats {
		outPath := types.FormatOutputPath(basePath, format)
		switch format {
		case "html":
			if err := generateHTMLFromDB(ctx, db, outPath); err != nil {
				fmt.Fprintf(os.Stderr, "%s Failed to generate HTML report: %v\n", terminal.ErrorPrefix(), err)
			} else if !opts.Silent {
				fmt.Fprintf(os.Stderr, "%s HTML report exported to %s\n", terminal.InfoSymbol(), terminal.Cyan(outPath))
			}
		case "jsonl":
			exportStatelessJSONL(ctx, db, opts, outPath)
		}
	}
}

// exportStatelessJSONL writes all database records to a JSONL file.
func exportStatelessJSONL(ctx context.Context, db *database.DB, opts *types.Options, outputPath string) {
	items, err := queryExportData(ctx, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to export data: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	f, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create output file: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	var writeErr error
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			writeErr = err
			break
		}
	}
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to write export data: %v\n", terminal.ErrorPrefix(), writeErr)
	} else if !opts.Silent {
		fmt.Fprintf(os.Stderr, "%s Results exported to %s (%d records)\n",
			terminal.InfoSymbol(), terminal.Cyan(outputPath), len(items))
	}
}

func setupScanSignalHandler(r *runner.Runner) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		// First Ctrl+C: graceful shutdown
		<-c
		zap.L().Info("CTRL+C pressed: Exiting")
		zap.L().Info("Attempting graceful shutdown...")

		// Start graceful Close in a goroutine
		closeDone := make(chan struct{})
		go func() {
			r.Close()
			close(closeDone)
		}()

		// Wait for Close to finish or a second Ctrl+C
		select {
		case <-closeDone:
			// Graceful shutdown completed
		case <-c:
			zap.L().Warn("Second CTRL+C received, forcing exit")
			os.Exit(1)
		}
	}()
}

// printScanSummary prints a human-readable scan configuration overview to stderr.
func printScanSummary(opts *types.Options, settings *config.Settings, strategyName string, repo *database.Repository) {
	if opts.Silent || globalJSON || globalCIOutput {
		return
	}

	// Phase status indicators: symbol + colored name + optional pace detail
	phaseLabel := func(name, phasePaceKey string, enabled bool) string {
		label := name
		if !enabled {
			return terminal.Gray(terminal.SymbolError) + " " + terminal.Gray(label)
		}
		// Append max_duration / duration_factor if set
		resolved := settings.ScanningPace.ResolvePhase(phasePaceKey)
		var paceDetail string
		if resolved.MaxDuration > 0 {
			paceDetail = resolved.MaxDuration.String()
		}
		if resolved.DurationFactor > 0 {
			if paceDetail != "" {
				paceDetail += fmt.Sprintf(", x%.1f", resolved.DurationFactor)
			} else {
				paceDetail = fmt.Sprintf("x%.1f", resolved.DurationFactor)
			}
		}
		if paceDetail != "" {
			label += " " + terminal.Gray("("+paceDetail+")")
		}
		return terminal.Green(terminal.SymbolSuccess) + " " + terminal.HiCyan(label)
	}

	discoveryEnabled := opts.DiscoverEnabled
	spideringEnabled := opts.SpideringEnabled
	knownIssueScanEnabled := opts.KnownIssueScanEnabled
	daEnabled := !opts.SkipAudit
	ehEnabled := opts.ExternalHarvestEnabled

	// Strategy name
	strategy := strategyName
	if strategy == "" {
		strategy = "default"
	}

	// Module counts
	var activeCount, passiveCount int
	if len(opts.Modules) > 0 && opts.Modules[0] == "all" {
		activeCount = len(modules.GetActiveModules())
	} else {
		activeCount = len(modules.GetActiveModulesByIDs(opts.Modules))
	}
	passiveCount = len(modules.GetPassiveModules())

	// Scope origin mode
	scopeOrigin := settings.Scope.CLIOriginMode
	if scopeOrigin == "" {
		scopeOrigin = "relaxed"
	}

	fmt.Fprintf(os.Stderr, "\n  %s run %s and %s to view ingested data and vulnerabilities\n",
		terminal.TipPrefix(),
		terminal.HiCyan("vigolium traffic list"),
		terminal.HiCyan("vigolium findings list"))
	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.HiBlue(terminal.SymbolSparkle), terminal.BoldHiBlue("Scan Configuration"))
	if opts.ProjectUUID != "" {
		fmt.Fprintf(os.Stderr, "  %s Project: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ProjectUUID))
	}
	fmt.Fprintf(os.Stderr, "  %s Strategy: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(strategy))
	if opts.ScanningProfile != "" {
		fmt.Fprintf(os.Stderr, "  %s Profile: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanningProfile))
	}
	targetsLine := fmt.Sprintf("Targets: %s (CLI: %s)", terminal.Orange(fmt.Sprintf("%d", len(opts.Targets))), terminal.HiBlue(strings.Join(opts.Targets, ", ")))
	if opts.TargetsFilePath != "" {
		targetsLine += fmt.Sprintf(" (+ file: %s)", terminal.HiTeal(opts.TargetsFilePath))
	}
	if repo != nil {
		ctx := context.Background()
		if dbCount, err := repo.CountRecordsAfterCursor(ctx, time.Time{}, ""); err == nil && dbCount > 0 {
			targetsLine += fmt.Sprintf(" | %s (HTTP Records)", terminal.Orange(fmt.Sprintf("%d", dbCount)))
		}
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolTarget), targetsLine)
	sastEnabled := opts.SASTEnabled
	fmt.Fprintf(os.Stderr, "  %s Phases: %s | %s | %s\n",
		terminal.Purple(terminal.SymbolInfo),
		phaseLabel("ExternalHarvest", "external_harvester", ehEnabled),
		phaseLabel("Spidering", "spidering", spideringEnabled),
		phaseLabel("Discovery", "discovery", discoveryEnabled))
	fmt.Fprintf(os.Stderr, "           %s | %s | %s\n",
		phaseLabel("KnownIssueScan", "known-issue-scan", knownIssueScanEnabled),
		phaseLabel("Audit", "audit", daEnabled),
		phaseLabel("SAST", "sast", sastEnabled))
	if sastEnabled && opts.SASTAdhoc != "" {
		fmt.Fprintf(os.Stderr, "  %s Repo: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.SASTAdhoc))
	}
	heuristicsDesc := map[string]string{
		"basic":    "probe target root pages to detect content type (HTML, JSON, blank) and skip spidering for non-HTML targets",
		"advanced": "basic checks + deep HTML analysis to detect SPA frameworks and optimize phase selection",
		"none":     "skip all heuristic probes, run all enabled phases unconditionally",
	}
	if desc, ok := heuristicsDesc[opts.HeuristicsCheck]; ok {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck),
			terminal.Gray(desc))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck))
	}
	fmt.Fprintf(os.Stderr, "  %s Speed: concurrency=%s | rate-limit=%s | max-per-host=%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiBlue(fmt.Sprintf("%d", opts.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", globalRateLimit)),
		terminal.HiBlue(fmt.Sprintf("%d", opts.MaxPerHost)))
	originDesc := map[string]string{
		"relaxed":  "host must contain the target's keyword (e.g. \"example\")",
		"all":      "no origin restriction, all hosts are in scope",
		"balanced": "host must share the target's eTLD+1 (e.g. *.example.com)",
		"strict":   "host must exactly match the target host",
	}
	originDescStr := ""
	if desc, ok := originDesc[scopeOrigin]; ok {
		originDescStr = " " + terminal.Gray(desc)
	}
	fmt.Fprintf(os.Stderr, "  %s Scope: origin=%s | ignore-static=%s%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiPurple(scopeOrigin),
		terminal.HiPurple(fmt.Sprintf("%v", settings.Scope.IgnoreStaticFile)),
		originDescStr)
	modulesLine := fmt.Sprintf("Modules: %s active, %s passive",
		terminal.Orange(fmt.Sprintf("%d", activeCount)),
		terminal.Orange(fmt.Sprintf("%d", passiveCount)))
	if settings != nil && settings.Audit.Extensions.Enabled {
		extCount := countExtensionFiles(&settings.Audit.Extensions)
		modulesLine += fmt.Sprintf(" + %s extensions", terminal.HiTeal(fmt.Sprintf("%d", extCount)))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), modulesLine)
	if globalVerbose {
		fmt.Fprintf(os.Stderr, "\n  %s view scope details via %s\n",
			terminal.TipPrefix(),
			terminal.HiCyan("vigolium config ls scope"))
		fmt.Fprintf(os.Stderr, "  %s view scanning pace via %s\n",
			terminal.TipPrefix(),
			terminal.HiCyan("vigolium config ls scanning_pace"))
		if knownIssueScanEnabled && !settings.KnownIssueScan.EnrichTargets {
			fmt.Fprintf(os.Stderr, "  %s enrich KnownIssueScan targets with discovered paths via %s\n",
				terminal.TipPrefix(),
				terminal.HiCyan("vigolium config known_issue_scan.enrich_targets=true"))
		}
	}
	fmt.Fprintln(os.Stderr)
}

// countExtensionFiles counts JS/TS/YAML extension files from the configured directories without loading them.
func countExtensionFiles(cfg *config.ExtensionsConfig) int {
	count := len(cfg.CustomDir)

	if cfg.ExtensionDir != "" {
		dir := config.ExpandPath(cfg.ExtensionDir)
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if strings.HasSuffix(name, ".d.ts") {
					continue
				}
				if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".vgm.yaml") {
					count++
				}
			}
		}
	}

	return count
}

// printScanCompletionSummary prints a compact summary of ingested records and findings after scan completion.
func printScanCompletionSummary(repo *database.Repository) {
	if repo == nil {
		return
	}

	ctx := context.Background()
	db := repo.DB()

	// Count HTTP records
	var recordCount int
	err := db.NewSelect().Model((*database.HTTPRecord)(nil)).ColumnExpr("COUNT(*)").Scan(ctx, &recordCount)
	if err != nil {
		return
	}

	// Count findings by severity
	type sevCount struct {
		Severity string `bun:"severity"`
		Count    int64  `bun:"count"`
	}
	var sevCounts []sevCount
	err = db.NewSelect().Model((*database.Finding)(nil)).
		ColumnExpr("severity, COUNT(*) AS count").
		GroupExpr("severity").
		Scan(ctx, &sevCounts)
	if err != nil {
		return
	}

	var totalFindings int64
	counts := make(map[string]int64)
	for _, sc := range sevCounts {
		counts[sc.Severity] = sc.Count
		totalFindings += sc.Count
	}

	fmt.Fprintf(os.Stderr, "  %s Records: %s http records ingested\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Cyan(fmt.Sprintf("%d", recordCount)))

	if totalFindings == 0 {
		fmt.Fprintf(os.Stderr, "  %s Findings: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray("no issues found"))
		return
	}

	// Build severity breakdown
	var parts []string
	for _, s := range []struct {
		key  string
		fn   func(string) string
		sym  func() string
	}{
		{"critical", terminal.BoldMagenta, terminal.CriticalSymbol},
		{"high", terminal.BoldRed, terminal.HighSymbol},
		{"medium", terminal.BoldYellow, terminal.MediumSymbol},
		{"low", terminal.BoldGreen, terminal.LowSymbol},
		{"suspect", terminal.BoldCyan, terminal.SuspectSymbol},
		{"info", terminal.BoldBlue, terminal.InfoSeveritySymbol},
	} {
		if c, ok := counts[s.key]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%s %s %s", s.sym(), s.fn(fmt.Sprintf("%d", c)), s.key))
		}
	}

	fmt.Fprintf(os.Stderr, "  %s Findings: %s issues found — %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(fmt.Sprintf("%d", totalFindings)),
		strings.Join(parts, ", "))
}
