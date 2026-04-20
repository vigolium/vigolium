package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	archonMode     string
	archonAgent    string
	archonSource   string
	archonNoStream bool
)

var archonValidModes = map[string]bool{
	"deep":    true,
	"scan":    true,
	"lite":    true,
	"confirm": true,
}

var archonValidPlatforms = map[string]bool{
	archon.PlatformClaude:   true,
	archon.PlatformCodex:    true,
	archon.PlatformOpenCode: true,
}

var agentArchonCmd = &cobra.Command{
	Use:   "archon",
	Short: "Run archon-audit as a foreground security audit",
	Long: `Run archon-audit, a multi-phase AI security audit, as a foreground process.

Extracts the embedded archon harness, clones the --source if it is a git URL
(using vigolium's source-aware storage) or resolves it as a local directory,
and launches the configured agent (Claude/Codex/OpenCode) against the target
source tree. Audit artifacts are synced into the vigolium agent session
directory and findings are imported into the vigolium database.

Examples:
  vigolium agent archon --mode deep --source .
  vigolium agent archon --mode lite --source https://github.com/org/repo
  vigolium agent archon --mode scan --agent codex --source ~/code/myapp`,
	RunE: runAgentArchon,
}

func init() {
	agentCmd.AddCommand(agentArchonCmd)

	f := agentArchonCmd.Flags()
	f.StringVar(&archonMode, "mode", "deep", "Audit mode: deep, scan, lite, confirm")
	f.StringVar(&archonAgent, "agent", archon.PlatformClaude, "Agent platform: claude, codex, opencode")
	f.StringVar(&archonSource, "source", ".", "Source path (local directory) or git URL to audit")
	f.BoolVar(&archonNoStream, "no-stream", false, "Disable stream-json rendering (Claude only, falls back to --print)")
}

func runAgentArchon(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	if !archonValidModes[archonMode] {
		return fmt.Errorf("invalid --mode %q (must be: deep, scan, lite, confirm)", archonMode)
	}
	if !archonValidPlatforms[archonAgent] {
		return fmt.Errorf("invalid --agent %q (must be: claude, codex, opencode)", archonAgent)
	}
	if archonSource == "" {
		return fmt.Errorf("--source is required (local path or git URL)")
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// Resolve source: git URL → clone via vigolium's source-aware helper;
	// local → absolute path.
	var absTarget string
	if looksLikeGitURL(archonSource) {
		fmt.Fprintf(os.Stderr, "%s Cloning %s\n", terminal.InfoSymbol(), terminal.Cyan(archonSource))
		absTarget, err = cloneGitRepo(archonSource)
		if err != nil {
			return fmt.Errorf("clone source: %w", err)
		}
	} else {
		absTarget, err = filepath.Abs(archonSource)
		if err != nil {
			return fmt.Errorf("resolve source path: %w", err)
		}
		if info, err := os.Stat(absTarget); os.IsNotExist(err) || (err == nil && !info.IsDir()) {
			return fmt.Errorf("source path does not exist or is not a directory: %s", absTarget)
		}
	}

	// Verify the configured CLI binary exists in PATH before doing any further work.
	if _, err := exec.LookPath(archonPlatformBinary(archonAgent)); err != nil {
		return fmt.Errorf("%s CLI not found in PATH", archonPlatformBinary(archonAgent))
	}

	// Extract embedded archon harness into the plugin dir for the selected platform.
	pluginDir := settings.Agent.Archon.EffectivePluginDir()
	extracted, err := archon.ExtractArchonHarnessForPlatform(pluginDir, archonAgent)
	if err != nil {
		return fmt.Errorf("extract archon harness: %w", err)
	}
	pluginDir = extracted

	// Create the session directory for this run.
	runID := uuid.New().String()
	sessionDir, err := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), runID)
	if err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	// Open DB (optional — findings import is a no-op without it).
	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
	}

	projectUUID, _ := resolveProjectUUID()

	// Print vigolium-style banner.
	printArchonBanner(archonAgent, archonMode, absTarget, pluginDir, sessionDir)

	// Build the runner config.
	streamEnabled := !archonNoStream && archonAgent == archon.PlatformClaude
	cfg := agent.AuditAgentConfig{
		PluginDir:    pluginDir,
		Mode:         archonMode,
		Platform:     archonAgent,
		SourcePath:   absTarget,
		SessionDir:   sessionDir,
		ProjectUUID:  projectUUID,
		ScanUUID:     globalScanID,
		SyncInterval: 30 * time.Second,
		Stream:       streamEnabled,
	}
	if streamEnabled {
		cfg.StreamWriter = os.Stdout
	}

	runner := agent.NewAuditAgenticScanner(cfg, repo)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := runner.Start(ctx); err != nil {
		return fmt.Errorf("start archon-audit: %w", err)
	}

	runErr := runner.Wait()

	// Summary.
	status := runner.Status()
	stats := runner.FindingStats()
	fmt.Fprintln(os.Stderr)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "%s archon-audit finished with error: %v\n",
			terminal.WarningSymbol(), runErr)
	} else {
		fmt.Fprintf(os.Stderr, "%s archon-audit complete — %s %d/%d phases\n",
			terminal.SuccessSymbol(),
			terminal.HiTeal(status.Status),
			status.CompletedPhases, status.TotalPhases)
	}
	printArchonFindingStats(stats, repo != nil)
	fmt.Fprintf(os.Stderr, "%s Session: %s\n", terminal.InfoSymbol(), terminal.Cyan(sessionDir))

	return runErr
}

// printArchonFindingStats writes a severity breakdown of the imported findings
// to stderr. When the repo is nil, only parse counts are shown (no "imported"
// line) since nothing was persisted.
func printArchonFindingStats(stats agent.FindingStats, persisted bool) {
	flag := terminal.Purple(terminal.SymbolFlag)

	if stats.Parsed == 0 {
		fmt.Fprintf(os.Stderr, "%s Findings: %s\n", flag, terminal.Gray("none parsed"))
		return
	}

	fmt.Fprintf(os.Stderr, "%s Findings: %s parsed%s\n",
		flag,
		terminal.HiTeal(fmt.Sprintf("%d", stats.Parsed)),
		archonSavedSuffix(stats, persisted))

	breakdown := stats.SeverityBreakdownString()
	if breakdown != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Gray(terminal.SymbolDot), breakdown)
	}
}

func archonSavedSuffix(stats agent.FindingStats, persisted bool) string {
	if !persisted {
		return terminal.Gray(" (db unavailable — not persisted)")
	}
	if stats.Saved == stats.Parsed {
		return terminal.Gray(fmt.Sprintf(", %d imported", stats.Saved))
	}
	return terminal.Yellow(fmt.Sprintf(", %d/%d imported", stats.Saved, stats.Parsed))
}

func printArchonBanner(platform, mode, target, pluginDir, sessionDir string) {
	fmt.Fprintf(os.Stderr, "%s %s\n",
		terminal.HiBlue(terminal.SymbolSparkle),
		terminal.BoldHiBlue("Archon Audit"))
	fmt.Fprintf(os.Stderr, "  %s Mode: %s | Agent: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiTeal(mode),
		terminal.HiTeal(platform))
	fmt.Fprintf(os.Stderr, "  %s Source: %s\n",
		terminal.Purple(terminal.SymbolTarget),
		terminal.Orange(target))
	fmt.Fprintf(os.Stderr, "  %s Plugin-dir: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Gray(pluginDir))
	fmt.Fprintf(os.Stderr, "  %s Session: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Gray(sessionDir))
	fmt.Fprintln(os.Stderr)
}

func archonPlatformBinary(platform string) string {
	switch platform {
	case archon.PlatformCodex:
		return "codex"
	case archon.PlatformOpenCode:
		return "opencode"
	default:
		return "claude"
	}
}

