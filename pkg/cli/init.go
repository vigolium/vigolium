package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	oliumresources "github.com/vigolium/vigolium/internal/resources/olium"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/diagnostics"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
	"go.uber.org/zap"
)

const (
	settingsFileName   = "vigolium-configs.yaml"
	initMarkerFileName = "initialized"
)

// writeInitMarker stamps ~/.vigolium/initialized with the binary version and
// current timestamp. The marker means "the core native-scan tooling (chromium +
// nuclei templates) was seen present" — written by ensureCoreDeps, doctor and
// init only when both are, or by --skip-dependency-check. Once stamped, scan
// commands fast-path past the dep check on every invocation.
func writeInitMarker(vigoliumDir string) error {
	path := filepath.Join(vigoliumDir, initMarkerFileName)
	payload := fmt.Sprintf(`{"version":%q,"initialized_at":%q}`+"\n",
		Version,
		time.Now().UTC().Format(time.RFC3339))
	return os.WriteFile(path, []byte(payload), 0644)
}

// initializeVigolium initializes Vigolium on first run: it writes the default
// config, profiles, extensions, prompts and skills into ~/.vigolium.
//
// createDefaultDB decides whether ~/.vigolium/database-vgnm.sqlite is created
// too. It is false when the invocation has pinned a different store with --db
// (or VIGOLIUM_DB_PATH, which applyDBPathEnv has already folded into globalDB
// by the time ensureInitialized runs): creating the default database there
// produces a seeded, schema-migrated file the run will never open, in the one
// directory a user is most likely to inspect to find out where their data went.
// The pinned store is created and seeded by whichever path first opens it,
// exactly as it already is on a warm $HOME.
func initializeVigolium(createDefaultDB bool) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	settingsPath := filepath.Join(vigoliumDir, settingsFileName)

	// Check if settings file already exists
	if _, err := os.Stat(settingsPath); err == nil {
		// Settings file exists, Vigolium is already initialized
		return nil
	}

	// First run - initialize Vigolium
	fmt.Fprintf(os.Stderr, "%s %s\n",
		terminal.Cyan(terminal.SymbolRunning),
		terminal.BoldCyan("First-time run detected — checking for mandatory configuration and dependencies..."))
	zap.L().Info("First run detected - initializing Vigolium...")

	// Create .vigolium directory
	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		return fmt.Errorf("failed to create .vigolium directory: %w", err)
	}

	// Write the curated example YAML as the default config — preserves comments,
	// formatting, and avoids zero-value noise from struct marshalling.
	// Replace the auth_api_key placeholder with a real random key.
	configData := bytes.Replace(
		public.DefaultConfigYAML,
		[]byte(`auth_api_key: "auto-generated-on-first-run"`),
		[]byte(fmt.Sprintf(`auth_api_key: "%s"`, config.GenerateRandomHex(40))),
		1,
	)
	if err := os.WriteFile(settingsPath, configData, 0600); err != nil {
		return fmt.Errorf("failed to write default config: %w", err)
	}

	// Load settings back for database initialization and display below.
	settings := config.DefaultSettings()

	zap.L().Info("Created default settings file",
		zap.String("path", settingsPath))

	// Initialize database
	if createDefaultDB && settings.Database.Enabled {
		fmt.Fprintf(os.Stderr, "  %s Creating database schema...\n", terminal.InfoSymbol())
		zap.L().Info("Initializing database...")

		db, err := database.NewDB(&settings.Database)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		defer func() { _ = db.Close() }()

		ctx := context.Background()
		if err := db.EnsureSchemaReady(ctx); err != nil {
			return fmt.Errorf("failed to create database schema: %w", err)
		}

		fmt.Fprintf(os.Stderr, "  %s Seeding default project and search indexes...\n", terminal.InfoSymbol())
		if err := db.SeedDefaults(ctx); err != nil {
			return fmt.Errorf("failed to seed default data: %w", err)
		}

		zap.L().Debug("Database initialized successfully",
			zap.String("driver", settings.Database.Driver),
			zap.String("path", settings.Database.SQLite.Path))
	}

	fmt.Fprintf(os.Stderr, "  %s Installing default profiles, extensions, prompts, and skills...\n", terminal.InfoSymbol())

	// Bootstrap default profiles
	bootstrapDefaultProfiles(vigoliumDir)

	// Bootstrap preset extensions
	bootstrapExtensions(vigoliumDir)

	// Bootstrap prompt templates
	bootstrapPrompts(vigoliumDir)

	// Bootstrap agentic-scan skills (~/.vigolium/skills or VIGOLIUM_SKILLS_DIR)
	bootstrapSkills()

	// Note: the ~/.vigolium/initialized marker is intentionally NOT written
	// here. The marker tracks core dep installation (chromium + nuclei
	// templates), which is handled by ensureCoreDeps. Config bootstrap by
	// itself does not satisfy "first-run setup".

	// Print success message
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.SuccessSymbol(), terminal.BoldGreen("Mandatory configuration initialized."))
	fmt.Fprintf(os.Stderr, "  %s Config: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(settingsPath)))
	// Only name the default database when this run actually created it. Naming
	// a file that is not there, on a run that is deliberately using a different
	// store, is the opposite of informative.
	if createDefaultDB {
		fmt.Fprintf(os.Stderr, "  %s Database: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(config.ExpandPath(settings.Database.SQLite.Path))))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Database: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(config.ExpandPath(globalDB))))
	}
	fmt.Fprintf(os.Stderr, "  %s Docs & guides: %s\n", terminal.InfoSymbol(), terminal.Cyan("https://docs.vigolium.com"))
	fmt.Fprintf(os.Stderr, "  %s Run %s for a full setup (browser, templates, and agentic-scan runtimes).\n",
		terminal.TipSymbol(), terminal.BoldCyan("vigolium doctor --fix"))

	return nil
}

// bootstrapDefaultProfiles copies embedded profile YAMLs into the profiles
// directory, write-if-missing per file: a profile the operator deleted comes
// back, one they edited is left alone, and a directory that exists but is
// missing some built-ins (a mounted config volume, a half-finished init) is
// completed rather than skipped.
func bootstrapDefaultProfiles(vigoliumDir string) {
	bootstrapEmbeddedDir(vigoliumDir, "profiles", "presets/profiles", "default scanning profiles")
}

// bootstrapPrompts copies embedded prompt templates to the prompts directory.
func bootstrapPrompts(vigoliumDir string) {
	bootstrapEmbeddedDir(vigoliumDir, "prompts", "presets/prompts", "prompt templates")
}

// bootstrapExtensions copies embedded preset extensions to the extensions directory.
func bootstrapExtensions(vigoliumDir string) {
	bootstrapEmbeddedDir(vigoliumDir, "extensions", "presets/extensions", "preset extensions")
}

// bootstrapSkills materializes the embedded built-in olium skills into the
// user-scope skills directory (~/.vigolium/skills, or VIGOLIUM_SKILLS_DIR) so
// operators get editable copies that the autopilot/swarm loader prefers over
// the embedded fallback. Write-if-missing — re-runs and operator edits are
// preserved. Best-effort: skills still load from the embed if this fails.
func bootstrapSkills() {
	dir := skill.UserSkillsDir()
	if dir == "" {
		return
	}
	n, err := oliumresources.EnsureOnDisk(dir)
	if err != nil {
		zap.L().Debug("Failed to materialize skills", zap.String("dir", dir), zap.Error(err))
		return
	}
	if n > 0 {
		zap.L().Info("Bootstrapped skills", zap.String("dir", dir), zap.Int("written", n))
	}
}

// bootstrapEmbeddedDir copies files from an embedded FS path into a subdirectory
// of vigoliumDir, preserving directory structure, write-if-missing per file
// (existing files, edited or not, are never overwritten). Returns how many
// files it wrote.
func bootstrapEmbeddedDir(vigoliumDir, subDir, embedPath, label string) int {
	targetDir := filepath.Join(vigoliumDir, subDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		zap.L().Debug("Failed to create "+subDir+" directory", zap.Error(err))
		return 0
	}
	n := copyEmbeddedDir(targetDir, embedPath)
	if n > 0 {
		zap.L().Info("Bootstrapped "+label, zap.String("dir", targetDir), zap.Int("written", n))
	}
	return n
}

// copyEmbeddedDir recursively copies files from the embedded FS into
// targetDir, skipping any destination that already exists. Returns the number
// of files written.
func copyEmbeddedDir(targetDir, embedPath string) int {
	entries, err := public.StaticFS.ReadDir(embedPath)
	if err != nil {
		return 0
	}
	written := 0

	for _, entry := range entries {
		if entry.IsDir() {
			subTarget := filepath.Join(targetDir, entry.Name())
			if err := os.MkdirAll(subTarget, 0755); err != nil {
				zap.L().Debug("Failed to create bootstrap subdir", zap.String("dir", subTarget), zap.Error(err))
				continue
			}
			written += copyEmbeddedDir(subTarget, embedPath+"/"+entry.Name())
			continue
		}
		dest := filepath.Join(targetDir, entry.Name())
		if _, err := os.Lstat(dest); err == nil {
			continue
		}
		data, readErr := public.StaticFS.ReadFile(embedPath + "/" + entry.Name())
		if readErr != nil {
			continue
		}
		if err := os.WriteFile(dest, data, 0644); err != nil {
			zap.L().Debug("Failed to write bootstrapped file", zap.String("dest", dest), zap.Error(err))
			continue
		}
		written++
	}
	return written
}

// coreDepCommands lists the command paths (not leaf names: `oast ingest` is not
// `ingest`) whose first run checks for chromium + nuclei templates and, when
// either is missing, says so in one stderr line. Nothing is installed here: the
// spidering and known-issue-scan phases provision what they need when they run
// (scan.setup).
// The set deliberately excludes:
//   - scan-url / scan-request: the direct path neither crawls nor runs nuclei
//     unless asked, and then the phase provisions lazily like any other scan
//   - informational commands (version, doctor, config, help, examples, license, log)
//   - data-management commands (project, scope, source, traffic, finding, db, …)
//   - the olium TUI and the agent query/olium/audit subcommands (LLM-only, no native scan)
var coreDepCommands = map[string]bool{
	"scan":            true,
	"run":             true,
	"agent autopilot": true, // uses chromium for spidering
	"agent swarm":     true, // drives the native scan pipeline
	"server":          true, // long-running API server that hosts scan endpoints
	"ingest":          true, // populates the queue feeding scan workers
}

// needsCoreDeps reports whether the given command should run the first-run
// chromium + nuclei-templates check.
func needsCoreDeps(cmd *cobra.Command) bool {
	return coreDepCommands[commandPathWithoutRoot(cmd)]
}

// coreDepState is what the first-run check found missing.
type coreDepState struct {
	chromeMissing bool // spidering would have to download Chrome for Testing
	nucleiMissing bool // known-issue-scan would have to clone nuclei-templates
}

func (s coreDepState) missing() bool { return s.chromeMissing || s.nucleiMissing }

// notice is the single stderr line ensureCoreDeps prints when something is
// missing: what will happen lazily, and how to do it now instead.
func (s coreDepState) notice() string {
	const fix = "check with 'vigolium doctor --for scan'; run 'vigolium doctor --fix' to pre-install"
	switch {
	case s.chromeMissing && s.nucleiMissing:
		return "chromium and nuclei-templates not found — chromium is downloaded on first --spider (~150 MB), templates are cloned on first known-issue scan; " + fix
	case s.chromeMissing:
		return "chromium not found — will be downloaded on first --spider (~150 MB); " + fix
	default:
		return "nuclei-templates not found — will be cloned on first known-issue scan; " + fix
	}
}

// checkCoreDeps reports which core native-scan dependencies are missing. No
// network, no install: "chromium" is missing exactly when a crawl would have to
// download Chrome for Testing (no configured, embedded, system or cached
// browser), and templates are missing when their directory does not exist. A
// var so tests can stage either state.
var checkCoreDeps = func(settings *config.Settings) coreDepState {
	var st coreDepState
	st.chromeMissing = spitolas.BrowserNeedsDownload(settings.Spidering.BrowserEngine, settings.Spidering.BrowserPath)
	info, err := os.Stat(diagnostics.NucleiTemplatesDir(settings))
	st.nucleiMissing = err != nil || !info.IsDir()
	return st
}

// runCoreDepFixes installs the core dependencies. Only `vigolium init` (an
// explicit setup command) calls it; the scan bootstrap never does. A var so
// tests can prove that.
var runCoreDepFixes = diagnostics.RunFixes

// coreDepNoticeQuiet reports whether the first-run notice must stay off stderr:
// a machine reader (-j, --events) or nobody at a terminal. Those callers learn
// about a lazy install from the scan.setup event instead.
func coreDepNoticeQuiet(cmd *cobra.Command) bool {
	if globalJSON || globalSilent || !terminal.StderrIsTerminal() {
		return true
	}
	if f := cmd.Flags().Lookup("events"); f != nil && f.Value.String() != "" {
		return true
	}
	return false
}

// ensureCoreDeps is the scan bootstrap's first-run check. It is check-only: it
// never installs and never blocks. When chromium and nuclei-templates are both
// present it stamps ~/.vigolium/initialized so later runs skip the check with
// one os.Stat. When either is missing it leaves the marker unwritten (the next
// run checks again), prints one stderr line unless quiet, and returns: the
// spidering and known-issue-scan phases provision what they need lazily,
// outside their time budgets, and announce it with scan.setup events.
func ensureCoreDeps(quiet bool) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil // Silently fail; downstream command will surface the real issue.
	}
	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	markerPath := filepath.Join(vigoliumDir, initMarkerFileName)
	if _, err := os.Stat(markerPath); err == nil {
		return nil
	}

	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	st := checkCoreDeps(settings)
	if st.missing() {
		if !quiet {
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), st.notice())
		}
		return nil
	}
	stampInitMarker(vigoliumDir)
	return nil
}

// installCoreDeps is `vigolium init`'s explicit setup: it installs chromium and
// nuclei-templates when missing (doctor's `--fix --only nuclei,chrome`) and
// stamps the marker once both are present. The scan bootstrap does not call it.
//
// It fails with not_ready when a dependency is still missing after the
// install: an init that reported success while both downloads failed sent the
// operator to a scan that then crawled nothing. Under --offline nothing is
// downloaded; a missing dependency is reported, not failed on.
func installCoreDeps() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	if _, err := os.Stat(filepath.Join(vigoliumDir, initMarkerFileName)); err == nil {
		return nil
	}

	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}
	if !checkCoreDeps(settings).missing() {
		stampInitMarker(vigoliumDir)
		return nil
	}

	if initOffline {
		st := checkCoreDeps(settings)
		fmt.Fprintf(os.Stderr, "%s --offline: not downloading %s; install later with %s\n",
			terminal.WarnPrefix(), st.missingNames(), terminal.Cyan("vigolium doctor --fix --only chrome,nuclei"))
		return nil
	}

	fmt.Fprintf(os.Stderr, "%s %s\n",
		terminal.InfoSymbol(),
		terminal.BoldCyan("Installing core scan dependencies (chromium, nuclei-templates)..."))

	// DB intentionally omitted — neither the chromium nor nuclei-templates
	// check touches the database.
	report := diagnostics.Run(diagnostics.Deps{Settings: settings, ProbeBrowserLaunch: true})
	ctx, cancel := context.WithTimeout(context.Background(), coreDepInstallTimeout)
	defer cancel()
	results := runCoreDepFixes(ctx, report, settings, []string{"nuclei", "chrome"})

	for _, r := range results {
		if r.Success {
			fmt.Fprintf(os.Stderr, "  %s %-30s %s\n", terminal.SuccessSymbol(), terminal.Green(r.Label), terminal.White(r.Message))
		} else {
			fmt.Fprintf(os.Stderr, "  %s %-30s %s\n", terminal.Red(terminal.SymbolError), terminal.Red(r.Label), terminal.White(r.Message))
		}
	}

	if st := checkCoreDeps(settings); st.missing() {
		return clicommon.CodedErrorf(apicontract.CodeNotReady,
			"%s still missing after install; retry with `vigolium doctor --fix --only chrome,nuclei` or pass --offline to skip downloads",
			st.missingNames())
	}
	stampInitMarker(vigoliumDir)
	return nil
}

// missingNames names the missing dependencies for a message.
func (s coreDepState) missingNames() string {
	switch {
	case s.chromeMissing && s.nucleiMissing:
		return "chromium and nuclei-templates"
	case s.chromeMissing:
		return "chromium"
	case s.nucleiMissing:
		return "nuclei-templates"
	}
	return "nothing"
}

// coreDepInstallTimeout caps `vigolium init`'s chromium + nuclei-templates
// install. Both are network-bound (template git clone, Chrome for Testing
// download), so the headroom is generous.
const coreDepInstallTimeout = 10 * time.Minute

// stampInitMarker writes the marker (best-effort, dir created if needed).
func stampInitMarker(vigoliumDir string) {
	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		zap.L().Debug("Failed to create .vigolium dir for init marker", zap.Error(err))
		return
	}
	if err := writeInitMarker(vigoliumDir); err != nil {
		zap.L().Debug("Failed to write init marker", zap.Error(err))
	}
}

// ensureInitMarkerIfDepsPresent stamps ~/.vigolium/initialized (best-effort,
// dir created if needed) ONLY when the two mandatory native-scan dependencies —
// chromium and nuclei-templates — are confirmed present in the supplied
// diagnostics report. Called by `vigolium doctor` so a run that observes a
// healthy toolchain backfills the marker, mirroring the ensureCoreDeps backfill
// (see ensureCoreDeps: both-present → writeInitMarker).
//
// The deps-present gate is the whole point: a read-only `vigolium doctor` on a
// machine that is MISSING chromium/nuclei must NOT stamp the marker, otherwise
// it would silence the first-run notice that tells the operator the next
// --spider or known-issue scan will download them. The existence guard
// preserves the original timestamp on repeat doctor runs.
func ensureInitMarkerIfDepsPresent(report *diagnostics.Report) {
	if report == nil {
		return
	}
	chromiumOK := report.Tools["chromium"] != nil && report.Tools["chromium"].Status == diagnostics.StatusOK
	nucleiOK := report.NucleiTemplates != nil && report.NucleiTemplates.Status == diagnostics.StatusOK
	if !chromiumOK || !nucleiOK {
		return // a dep is missing — leave the first-run install path armed for the next scan
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	markerPath := filepath.Join(vigoliumDir, initMarkerFileName)
	if _, err := os.Stat(markerPath); err == nil {
		return // already stamped; preserve original timestamp
	}
	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		zap.L().Debug("doctor: failed to create .vigolium dir for init marker", zap.Error(err))
		return
	}
	if err := writeInitMarker(vigoliumDir); err != nil {
		zap.L().Debug("doctor: failed to write init marker", zap.Error(err))
	}
}

// skipCoreDepCheck honors the --skip-dependency-check flag: it stamps
// ~/.vigolium/initialized immediately without probing for chromium or nuclei
// templates, so this run and every future scan fast-path past the first-run
// dependency check. Since the check no longer installs anything, the flag only
// silences the one-line notice; kept for compatibility. Best-effort — a failed mkdir/write just means the check may
// run on a later invocation. Returns true when it actually wrote the marker.
func skipCoreDepCheck() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	markerPath := filepath.Join(vigoliumDir, initMarkerFileName)
	if _, err := os.Stat(markerPath); err == nil {
		return false // already stamped; nothing to do
	}
	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		zap.L().Debug("skip-dependency-check: failed to create .vigolium dir", zap.Error(err))
		return false
	}
	if err := writeInitMarker(vigoliumDir); err != nil {
		zap.L().Debug("skip-dependency-check: failed to write init marker", zap.Error(err))
		return false
	}
	return true
}

// ensureInitialized checks if Vigolium is initialized and initializes if needed
// This is called before any command runs that shouldBootstrap admits.
func ensureInitialized() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil // Silently fail, command will continue
	}

	settingsPath := filepath.Join(homeDir, ".vigolium", settingsFileName)

	// Check if already initialized
	if _, err := os.Stat(settingsPath); err == nil {
		return nil
	}

	// Not initialized - run initialization. The default database is created
	// only when it is the store this invocation will use: a pinned --db (or a
	// VIGOLIUM_DB_PATH that applyDBPathEnv has already folded into globalDB)
	// means the default file would be created, seeded and never opened.
	//
	// --read-only deliberately does NOT suppress it. The spec called for that,
	// but with no --db the default file IS the store the read is about to open,
	// and openSQLiteReadOnly refuses a path that does not exist — so skipping
	// here would turn a cold-$HOME `vigolium --read-only finding` from "0
	// findings, exit 0" into "database file not readable". Creating an empty
	// store the read then reports as empty modifies nothing that existed.
	return initializeVigolium(strings.TrimSpace(globalDB) == "")
}

// bootstrapExemptCommands are the leaf command names that must not materialize
// ~/.vigolium as a side effect of running.
//
// Bootstrap writes a config, a database, and four directories of presets. That
// is the right thing to do before a scan and the wrong thing to do when the
// user asked what version this is, asked for help, or — worst of all — pressed
// tab. `__complete` runs on every shell completion, so a user who had never run
// vigolium could create a seeded database by typing `vigolium ` and hitting tab
// twice; `completion bash` is routinely run from a shell rc file, which made it
// happen at login.
//
// `init` is exempt because it does the initialization itself, with its own
// flags and its own reporting.
var bootstrapExemptCommands = map[string]bool{
	"init":                          true,
	"version":                       true,
	"help":                          true,
	cobra.ShellCompRequestCmd:       true, // __complete
	cobra.ShellCompNoDescRequestCmd: true, // __completeNoDesc
}

// shouldBootstrap reports whether this command may create ~/.vigolium.
//
// The root command with no subcommand only prints usage, and the `completion`
// subtree only writes a shell script to stdout — neither touches a database or
// a profile, and both are reached by users who have not yet decided to use
// vigolium at all. The `schema` subtree prints compiled-in schemas, the same.
func shouldBootstrap(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	if cmd.Root() == cmd {
		return false
	}
	if bootstrapExemptCommands[cmd.Name()] {
		return false
	}
	for c := cmd; c != nil; c = c.Parent() {
		if c.Name() == "completion" || (c.Name() == "schema" && c.Parent() == cmd.Root()) {
			return false
		}
	}
	return true
}
