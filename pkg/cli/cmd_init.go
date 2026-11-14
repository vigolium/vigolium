package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Vigolium with default configuration and preset data",
	Long: `Create the ~/.vigolium directory with a default config file, database schema,
scanning profiles, prompt templates, and extensions.

Idempotent: on an existing installation it re-runs every step that is safe to
repeat — database schema and seed, write-if-missing presets (profiles,
extensions, prompts, skills) and the core dependency check — so a deleted
profile or a missing database is restored and existing edits are kept.
--force backs up the config and preset directories to
~/.vigolium/backup-<timestamp>/ before regenerating them (with a new API key).
Fails (not_ready) when chromium or nuclei-templates cannot be installed;
--offline skips those downloads.`,
	RunE: runInitCmd,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInitCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	vigoliumDir := filepath.Join(homeDir, ".vigolium")
	settingsPath := filepath.Join(vigoliumDir, settingsFileName)

	_, statErr := os.Stat(settingsPath)
	existed := statErr == nil

	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		return fmt.Errorf("failed to create .vigolium directory: %w", err)
	}

	backupDir := ""
	if globalForce && existed {
		dir, err := backupVigoliumHome(vigoliumDir, settingsPath)
		if err != nil {
			return fmt.Errorf("back up before --force: %w", err)
		}
		backupDir = dir
	}

	wroteConfig := false
	if !existed || globalForce {
		// Write default config with a fresh API key
		configData := bytes.Replace(
			public.DefaultConfigYAML,
			[]byte(`auth_api_key: "auto-generated-on-first-run"`),
			[]byte(fmt.Sprintf(`auth_api_key: "%s"`, config.GenerateRandomHex(40))),
			1,
		)
		if err := os.WriteFile(settingsPath, configData, 0600); err != nil {
			return fmt.Errorf("failed to write default config: %w", err)
		}
		wroteConfig = true
	}

	// The database the effective config names (the default on a fresh home).
	settings := config.DefaultSettings()
	if existed && !globalForce {
		if loaded, err := clicommon.LoadSettings(globalConfig); err == nil && loaded != nil {
			settings = loaded
		}
	}

	// Initialize database: schema and seed are idempotent, so they run on every
	// init and restore a store that was deleted or never created.
	if settings.Database.Enabled {
		db, err := database.NewDB(&settings.Database)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		defer func() { _ = db.Close() }()

		ctx := context.Background()
		if err := db.EnsureSchemaReady(ctx); err != nil {
			return fmt.Errorf("failed to create database schema: %w", err)
		}
		if err := db.SeedDefaults(ctx); err != nil {
			return fmt.Errorf("failed to seed default data: %w", err)
		}
	}

	bootstrapDefaultProfiles(vigoliumDir)
	bootstrapExtensions(vigoliumDir)
	bootstrapPrompts(vigoliumDir)
	bootstrapSkills()

	// Install the core deps (chromium + nuclei templates) inline so explicit
	// `vigolium init` is a complete setup — unlike a scan, which only checks and
	// lets the phase that needs a dependency fetch it. Without --force the
	// marker may already exist and installCoreDeps short-circuits; under --force
	// we wipe the marker first so the check re-runs on the same invocation.
	if globalForce {
		_ = os.Remove(filepath.Join(vigoliumDir, initMarkerFileName))
	}
	if err := installCoreDeps(); err != nil {
		return err
	}

	if globalJSON {
		dbPath := ""
		if settings.Database.Enabled {
			dbPath = config.ContractPath(config.ExpandPath(settings.Database.SQLite.Path))
		}
		items := []initPathView{{Kind: "config", Path: config.ContractPath(settingsPath)}}
		if dbPath != "" {
			items = append(items, initPathView{Kind: "database", Path: dbPath})
		}
		for _, sub := range []string{"profiles", "extensions", "prompts"} {
			items = append(items, initPathView{Kind: sub, Path: config.ContractPath(filepath.Join(vigoliumDir, sub))})
		}
		if sk := skill.UserSkillsDir(); sk != "" {
			items = append(items, initPathView{Kind: "skills", Path: config.ContractPath(sk)})
		}
		if backupDir != "" {
			items = append(items, initPathView{Kind: "backup", Path: config.ContractPath(backupDir)})
		}
		action := "create"
		switch {
		case globalForce:
			action = "reset"
		case existed:
			action = "repair"
		}
		return emitMutation(cmd, "", mutationResult{Changed: wroteConfig || !existed, Action: action, Items: items,
			Extra: map[string]any{"already_initialized": existed, "config_path": config.ContractPath(settingsPath)}})
	}

	headline := "Vigolium initialized successfully!"
	if existed && !globalForce {
		headline = "Vigolium installation checked and repaired (existing config kept)."
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.SuccessSymbol(), terminal.BoldGreen(headline))
	fmt.Fprintf(os.Stderr, "  %s Config:   %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(settingsPath)))
	fmt.Fprintf(os.Stderr, "  %s Database: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(config.ExpandPath(settings.Database.SQLite.Path))))
	if backupDir != "" {
		fmt.Fprintf(os.Stderr, "  %s Backup:   %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(backupDir)))
	}
	fmt.Fprintf(os.Stderr, "  %s Docs:     %s\n", terminal.InfoSymbol(), terminal.Cyan("https://docs.vigolium.com"))

	return nil
}

// backupVigoliumHome moves the config file and the preset directories
// (profiles, extensions, prompts, and the skills dir) into
// ~/.vigolium/backup-<timestamp>/ so --force regenerates from defaults without
// destroying operator edits. Returns the backup directory.
func backupVigoliumHome(vigoliumDir, settingsPath string) (string, error) {
	dir := filepath.Join(vigoliumDir, "backup-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	move := func(src, name string) error {
		if _, err := os.Lstat(src); err != nil {
			return nil
		}
		return os.Rename(src, filepath.Join(dir, name))
	}
	if err := move(settingsPath, filepath.Base(settingsPath)); err != nil {
		return "", err
	}
	for _, sub := range []string{"profiles", "extensions", "prompts"} {
		if err := move(filepath.Join(vigoliumDir, sub), sub); err != nil {
			return "", err
		}
	}
	// Skills may live outside vigoliumDir (VIGOLIUM_SKILLS_DIR); a rename
	// across filesystems can fail, in which case the skills are left in place
	// (write-if-missing keeps the operator's copies).
	if sk := skill.UserSkillsDir(); sk != "" {
		_ = move(sk, "skills")
	}
	return dir, nil
}

// initPathView is one path `init -j` wrote or re-extracted.
type initPathView struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}
