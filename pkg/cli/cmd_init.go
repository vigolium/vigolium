package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
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

Safe to run on an existing installation — skips components that already exist
unless --force is passed, which regenerates the config (with a new API key)
and re-extracts all preset data.`,
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

	if _, err := os.Stat(settingsPath); err == nil && !globalForce {
		fmt.Fprintf(os.Stderr, "%s Already initialized (%s exists). Use --force to reinitialize.\n",
			terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(settingsPath)))
		// The config exists, but the core deps may not: every bootstrapping command writes the
		// config on first use without fetching chromium or nuclei-templates, so an explicit
		// `init` on such a home must still complete them. installCoreDeps returns at once when
		// the marker is already stamped.
		if err := installCoreDeps(); err != nil {
			return fmt.Errorf("core dependency install failed: %w", err)
		}
		if globalJSON {
			return emitMutation(cmd, "", mutationResult{
				Action: "noop",
				Extra:  map[string]any{"already_initialized": true, "config_path": config.ContractPath(settingsPath)},
			})
		}
		return nil
	}

	if err := os.MkdirAll(vigoliumDir, 0755); err != nil {
		return fmt.Errorf("failed to create .vigolium directory: %w", err)
	}

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

	settings := config.DefaultSettings()

	// Initialize database
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

	if globalForce {
		// Remove sentinel directories so bootstrap helpers re-extract
		for _, sub := range []string{"profiles", "extensions", "prompts"} {
			_ = os.RemoveAll(filepath.Join(vigoliumDir, sub))
		}
		// Skills may live outside vigoliumDir (VIGOLIUM_SKILLS_DIR), so resolve
		// and wipe the actual dir before re-extracting. --force resets to
		// defaults, discarding any operator edits.
		if sk := skill.UserSkillsDir(); sk != "" {
			_ = os.RemoveAll(sk)
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
	// we wipe the marker first so the check re-runs on the same invocation
	// (handy when --force is used to recover a broken setup).
	if globalForce {
		_ = os.Remove(filepath.Join(vigoliumDir, initMarkerFileName))
	}
	if err := installCoreDeps(); err != nil {
		return fmt.Errorf("core dependency install failed: %w", err)
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
		action := "create"
		if globalForce {
			action = "reset"
		}
		return emitMutation(cmd, "", mutationResult{Changed: true, Action: action, Items: items})
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.SuccessSymbol(), terminal.BoldGreen("Vigolium initialized successfully!"))
	fmt.Fprintf(os.Stderr, "  %s Config:   %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(settingsPath)))
	fmt.Fprintf(os.Stderr, "  %s Database: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(config.ExpandPath(settings.Database.SQLite.Path))))
	fmt.Fprintf(os.Stderr, "  %s Docs:     %s\n", terminal.InfoSymbol(), terminal.Cyan("https://docs.vigolium.com"))

	return nil
}

// initPathView is one path `init -j` wrote or re-extracted.
type initPathView struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}
