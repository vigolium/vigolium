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
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Vigolium with default configuration and preset data",
	Long: `Create the ~/.vigolium directory with a default config file, database schema,
scanning profiles, prompt templates, extensions, and SAST rules.

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
		if err := db.CreateSchema(ctx); err != nil {
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
	}

	bootstrapDefaultProfiles(vigoliumDir)
	bootstrapExtensions(vigoliumDir)
	bootstrapPrompts(vigoliumDir)

	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.SuccessSymbol(), terminal.BoldGreen("Vigolium initialized successfully!"))
	fmt.Fprintf(os.Stderr, "  %s Config:   %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(settingsPath)))
	fmt.Fprintf(os.Stderr, "  %s Database: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(config.ExpandPath(settings.Database.SQLite.Path))))
	fmt.Fprintf(os.Stderr, "  %s Docs:     %s\n", terminal.InfoSymbol(), terminal.Cyan("https://docs.vigolium.com"))

	return nil
}
