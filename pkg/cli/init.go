package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/public"
	"go.uber.org/zap"
)

const settingsFileName = "vigolium-configs.yaml"

// initializeVigolium initializes Vigolium on first run
// Creates default settings file and initializes database
func initializeVigolium() error {
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
	fmt.Fprintf(os.Stderr, "%s No existing configuration detected. Initializing with default preset data\n",
		terminal.Red(terminal.SymbolFailed))
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
	if settings.Database.Enabled {
		zap.L().Info("Initializing database...")

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

		zap.L().Debug("Database initialized successfully",
			zap.String("driver", settings.Database.Driver),
			zap.String("path", settings.Database.SQLite.Path))
	}

	// Bootstrap default profiles
	bootstrapDefaultProfiles(vigoliumDir)

	// Bootstrap preset extensions
	bootstrapExtensions(vigoliumDir)

	// Bootstrap prompt templates
	bootstrapPrompts(vigoliumDir)

	// Print success message
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.SuccessSymbol(), terminal.BoldGreen("Vigolium initialized successfully!"))
	fmt.Fprintf(os.Stderr, "  %s Config: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(settingsPath)))
	fmt.Fprintf(os.Stderr, "  %s Database: %s\n", terminal.InfoSymbol(), terminal.Cyan(config.ContractPath(config.ExpandPath(settings.Database.SQLite.Path))))
	fmt.Fprintf(os.Stderr, "  %s Docs & guides: %s\n", terminal.InfoSymbol(), terminal.Cyan("https://docs.vigolium.com"))

	return nil
}

// bootstrapDefaultProfiles copies embedded profile YAMLs to the profiles directory
// if the directory does not exist yet. This runs during first-time initialization.
func bootstrapDefaultProfiles(vigoliumDir string) {
	profilesDir := filepath.Join(vigoliumDir, "profiles")

	// Only bootstrap if the profiles directory does not exist
	if _, err := os.Stat(profilesDir); err == nil {
		return
	}

	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		zap.L().Debug("Failed to create profiles directory", zap.Error(err))
		return
	}

	entries, err := public.StaticFS.ReadDir("presets/profiles")
	if err != nil {
		zap.L().Debug("Failed to read embedded profiles", zap.Error(err))
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, readErr := public.StaticFS.ReadFile("presets/profiles/" + entry.Name())
		if readErr != nil {
			continue
		}
		dest := filepath.Join(profilesDir, entry.Name())
		_ = os.WriteFile(dest, data, 0644)
	}

	zap.L().Info("Bootstrapped default scanning profiles",
		zap.String("dir", profilesDir))
}

// bootstrapPrompts copies embedded prompt templates to the prompts directory.
func bootstrapPrompts(vigoliumDir string) {
	bootstrapEmbeddedDir(vigoliumDir, "prompts", "presets/prompts", "prompt templates")
}

// bootstrapExtensions copies embedded preset extensions to the extensions directory.
func bootstrapExtensions(vigoliumDir string) {
	bootstrapEmbeddedDir(vigoliumDir, "extensions", "presets/extensions", "preset extensions")
}

// bootstrapEmbeddedDir copies files from an embedded FS path into a subdirectory
// of vigoliumDir, preserving directory structure. It only runs if the target
// directory does not exist yet.
func bootstrapEmbeddedDir(vigoliumDir, subDir, embedPath, label string) {
	targetDir := filepath.Join(vigoliumDir, subDir)

	if _, err := os.Stat(targetDir); err == nil {
		return
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		zap.L().Debug("Failed to create "+subDir+" directory", zap.Error(err))
		return
	}

	copyEmbeddedDir(targetDir, embedPath)

	zap.L().Info("Bootstrapped "+label, zap.String("dir", targetDir))
}

// copyEmbeddedDir recursively copies files from the embedded FS into targetDir.
func copyEmbeddedDir(targetDir, embedPath string) {
	entries, err := public.StaticFS.ReadDir(embedPath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			subTarget := filepath.Join(targetDir, entry.Name())
			_ = os.MkdirAll(subTarget, 0755)
			copyEmbeddedDir(subTarget, embedPath+"/"+entry.Name())
			continue
		}
		data, readErr := public.StaticFS.ReadFile(embedPath + "/" + entry.Name())
		if readErr != nil {
			continue
		}
		dest := filepath.Join(targetDir, entry.Name())
		_ = os.WriteFile(dest, data, 0644)
	}
}

// ensureInitialized checks if Vigolium is initialized and initializes if needed
// This is called before any command runs
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

	// Not initialized - run initialization
	return initializeVigolium()
}
