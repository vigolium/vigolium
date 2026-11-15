package cli

import (
	"os"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
)

// overlayProjectUUID returns the project whose config overlay
// (config.ProjectConfigPath) applies to this invocation's settings, or "" for
// global-only settings.
//
// It follows the same rule as project-scoped reads (effectiveProjectUUID): a
// standalone database — -S/--stateless, --glob-db, or a shell pinned with
// $VIGOLIUM_DB_PATH — runs unscoped, so the persisted active project (a
// different context from the pinned session) contributes no overlay. Naming a
// project (--project-uuid / --project-name or their env vars) applies its
// overlay in every mode.
func overlayProjectUUID() (string, error) {
	if (statelessReadRequested() || dbPathEnvPinned) && !explicitProjectSelected() {
		return "", nil
	}
	return resolveProjectUUID()
}

// loadProjectSettings loads the settings a scan (or a scope judgement) runs
// under: global config, then the invocation's project overlay. The scanning
// profile and CLI flags are layered on afterwards by the scan-options
// resolver, completing global → project → profile → CLI.
func loadProjectSettings(configPath string) (*config.Settings, error) {
	projectUUID, err := overlayProjectUUID()
	if err != nil {
		return nil, err
	}
	return clicommon.LoadProjectSettings(configPath, projectUUID)
}

// configProjectSettings is loadProjectSettings for the config commands: the
// merged settings and the project whose overlay was applied ("" = none).
func configProjectSettings() (*config.Settings, string, error) {
	projectUUID, err := overlayProjectUUID()
	if err != nil {
		return nil, "", err
	}
	settings, err := clicommon.LoadProjectSettings(globalConfig, projectUUID)
	if err != nil {
		return nil, "", err
	}
	if _, statErr := os.Stat(config.ProjectConfigPath(projectUUID)); projectUUID == "" || statErr != nil {
		projectUUID = ""
	}
	return settings, projectUUID, nil
}

// configFlagKeys names the settings keys a global flag of this invocation
// set, for config ls's source column.
func configFlagKeys() []string {
	var keys []string
	if f := rootCmd.PersistentFlags().Lookup("db"); f != nil && f.Changed {
		keys = append(keys, "database.sqlite.path")
	}
	if f := rootCmd.PersistentFlags().Lookup("offline"); f != nil && f.Changed {
		keys = append(keys, "offline")
	}
	return keys
}
