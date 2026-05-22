package cli

import "github.com/vigolium/vigolium/pkg/cli/internal/clicommon"

// effectiveConfigPath resolves the config file path from the --config global flag.
func effectiveConfigPath() string {
	return clicommon.EffectiveConfigPath(globalConfig)
}
