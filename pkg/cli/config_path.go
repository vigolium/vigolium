package cli

import "github.com/vigolium/vigolium/internal/config"

func effectiveConfigPath() string {
	if globalConfig != "" {
		return config.ExpandPath(globalConfig)
	}
	return config.ConfigFilePath()
}
