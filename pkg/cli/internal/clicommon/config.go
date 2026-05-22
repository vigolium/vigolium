package clicommon

import "github.com/vigolium/vigolium/internal/config"

// EffectiveConfigPath resolves the config file path to operate on: the expanded
// --config flag value when set, otherwise the default config file location.
func EffectiveConfigPath(configFlag string) string {
	if configFlag != "" {
		return config.ExpandPath(configFlag)
	}
	return config.ConfigFilePath()
}
