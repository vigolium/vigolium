package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
)

// globalSetOverlay backs --set: one `<dotted.key>=<value>` per occurrence,
// overlaid on the effective config for this invocation only. The file is never
// written. Every layer (config file, project overlay, scanning profile) is
// applied under it, so an entry outranks them as a typed flag does; a typed
// flag that maps to the same setting still wins over the entry.
var globalSetOverlay []string

func init() {
	rootCmd.PersistentFlags().StringArrayVar(&globalSetOverlay, "set", nil,
		"Overlay one config key for this invocation, repeatable: --set spidering.max_depth=3 (same keys and value syntax as config set; the file is not changed)")
}

// installConfigOverlay parses --set and installs it as the process overlay
// (config.SetProcessOverlay) before anything loads settings. An unknown key or
// a value its setting cannot hold is a usage error naming the key.
//
// A command that writes shared state (WritesGlobal: the config file, scope,
// module sets, …) refuses --set: several of them rebuild what they write from
// the loaded settings, which would carry the overlay into the file.
func installConfigOverlay(cmd *cobra.Command) error {
	if len(globalSetOverlay) > 0 {
		if t, _ := traitOf(cmd); t.WritesGlobal {
			return usageErrorf("--set overlays one invocation and cannot be combined with `%s`, which writes shared state; pass the value to it directly",
				commandPathWithoutRoot(cmd))
		}
	}
	entries, err := config.ParseOverlay(globalSetOverlay)
	if err != nil {
		if errors.Is(err, config.ErrUnknownKey) || errors.Is(err, config.ErrInvalidValue) {
			return asUsageError(fmt.Errorf("%w (`vigolium config ls` lists the keys)", err))
		}
		return err
	}
	config.SetProcessOverlay(entries)
	return nil
}
