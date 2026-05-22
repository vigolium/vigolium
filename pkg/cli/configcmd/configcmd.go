// Package configcmd implements the `vigolium config` command group.
//
// It is the first command group split out of the flat pkg/cli package into its
// own subpackage. Rather than self-registering via init() into a package-private
// rootCmd, it exposes an explicit NewCommand(deps, examples) constructor that
// pkg/cli wires onto the root command. All of the implicit package-global state
// the commands previously reached for (the --config / --force flag values and
// the first-run reinitializer) is passed in explicitly via Deps, so this package
// has no dependency back on pkg/cli.
package configcmd

import "github.com/spf13/cobra"

// Deps carries the runtime dependencies the config commands need, injected by
// pkg/cli so this package stays decoupled from the CLI's global flag state.
type Deps struct {
	// ConfigFlag returns the raw --config flag value (may be empty).
	ConfigFlag func() string
	// Force returns the --force flag value.
	Force func() bool
	// Reinitialize regenerates ~/.vigolium with fresh defaults (used by `config clean`).
	Reinitialize func() error
}

// Examples carries the per-command example blocks, defined in pkg/cli.
type Examples struct {
	Parent string
	Ls     string
	Set    string
	Clean  string
}

// NewCommand builds the `config` command group with its subcommands.
func NewCommand(deps Deps, ex Examples) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "config",
		Short:   "Manage configuration",
		Long:    "Inspect and edit Vigolium settings stored in ~/.vigolium/vigolium-configs.yaml. Subcommands list current values, set keys via dot-notation, and reset to clean defaults.",
		Example: ex.Parent,
	}
	cmd.AddCommand(
		newLsCmd(deps, ex.Ls),
		newSetCmd(deps, ex.Set),
		newCleanCmd(deps, ex.Clean),
	)
	return cmd
}
